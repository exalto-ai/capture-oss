#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 [smoke|full]" >&2
  echo "       $0 {sqlite|postgres} {filesystem|s3} {1|2} {smoke|full}" >&2
}

metadata_engine=sqlite
artifact_engine=filesystem
replica_count=1
profile=full
if [[ $# -eq 1 ]]; then
  profile=$1
elif [[ $# -eq 4 ]]; then
  metadata_engine=$1
  artifact_engine=$2
  replica_count=$3
  profile=$4
elif [[ $# -ne 0 ]]; then
  usage
  exit 2
fi
if [[ $replica_count == 2 ]]; then
  if [[ $metadata_engine != postgres || $artifact_engine != s3 || ( $profile != smoke && $profile != full ) ]]; then
    echo "cluster E2E supports only postgres s3 2 {smoke|full}" >&2
    exit 2
  fi
  script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
  exec "$script_dir/test-daemon-cluster-e2e.sh" "$profile"
fi
if [[ ( $metadata_engine != sqlite && $metadata_engine != postgres ) || ( $artifact_engine != filesystem && $artifact_engine != s3 ) || $replica_count != 1 || ( $profile != smoke && $profile != full ) ]]; then
  echo "unsupported daemon E2E matrix entry: $metadata_engine $artifact_engine $replica_count $profile" >&2
  usage
  exit 2
fi

postgres_scenarios=${DAEMON_E2E_POSTGRES_SCENARIOS:-core}
if [[ $postgres_scenarios != core && $postgres_scenarios != extended ]]; then
  echo "DAEMON_E2E_POSTGRES_SCENARIOS must be core or extended" >&2
  exit 2
fi

case "$metadata_engine:$artifact_engine" in
  sqlite:filesystem)
    daemon_service=daemon
    daemon_config=/etc/capture/config.toml
    ;;
  postgres:filesystem)
    daemon_service=daemon-postgres
    daemon_config=/etc/capture/config-postgres.toml
    ;;
  sqlite:s3)
    daemon_service=daemon-s3
    daemon_config=/etc/capture/config-s3.toml
    ;;
  postgres:s3)
    daemon_service=daemon-postgres-s3
    daemon_config=/etc/capture/config-postgres-s3.toml
    ;;
esac

if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  echo "Docker with the Compose plugin is required" >&2
  exit 2
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository_dir=$script_dir
compose_file="$repository_dir/compose.daemon-e2e.yml"
project_name="captured-e2e-$$"
compose=(docker compose --project-name "$project_name" --file "$compose_file")
postgres_migration_files=("$repository_dir"/crates/captured/migrations-postgres-daemon/*.sql)
expected_postgres_migration_count=${#postgres_migration_files[@]}

cleanup() {
  result=$?
  trap - EXIT
  set +e
  if [[ $result -ne 0 ]]; then
    "${compose[@]}" ps >&2
    "${compose[@]}" logs --no-color setup postgres migrator object-store object-store-init provider notary daemon daemon-postgres daemon-s3 daemon-postgres-s3 >&2
  fi
  if [[ ${DAEMON_E2E_KEEP:-0} == 1 ]]; then
    echo "preserving Docker E2E project $project_name" >&2
  else
    "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1
  fi
  exit "$result"
}
trap cleanup EXIT

wait_for_daemon() {
  local attempts=0
  local container_id
  local health
  while (( attempts < 60 )); do
    container_id=$("${compose[@]}" ps --quiet "$daemon_service")
    if [[ -n $container_id ]]; then
      health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container_id" 2>/dev/null || true)
      if [[ $health == healthy ]]; then
        return 0
      fi
      if [[ $health == exited || $health == dead ]]; then
        break
      fi
    fi
    attempts=$((attempts + 1))
    sleep 1
  done
  echo "captured did not become healthy" >&2
  return 1
}

daemon_cli() {
  "${compose[@]}" exec -T "$daemon_service" \
    capture --config "$daemon_config" --json "$@"
}

daemon_operation() {
  local operation_id=$1
  "${compose[@]}" exec -T "$daemon_service" \
    curl --fail --silent --show-error \
      "http://127.0.0.1:8788/v1/operations/$operation_id"
}

wait_for_trace_ready() {
  local trace_id=$1
  local trace=""
  local state=""
  for _ in $(seq 1 40); do
    trace=$(daemon_cli traces show "$trace_id")
    if printf '%s' "$trace" | "${compose[@]}" exec -T "$daemon_service" jq -e '
      .state == "captured" and
      any(.artifacts[]; .kind == "capture_checkpoint")
    ' >/dev/null; then
      printf '%s\n' "$trace"
      return 0
    fi
    state=$(printf '%s' "$trace" | "${compose[@]}" exec -T "$daemon_service" jq -r \
      '.status')
    if [[ $state == capture_failed ]]; then
      echo "Trace $trace_id failed during capture before it became ready to notarize" >&2
      printf '%s\n' "$trace" >&2
      return 1
    fi
    sleep 0.25
  done
  echo "Trace $trace_id did not become ready to notarize" >&2
  printf '%s\n' "$trace" >&2
  return 1
}

wait_for_daemon_http_status() {
  local path=$1
  local expected=$2
  local attempts=0
  local observed=000
  while (( attempts < 10 )); do
    observed=$("${compose[@]}" exec -T "$daemon_service" \
      curl --silent --output /dev/null --write-out '%{http_code}' \
        --max-time 3 "http://127.0.0.1:8788$path" || true)
    if [[ $observed == "$expected" ]]; then
      printf '%s\n' "$observed"
      return 0
    fi
    attempts=$((attempts + 1))
    sleep 1
  done
  printf '%s\n' "$observed"
  return 1
}

assert_json() {
  local json=$1
  local expression=$2
  shift 2
  if ! printf '%s' "$json" | "${compose[@]}" exec -T "$daemon_service" jq -e "$@" "$expression" >/dev/null; then
    echo "JSON assertion failed: $expression" >&2
    printf '%s\n' "$json" >&2
    return 1
  fi
}

assert_json_while_daemon_stopped() {
  local json=$1
  local expression=$2
  shift 2
  if ! printf '%s' "$json" | "${compose[@]}" run --rm --no-deps -T \
    --entrypoint jq "$daemon_service" -e "$@" "$expression" >/dev/null; then
    echo "JSON assertion failed: $expression" >&2
    printf '%s\n' "$json" >&2
    return 1
  fi
}

json_value() {
  local json=$1
  local expression=$2
  printf '%s' "$json" | "${compose[@]}" exec -T "$daemon_service" jq -er "$expression"
}

wait_for_postgres() {
  local attempts=0
  local container_id
  local health
  while (( attempts < 60 )); do
    container_id=$("${compose[@]}" ps --quiet postgres)
    if [[ -n $container_id ]]; then
      health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container_id" 2>/dev/null || true)
      if [[ $health == healthy ]]; then
        return 0
      fi
      if [[ $health == exited || $health == dead ]]; then
        break
      fi
    fi
    attempts=$((attempts + 1))
    sleep 1
  done
  echo "PostgreSQL did not become healthy" >&2
  return 1
}

wait_for_object_store() {
  local attempts=0
  local container_id
  local health
  while (( attempts < 60 )); do
    container_id=$("${compose[@]}" ps --quiet object-store)
    if [[ -n $container_id ]]; then
      health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container_id" 2>/dev/null || true)
      if [[ $health == healthy ]]; then
        return 0
      fi
      if [[ $health == exited || $health == dead ]]; then
        break
      fi
    fi
    attempts=$((attempts + 1))
    sleep 1
  done
  echo "the S3 object store did not become healthy" >&2
  return 1
}

s3_bucket=captured-e2e

object_store_aws() {
  "${compose[@]}" run --rm --no-deps -T object-store-client "$@"
}

artifact_target() {
  local trace_id=$1
  local kind=$2
  local extension
  local directory
  if [[ $kind == capture_checkpoint ]]; then
    extension=llmcapture
    directory=capture-checkpoints
    if [[ $artifact_engine == filesystem ]]; then
      printf '/state/capture-checkpoints/%s.%s' "$trace_id" "$extension"
      return
    fi
  else
    extension=llmtrace
    directory=trace-packages
    if [[ $artifact_engine == filesystem ]]; then
      printf '/state/trace-packages/%s.%s' "$trace_id" "$extension"
      return
    fi
  fi
  printf 'captured/%s/%s.%s' "$directory" "$trace_id" "$extension"
}

artifact_exists() {
  local target=$1
  if [[ $artifact_engine == filesystem ]]; then
    "${compose[@]}" exec -T "$daemon_service" test -f "$target"
  else
    object_store_aws s3api head-object --bucket "$s3_bucket" --key "$target" >/dev/null 2>&1
  fi
}

artifact_sha256() {
  local target=$1
  if [[ $artifact_engine == filesystem ]]; then
    "${compose[@]}" exec -T "$daemon_service" sha256sum "$target" | awk '{print $1}'
  else
    object_store_aws s3 cp "s3://$s3_bucket/$target" - | \
      "${compose[@]}" exec -T "$daemon_service" sha256sum | awk '{print $1}'
  fi
}

artifact_identity() {
  local target=$1
  if [[ $artifact_engine == filesystem ]]; then
    "${compose[@]}" exec -T "$daemon_service" stat -c '%i:%Y:%s' "$target"
  else
    object_store_aws s3api head-object --bucket "$s3_bucket" --key "$target" --output json
  fi
}

prepare_s3() {
  echo "starting an isolated SeaweedFS S3 object store"
  "${compose[@]}" up --detach object-store
  wait_for_object_store
  "${compose[@]}" run --rm --no-deps -T object-store-init >/dev/null
  object_store_aws s3api head-bucket --bucket "$s3_bucket" >/dev/null
}

postgres_psql() {
  "${compose[@]}" exec -T postgres \
    psql --set ON_ERROR_STOP=1 --username daemon_e2e --dbname daemon_e2e "$@"
}

run_migrator() {
  local config=${1:-/etc/capture/config-postgres.toml}
  "${compose[@]}" run --rm --no-deps migrator migrate --config "$config"
}

expect_postgres_daemon_failure() {
  local scenario=$1
  local expected=$2
  local output
  local status
  set +e
  output=$("${compose[@]}" run --rm --no-deps --entrypoint /usr/bin/timeout \
    daemon-postgres 15s captured --config /etc/capture/config-postgres.toml 2>&1)
  status=$?
  set -e
  if [[ $status -eq 0 || $status -eq 124 ]]; then
    echo "PostgreSQL $scenario probe unexpectedly started the daemon" >&2
    printf '%s\n' "$output" >&2
    return 1
  fi
  if ! grep -Eqi "$expected" <<<"$output"; then
    echo "PostgreSQL $scenario probe failed for the wrong reason" >&2
    printf '%s\n' "$output" >&2
    return 1
  fi
}

prepare_postgres() {
  echo "starting an isolated PostgreSQL 17.7 database"
  "${compose[@]}" up --detach postgres
  wait_for_postgres
  "${compose[@]}" run --rm --no-deps setup >/dev/null

  echo "verifying the daemon refuses an unmigrated PostgreSQL schema"
  expect_postgres_daemon_failure unmigrated 'not migrated|daemon schema|schema is not current|migration journal'

  if [[ $postgres_scenarios == extended ]]; then
    echo "running two PostgreSQL migrators concurrently"
    set +e
    (run_migrator >/dev/null) &
    local first_pid=$!
    (run_migrator >/dev/null) &
    local second_pid=$!
    wait "$first_pid"
    local first_status=$?
    wait "$second_pid"
    local second_status=$?
    set -e
    if [[ $first_status -ne 0 || $second_status -ne 0 ]]; then
      echo "concurrent PostgreSQL migrators did not both complete successfully" >&2
      return 1
    fi
  fi

  echo "applying PostgreSQL metadata migrations twice to prove idempotency"
  run_migrator >/dev/null
  run_migrator >/dev/null
  local migration_count
  migration_count=$(postgres_psql --tuples-only --no-align \
    --command 'SELECT COUNT(*) FROM captured.schema_migrations;')
  if [[ $migration_count != "$expected_postgres_migration_count" ]]; then
    echo "unexpected PostgreSQL daemon migration count: $migration_count (expected $expected_postgres_migration_count)" >&2
    return 1
  fi

  if [[ $postgres_scenarios == extended ]]; then
    echo "verifying the PostgreSQL migration advisory-lock timeout"
    postgres_psql >/dev/null <<'SQL' &
BEGIN;
SELECT pg_advisory_xact_lock(hashtextextended('ecp/captured-postgres-migrations/v1', 0));
SELECT pg_sleep(4);
COMMIT;
SQL
    local lock_holder_pid=$!
    sleep 1
    local lock_output
    local lock_status
    set +e
    lock_output=$(run_migrator /etc/capture/config-postgres-lock-timeout.toml 2>&1)
    lock_status=$?
    set -e
    wait "$lock_holder_pid"
    local postgres_logs
    postgres_logs=$("${compose[@]}" logs --no-color postgres)
    if [[ $lock_status -eq 0 ]] || ! grep -Fq 'canceling statement due to lock timeout' <<<"$postgres_logs"; then
      echo "PostgreSQL migrator did not fail at the configured advisory-lock timeout" >&2
      printf '%s\n' "$lock_output" >&2
      return 1
    fi
  fi

  echo "verifying bounded failure while PostgreSQL is unavailable"
  "${compose[@]}" stop postgres >/dev/null
  expect_postgres_daemon_failure unavailable 'connect|connection|database|pool'
  local migration_output
  local migration_status
  set +e
  migration_output=$("${compose[@]}" run --rm --no-deps --entrypoint /usr/bin/timeout \
    migrator 15s captured migrate --config /etc/capture/config-postgres.toml 2>&1)
  migration_status=$?
  set -e
  if [[ $migration_status -eq 0 || $migration_status -eq 124 ]]; then
    echo "PostgreSQL migrator was not bounded while the database was unavailable" >&2
    printf '%s\n' "$migration_output" >&2
    return 1
  fi
  "${compose[@]}" up --detach postgres
  wait_for_postgres
}

assert_runtime_postgres_outage() {
  local health_status
  local readiness_status
  local status_status

  echo "verifying liveness and readiness during a live PostgreSQL outage"
  "${compose[@]}" stop postgres >/dev/null
  health_status=$("${compose[@]}" exec -T "$daemon_service" \
    curl --silent --output /dev/null --write-out '%{http_code}' \
      --max-time 10 http://127.0.0.1:8788/healthz)
  readiness_status=$(wait_for_daemon_http_status /readyz 503 || true)
  status_status=$("${compose[@]}" exec -T "$daemon_service" \
    curl --silent --output /dev/null --write-out '%{http_code}' \
      --max-time 3 http://127.0.0.1:8788/v1/status)
  if [[ $health_status != 200 || $readiness_status != 503 || $status_status != 503 ]]; then
    echo "unexpected outage probes: /healthz=$health_status /readyz=$readiness_status /v1/status=$status_status" >&2
    return 1
  fi

  "${compose[@]}" up --detach postgres
  wait_for_postgres
  wait_for_daemon
  readiness_status=$("${compose[@]}" exec -T "$daemon_service" \
    curl --silent --output /dev/null --write-out '%{http_code}' \
      --max-time 10 http://127.0.0.1:8788/readyz)
  if [[ $readiness_status != 200 ]]; then
    echo "PostgreSQL-backed readiness did not recover: /readyz=$readiness_status" >&2
    return 1
  fi
}

assert_runtime_s3_outage() {
  local health_status
  local readiness_status
  local status_status

  echo "verifying liveness and readiness during a live S3 outage"
  "${compose[@]}" stop object-store >/dev/null
  health_status=$("${compose[@]}" exec -T "$daemon_service" \
    curl --silent --output /dev/null --write-out '%{http_code}' \
      --max-time 10 http://127.0.0.1:8788/healthz)
  readiness_status=$(wait_for_daemon_http_status /readyz 503 || true)
  status_status=$("${compose[@]}" exec -T "$daemon_service" \
    curl --silent --output /dev/null --write-out '%{http_code}' \
      --max-time 10 http://127.0.0.1:8788/v1/status)
  if [[ $health_status != 200 || $readiness_status != 503 || $status_status != 503 ]]; then
    echo "unexpected S3 outage probes: /healthz=$health_status /readyz=$readiness_status /v1/status=$status_status" >&2
    return 1
  fi

  "${compose[@]}" up --detach object-store
  wait_for_object_store
  wait_for_daemon
  # Readiness caches dependency probes briefly, and a probe started while the
  # store was still booting can outlive the store's first healthy check.
  readiness_status=$(wait_for_daemon_http_status /readyz 200 || true)
  if [[ $readiness_status != 200 ]]; then
    echo "S3-backed readiness did not recover: /readyz=$readiness_status" >&2
    return 1
  fi
}

echo "building daemon E2E image"
if [[ ${DAEMON_E2E_SKIP_BUILD:-0} != 1 ]]; then
  "${compose[@]}" build daemon
fi

if [[ $metadata_engine == postgres ]]; then
  prepare_postgres
fi

if [[ $artifact_engine == s3 ]]; then
  prepare_s3
fi

echo "starting a fresh $metadata_engine/$artifact_engine daemon"
"${compose[@]}" up --detach "$daemon_service"
wait_for_daemon

health_json=$("${compose[@]}" exec -T "$daemon_service" \
  curl --fail --silent --show-error http://127.0.0.1:8788/healthz)
assert_json "$health_json" '.service == "captured" and .api_version == "v1"'

fresh_status=$(daemon_cli status)
assert_json "$fresh_status" '
  .metadata_backend == $metadata and
  .metadata_status == "ready" and
  .artifact_backend == $artifact and
  .artifact_status == "ready" and
  .counts == {
    "captured": 0,
    "notarizing": 0,
    "notarized": 0,
    "needs_attention": 0,
    "capturing": 0,
    "capture_failed": 0
  }
' --arg metadata "$metadata_engine" --arg artifact "$artifact_engine"

if [[ $artifact_engine == s3 ]]; then
  "${compose[@]}" exec -T "$daemon_service" /bin/sh -ec \
    "grep -F 'endpoint = \"http://object-store:8333\"' '$daemon_config' >/dev/null
     grep -F 'prefix = \"captured\"' '$daemon_config' >/dev/null
     grep -F 'force_path_style = true' '$daemon_config' >/dev/null
     grep -F 'allow_insecure_http = true' '$daemon_config' >/dev/null"
fi

if [[ $metadata_engine == postgres ]]; then
  assert_runtime_postgres_outage
fi
if [[ $artifact_engine == s3 ]]; then
  assert_runtime_s3_outage
fi

echo "seeding deterministic offline persistence fixtures while the daemon is stopped"
"${compose[@]}" stop "$daemon_service"
if [[ $artifact_engine == filesystem ]]; then
  fixture_locator=artifact/v1/filesystem/L3N0YXRlL2NhcHR1cmUtY2hlY2twb2ludHMvdHJjLWUyZS1ub3Rhcml6ZS5sbG1jYXB0dXJl
  "${compose[@]}" run --rm --no-deps --entrypoint /bin/sh "$daemon_service" -ec '
    umask 077
    mkdir -p /state/capture-checkpoints
    printf "%s" "encrypted-offline-e2e-fixture" > /state/capture-checkpoints/trc-e2e-recovered.llmcapture
    printf "%s" "encrypted-offline-e2e-fixture" > /state/capture-checkpoints/trc-e2e-notarize.llmcapture
  '
else
  recovered_object=captured/capture-checkpoints/trc-e2e-recovered.llmcapture
  notarize_object=captured/capture-checkpoints/trc-e2e-notarize.llmcapture
  fixture_locator=artifact/v1/s3/Y2FwdHVyZWQvY2FwdHVyZS1jaGVja3BvaW50cy90cmMtZTJlLW5vdGFyaXplLmxsbWNhcHR1cmU
  fixture_metadata='artifact-sha256=43a39c6489f21d8976477d52b4bb184c5a4166086d069450660d5754b93c6b7d,artifact-size=29,artifact-kind=capture_checkpoint'
  printf '%s' 'encrypted-offline-e2e-fixture' | \
    object_store_aws s3 cp --metadata "$fixture_metadata" - \
      "s3://$s3_bucket/$recovered_object" >/dev/null
  # Metadata intentionally describes the untampered digest. The same-size
  # replacement proves reads fail closed on object corruption.
  printf '%s' 'corrupted-offline-e2e-fixture' | \
    object_store_aws s3 cp --metadata "$fixture_metadata" - \
      "s3://$s3_bucket/$notarize_object" >/dev/null
fi
if [[ $metadata_engine == sqlite ]]; then
  "${compose[@]}" run --rm --no-deps --entrypoint sqlite3 "$daemon_service" /state/metadata.db >/dev/null <<SQL
PRAGMA foreign_keys = ON;
BEGIN IMMEDIATE;
INSERT INTO traces (
    trace_id, created_at_unix_ms, completed_at_unix_ms, provider, operation,
    requested_model, response_model, http_status, streaming, request_bytes,
    response_bytes, duration_ms, prompt_preview, prompt_preview_truncated,
    output_preview, output_preview_truncated, config_fingerprint,
    capture_status, notarization_status, expected_artifact_size_bytes,
    expected_artifact_sha256
) VALUES (
    'trc-e2e-recovered', 1700000000000, 1700000000005, 'openai', '/v1/responses',
    'fixture-model', 'fixture-model', 200, 0, 41,
    29, 5, 'offline recovery fixture', 0,
    'offline recovered fixture', 0, 'sha256:offline-fixture',
    'capturing', 'not_requested', 29,
    '43a39c6489f21d8976477d52b4bb184c5a4166086d069450660d5754b93c6b7d'
);
INSERT INTO traces (
    trace_id, created_at_unix_ms, completed_at_unix_ms, provider, operation,
    requested_model, response_model, http_status, streaming, request_bytes,
    response_bytes, duration_ms, prompt_preview, prompt_preview_truncated,
    output_preview, output_preview_truncated, config_fingerprint,
    capture_status, notarization_status
) VALUES (
    'trc-e2e-notarize', 1700000001000, 1700000001005, 'openai', '/v1/responses',
    'fixture-model', 'fixture-model', 200, 0, 43,
    29, 5, 'offline SQLite fixture', 0,
    'offline $artifact_engine fixture', 0, 'sha256:offline-fixture',
    'captured', 'not_requested'
);
INSERT INTO artifacts (trace_id, kind, locator, size_bytes, sha256, state)
VALUES (
    'trc-e2e-notarize', 'capture_checkpoint',
    '$fixture_locator', 29,
    '43a39c6489f21d8976477d52b4bb184c5a4166086d069450660d5754b93c6b7d',
    'available'
);
INSERT INTO trace_search (trace_id, prompt_preview, output_preview)
VALUES (
    'trc-e2e-notarize', 'offline SQLite fixture', 'offline $artifact_engine fixture'
);
COMMIT;
PRAGMA wal_checkpoint(TRUNCATE);
SQL
else
  postgres_psql >/dev/null <<SQL
BEGIN;
INSERT INTO captured.traces (
    trace_id, created_at_unix_ms, completed_at_unix_ms, provider, operation,
    requested_model, response_model, http_status, streaming, request_bytes,
    response_bytes, duration_ms, prompt_preview, prompt_preview_truncated,
    output_preview, output_preview_truncated, config_fingerprint,
    capture_status, notarization_status, expected_artifact_size_bytes,
    expected_artifact_sha256
) VALUES (
    'trc-e2e-recovered', 1700000000000, 1700000000005, 'openai', '/v1/responses',
    'fixture-model', 'fixture-model', 200, FALSE, 41,
    29, 5, 'offline recovery fixture', FALSE,
    'offline recovered fixture', FALSE, 'sha256:offline-fixture',
    'capturing', 'not_requested', 29,
    '43a39c6489f21d8976477d52b4bb184c5a4166086d069450660d5754b93c6b7d'
);
INSERT INTO captured.traces (
    trace_id, created_at_unix_ms, completed_at_unix_ms, provider, operation,
    requested_model, response_model, http_status, streaming, request_bytes,
    response_bytes, duration_ms, prompt_preview, prompt_preview_truncated,
    output_preview, output_preview_truncated, config_fingerprint,
    capture_status, notarization_status
) VALUES (
    'trc-e2e-notarize', 1700000001000, 1700000001005, 'openai', '/v1/responses',
    'fixture-model', 'fixture-model', 200, FALSE, 43,
    29, 5, 'offline PostgreSQL fixture', FALSE,
    'offline $artifact_engine fixture', FALSE, 'sha256:offline-fixture',
    'captured', 'not_requested'
);
INSERT INTO captured.artifacts (
    trace_id, kind, locator, size_bytes, sha256, state
) VALUES (
    'trc-e2e-notarize', 'capture_checkpoint',
    '$fixture_locator', 29,
    '43a39c6489f21d8976477d52b4bb184c5a4166086d069450660d5754b93c6b7d',
    'available'
);
INSERT INTO captured.trace_search (
    trace_id, prompt_document, output_document
)
VALUES (
    'trc-e2e-notarize',
    to_tsvector('simple', 'offline PostgreSQL fixture'),
    to_tsvector('simple', 'offline $artifact_engine fixture')
);
COMMIT;
SQL
fi

if [[ $artifact_engine == s3 ]]; then
  if [[ $metadata_engine == sqlite ]]; then
    "${compose[@]}" run --rm --no-deps --entrypoint sqlite3 "$daemon_service" /state/metadata.db >/dev/null <<'SQL'
INSERT INTO traces (
    trace_id, created_at_unix_ms, provider, operation, requested_model,
    streaming, request_bytes, prompt_preview, prompt_preview_truncated,
    config_fingerprint, capture_status, notarization_status
) VALUES (
    'trc-e2e-missing', 1700000002000, 'openai', '/v1/responses', 'fixture-model',
    0, 31, 'missing S3 recovery fixture', 0,
    'sha256:offline-fixture', 'capturing', 'not_requested'
);
SQL
  else
    postgres_psql >/dev/null <<'SQL'
INSERT INTO captured.traces (
    trace_id, created_at_unix_ms, provider, operation, requested_model,
    streaming, request_bytes, prompt_preview, prompt_preview_truncated,
    config_fingerprint, capture_status, notarization_status
) VALUES (
    'trc-e2e-missing', 1700000002000, 'openai', '/v1/responses', 'fixture-model',
    FALSE, 31, 'missing S3 recovery fixture', FALSE,
    'sha256:offline-fixture', 'capturing', 'not_requested'
);
SQL
  fi
fi

echo "starting the daemon and verifying recovery plus REST-backed CLI behavior"
"${compose[@]}" up --detach --no-deps "$daemon_service"
wait_for_daemon

recovered_status=$(daemon_cli status)
if [[ $artifact_engine == s3 ]]; then
  assert_json "$recovered_status" '
    .counts.captured == 2 and
    .counts.capturing == 0 and
    .counts.capture_failed == 1 and
    .counts.needs_attention == 1 and
    .counts.notarizing == 0 and
    .counts.notarized == 0
  '
  missing_trace=$(daemon_cli traces show trc-e2e-missing)
  assert_json "$missing_trace" '
    .state == null and
    .status == "capture_failed" and
    .failure_code == "interrupted" and
    (.artifacts | length) == 0
  '
else
  assert_json "$recovered_status" '
    .counts.captured == 2 and
    .counts.capturing == 0 and
    .counts.capture_failed == 0 and
    .counts.needs_attention == 0 and
    .counts.notarizing == 0 and
    .counts.notarized == 0
  '
fi

recovered_trace=$(daemon_cli traces show trc-e2e-recovered)
assert_json "$recovered_trace" '
  .state == "captured" and
  .status == null and
  .artifacts[0].kind == "capture_checkpoint" and
  .artifacts[0].size_bytes == 29 and
  .artifacts[0].sha256 == "43a39c6489f21d8976477d52b4bb184c5a4166086d069450660d5754b93c6b7d"
'

capture_search_term=SQLite
if [[ $metadata_engine == postgres ]]; then
  capture_search_term=PostgreSQL
fi
capture_page=$(daemon_cli traces list --query "$capture_search_term" --metadata-only)
assert_json "$capture_page" '
  (.items | length) == 1 and
  .items[0].trace_id == "trc-e2e-notarize" and
  (.items[0] | has("prompt_preview") | not) and
  (.items[0] | has("output_preview") | not)
'

echo "queuing a notarization to exercise durable mutation and failure history"
notarization=$(daemon_cli traces seal trc-e2e-notarize --wait)
expected_fixture_failure=notarization_error
if [[ $artifact_engine == s3 ]]; then
  expected_fixture_failure=artifact_corrupt
fi
assert_json "$notarization" '
  .deduplicated == false and
  .operation.trace_id == "trc-e2e-notarize" and
  .operation.state == "failed" and
  .operation.attempt == 1 and
  .operation.failure_code == $failure_code
' --arg failure_code "$expected_fixture_failure"
operation_id=$(json_value "$notarization" '.operation.operation_id')

events=$(daemon_cli activity --trace-id trc-e2e-notarize --all)
assert_json "$events" '
  any(.items[]; .event_type == "notarization_queued") and
  any(.items[]; .event_type == "notarization_failed")
'

if [[ $profile == full ]]; then
  echo "running an offline Proxy-TLS capture through the real daemon and notary fixture"
  provider_response=$("${compose[@]}" exec -T "$daemon_service" \
    curl --fail --silent --show-error \
      --dump-header /tmp/daemon-e2e-capture.headers \
      --header 'authorization: Bearer offline-daemon-e2e-secret' \
      --header 'content-type: application/json' \
      --data '{"model":"fixture-model","messages":[{"role":"user","content":"offline daemon E2E prompt"}]}' \
      http://127.0.0.1:8787/openai/v1/chat/completions)
  assert_json "$provider_response" '
    .id == "chatcmpl-daemon-e2e" and
    .model == "fixture-model" and
    .choices[0].message.content == "offline daemon E2E response"
  '
  full_trace_id=$("${compose[@]}" exec -T "$daemon_service" /bin/sh -ec \
    "awk 'tolower(\$1) == \"x-notary-trace-id:\" {gsub(\"\\r\", \"\", \$2); print \$2}' /tmp/daemon-e2e-capture.headers")
  if [[ $full_trace_id != trc-* ]]; then
    echo "Proxy-TLS response omitted a valid trace ID" >&2
    exit 1
  fi

  full_capture=$(wait_for_trace_ready "$full_trace_id")
  assert_json "$full_capture" '
    .trace_id == $trace_id and
    .provider == "openai" and
    .operation == "/v1/chat/completions" and
    .requested_model == "fixture-model" and
    .response_model == "fixture-model" and
    .http_status == 200 and
    .state == "captured" and
    .status == null and
    .notarization == null and
    any(.artifacts[]; .kind == "capture_checkpoint")
  ' --arg trace_id "$full_trace_id"

  full_page=$(daemon_cli traces list --query 'offline daemon E2E prompt')
  assert_json "$full_page" '
    any(.items[];
      .trace_id == $trace_id and
      .prompt_preview == "user: offline daemon E2E prompt" and
      .output_preview == "offline daemon E2E response")
  ' --arg trace_id "$full_trace_id"

  full_bundle_target=$(artifact_target "$full_trace_id" capture_checkpoint)
  artifact_exists "$full_bundle_target"
  if [[ $artifact_engine == filesystem ]]; then
    credential_exposed=$("${compose[@]}" exec -T "$daemon_service" /bin/sh -ec \
      "grep -a -F 'offline-daemon-e2e-secret' '$full_bundle_target' >/dev/null" && printf yes || true)
  else
    credential_exposed=$(object_store_aws s3 cp "s3://$s3_bucket/$full_bundle_target" - | \
      grep -a -F 'offline-daemon-e2e-secret' >/dev/null && printf yes || true)
  fi
  if [[ $credential_exposed == yes ]]; then
    echo "encrypted capture checkpoint exposed the provider credential" >&2
    exit 1
  fi

  echo "notarizing the captured checkpoint and building a verified package"
  full_notarization=$(daemon_cli traces seal "$full_trace_id" --wait)
  assert_json "$full_notarization" '
    .deduplicated == false and
    .operation.trace_id == $trace_id and
    .operation.state == "succeeded" and
    .operation.attempt == 1 and
    .operation.progress.phase == "complete"
  ' --arg trace_id "$full_trace_id"
  full_operation_id=$(json_value "$full_notarization" '.operation.operation_id')

  full_trace=$(daemon_cli traces show "$full_trace_id")
  assert_json "$full_trace" '
    .trace_id == $trace_id and
    .content.manifest.source.provider.name == "openai" and
    .content.manifest.source.provider.host == "api.openai.com"
  ' --arg trace_id "$full_trace_id"

  daemon_verification=$(daemon_cli traces verify "$full_trace_id")
  assert_json "$daemon_verification" '
    .trace_id == $trace_id and .outcome == "passed"
  ' --arg trace_id "$full_trace_id"

  "${compose[@]}" exec -T "$daemon_service" \
    curl --fail --silent --show-error \
      --output /tmp/daemon-e2e.llmtrace \
      "http://127.0.0.1:8788/v1/traces/$full_trace_id/package.llmtrace"
  full_package_sha=$("${compose[@]}" exec -T "$daemon_service" \
    sha256sum /tmp/daemon-e2e.llmtrace | awk '{print $1}')
  file_verification=$(daemon_cli traces verify /tmp/daemon-e2e.llmtrace \
    --trusted-notary-key 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)
  assert_json "$file_verification" '
    .trace_id == $trace_id and
    .outcome == "passed" and
    .trust_source == "explicit_key"
  ' --arg trace_id "$full_trace_id"

  echo "sharing the exact verified package through a loopback hosted-API fixture"
  "${compose[@]}" exec --detach "$daemon_service" \
    python3 /usr/local/libexec/notary-e2e-share.py
  share_fixture_ready=0
  for _ in $(seq 1 30); do
    if "${compose[@]}" exec -T "$daemon_service" \
      curl --fail --silent --show-error http://127.0.0.1:9797/healthz >/dev/null 2>&1; then
      share_fixture_ready=1
      break
    fi
    sleep 1
  done
  if [[ $share_fixture_ready != 1 ]]; then
    echo "loopback share fixture did not become ready" >&2
    exit 1
  fi
  full_share=$(daemon_cli traces share "$full_trace_id")
  assert_json "$full_share" '
    .trace_id == $trace_id and
    .progress == "verifying" and
    .visibility == "unlisted"
  ' --arg trace_id "$full_trace_id"
  uploaded_share=$("${compose[@]}" exec -T "$daemon_service" \
    curl --fail --silent --show-error http://127.0.0.1:9797/debug/upload)
  assert_json "$uploaded_share" '
    .size_bytes > 0 and .sha256 == $package_sha
  ' --arg package_sha "$full_package_sha"

  if [[ $artifact_engine == s3 ]]; then
    full_package_target=$(artifact_target "$full_trace_id" trace_package)
    artifact_exists "$full_bundle_target"
    artifact_exists "$full_package_target"
    object_paths=$(object_store_aws s3api list-objects-v2 --bucket "$s3_bucket" \
      --query 'Contents[].Key' --output json | \
      "${compose[@]}" exec -T "$daemon_service" jq -r '(. // [])[]')
    while IFS= read -r object_path; do
      [[ -z $object_path || $object_path == captured/* ]] && continue
      echo "S3 object escaped the configured prefix/private namespace: $object_path" >&2
      exit 1
    done <<<"$object_paths"
  fi

  echo "running and notarizing a streaming Proxy-TLS capture"
  stream_response=$("${compose[@]}" exec -T "$daemon_service" \
    curl --fail --silent --show-error \
      --dump-header /tmp/daemon-e2e-stream.headers \
      --header 'authorization: Bearer offline-daemon-e2e-secret' \
      --header 'content-type: application/json' \
      --data '{"model":"fixture-model","stream":true,"messages":[{"role":"user","content":"offline streaming E2E prompt"}]}' \
      http://127.0.0.1:8787/openai/v1/chat/completions)
  if [[ $stream_response != *'offline '* || $stream_response != *'streaming response'* || $stream_response != *'data: [DONE]'* ]]; then
    echo "streaming provider response was incomplete" >&2
    exit 1
  fi
  stream_trace_id=$("${compose[@]}" exec -T "$daemon_service" /bin/sh -ec \
    "awk 'tolower(\$1) == \"x-notary-trace-id:\" {gsub(\"\\r\", \"\", \$2); print \$2}' /tmp/daemon-e2e-stream.headers")
  if [[ $stream_trace_id != trc-* ]]; then
    echo "streaming Proxy-TLS response omitted a valid trace ID" >&2
    exit 1
  fi
  stream_capture=$(wait_for_trace_ready "$stream_trace_id")
  assert_json "$stream_capture" '
    .trace_id == $trace_id and
    .streaming == true and
    .state == "captured" and
    .status == null and
    .prompt_preview == "user: offline streaming E2E prompt" and
    .output_preview == "offline streaming response" and
    any(.artifacts[]; .kind == "capture_checkpoint")
  ' --arg trace_id "$stream_trace_id"
  stream_notarization=$(daemon_cli traces seal "$stream_trace_id" --wait)
  assert_json "$stream_notarization" '
    .operation.trace_id == $trace_id and
    .operation.state == "succeeded" and
    .operation.progress.phase == "complete"
  ' --arg trace_id "$stream_trace_id"
  stream_operation_id=$(json_value "$stream_notarization" '.operation.operation_id')
  stream_trace=$(daemon_cli traces show "$stream_trace_id")
  assert_json "$stream_trace" '
    .trace_id == $trace_id and
    .content.manifest.source.provider.name == "openai"
  ' --arg trace_id "$stream_trace_id"
  stream_verification=$(daemon_cli traces verify "$stream_trace_id")
  assert_json "$stream_verification" '
    .trace_id == $trace_id and .outcome == "passed"
  ' --arg trace_id "$stream_trace_id"
  "${compose[@]}" exec -T "$daemon_service" \
    curl --fail --silent --show-error \
      --output /tmp/daemon-e2e-stream.llmtrace \
      "http://127.0.0.1:8788/v1/traces/$stream_trace_id/package.llmtrace"
  stream_file_verification=$(daemon_cli traces verify /tmp/daemon-e2e-stream.llmtrace \
    --trusted-notary-key 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)
  assert_json "$stream_file_verification" '
    .trace_id == $trace_id and .outcome == "passed"
  ' --arg trace_id "$stream_trace_id"
  stream_package_sha=$("${compose[@]}" exec -T "$daemon_service" \
    sha256sum /tmp/daemon-e2e-stream.llmtrace | awk '{print $1}')
  stream_share=$(daemon_cli traces share "$stream_trace_id")
  assert_json "$stream_share" '
    .trace_id == $trace_id and
    .progress == "verifying"
  ' --arg trace_id "$stream_trace_id"
  uploaded_stream_share=$("${compose[@]}" exec -T "$daemon_service" \
    curl --fail --silent --show-error http://127.0.0.1:9797/debug/upload)
  assert_json "$uploaded_stream_share" '
    .size_bytes > 0 and .sha256 == $package_sha
  ' --arg package_sha "$stream_package_sha"

  echo "injecting a crash after package commit and before metadata completion"
  "${compose[@]}" stop "$daemon_service"
  "${compose[@]}" rm --force "$daemon_service"
  export DAEMON_E2E_NOTARIZATION_PAUSE_MS=30000
  "${compose[@]}" up --detach --no-deps "$daemon_service"
  wait_for_daemon

  crash_response=$("${compose[@]}" exec -T "$daemon_service" \
    curl --fail --silent --show-error \
      --dump-header /tmp/daemon-e2e-crash.headers \
      --header 'authorization: Bearer offline-daemon-e2e-secret' \
      --header 'content-type: application/json' \
      --data '{"model":"fixture-model","messages":[{"role":"user","content":"offline crash-window prompt"}]}' \
      http://127.0.0.1:8787/openai/v1/chat/completions)
  assert_json "$crash_response" '.id == "chatcmpl-daemon-e2e"'
  crash_trace_id=$("${compose[@]}" exec -T "$daemon_service" /bin/sh -ec \
    "awk 'tolower(\$1) == \"x-notary-trace-id:\" {gsub(\"\\r\", \"\", \$2); print \$2}' /tmp/daemon-e2e-crash.headers")
  if [[ $crash_trace_id != trc-* ]]; then
    echo "crash-window capture omitted a valid trace ID" >&2
    exit 1
  fi
  crash_notarization=$(daemon_cli traces seal "$crash_trace_id")
  crash_operation_id=$(json_value "$crash_notarization" '.operation.operation_id')

  crash_package_path=$(artifact_target "$crash_trace_id" trace_package)
  crash_package_ready=0
  for _ in $(seq 1 90); do
    if artifact_exists "$crash_package_path"; then
      crash_package_ready=1
      break
    fi
    sleep 1
  done
  if [[ $crash_package_ready != 1 ]]; then
    echo "notarization did not reach the injected post-commit pause" >&2
    exit 1
  fi
  crash_package_sha=$(artifact_sha256 "$crash_package_path")
  crash_package_identity=$(artifact_identity "$crash_package_path")
  daemon_container=$("${compose[@]}" ps --quiet "$daemon_service")
  docker kill "$daemon_container" >/dev/null

  unset DAEMON_E2E_NOTARIZATION_PAUSE_MS
  "${compose[@]}" rm --force "$daemon_service"
  "${compose[@]}" up --detach --no-deps "$daemon_service"
  wait_for_daemon

  interrupted=$(daemon_operation "$crash_operation_id")
  assert_json "$interrupted" '
    .state == "interrupted" and .attempt == 1 and .retryable == true
  '
  retry_request=$(daemon_cli traces seal "$crash_trace_id")
  assert_json "$retry_request" '
    .deduplicated == false and
    .operation.operation_id == $operation_id and
    .operation.state == "queued"
  ' --arg operation_id "$crash_operation_id"
  crash_final_state=""
  for _ in $(seq 1 90); do
    crash_final_state=$(daemon_operation "$crash_operation_id")
    state=$(json_value "$crash_final_state" '.state')
    if [[ $state == succeeded ]]; then
      break
    fi
    if [[ $state == failed ]]; then
      echo "orphan-package retry failed" >&2
      printf '%s\n' "$crash_final_state" >&2
      exit 1
    fi
    sleep 1
  done
  assert_json "$crash_final_state" '
    .state == "succeeded" and
    .attempt == 2 and
    (.attempt_history | length) == 2 and
    .attempt_history[0].state == "succeeded" and
    .attempt_history[1].state == "interrupted"
  '
  retry_package_sha=$(artifact_sha256 "$crash_package_path")
  retry_package_identity=$(artifact_identity "$crash_package_path")
  if [[ $retry_package_sha != "$crash_package_sha" || $retry_package_identity != "$crash_package_identity" ]]; then
    echo "retry replaced rather than reused the orphan package" >&2
    exit 1
  fi
  crash_events=$(daemon_cli activity --operation-id "$crash_operation_id" --all)
  assert_json "$crash_events" '
    ([.items[] | select(.event_type == "notarization_completed")] | length) == 1
  '
fi

echo "removing and recreating the app container with the same durable volume"
"${compose[@]}" stop "$daemon_service"
"${compose[@]}" rm --force "$daemon_service"
"${compose[@]}" up --detach --no-deps "$daemon_service"
wait_for_daemon

restart_health=$("${compose[@]}" exec -T "$daemon_service" \
  curl --fail --silent --show-error http://127.0.0.1:8788/healthz)
assert_json "$restart_health" '.service == "captured" and .api_version == "v1"'

restart_status=$(daemon_cli status)
if [[ $profile == full ]]; then
  if [[ $artifact_engine == s3 ]]; then
    assert_json "$restart_status" '
      .counts.captured == 2 and
      .counts.notarized == 3 and
      .counts.needs_attention == 2 and
      .counts.capture_failed == 1 and
      .counts.notarizing == 0 and
      .counts.capturing == 0
    '
  else
    assert_json "$restart_status" '
      .counts.captured == 2 and
      .counts.notarized == 3 and
      .counts.needs_attention == 1 and
      .counts.capture_failed == 0 and
      .counts.notarizing == 0 and
      .counts.capturing == 0
    '
  fi
else
  if [[ $artifact_engine == s3 ]]; then
    assert_json "$restart_status" '
      .counts.captured == 2 and
      .counts.notarized == 0 and
      .counts.needs_attention == 2 and
      .counts.capture_failed == 1 and
      .counts.notarizing == 0 and
      .counts.capturing == 0
    '
  else
    assert_json "$restart_status" '
      .counts.captured == 2 and
      .counts.notarized == 0 and
      .counts.needs_attention == 1 and
      .counts.capture_failed == 0 and
      .counts.notarizing == 0 and
      .counts.capturing == 0
    '
  fi
fi

persisted_operation=$(daemon_operation "$operation_id")
assert_json "$persisted_operation" '
  .operation_id == $operation_id and
  .trace_id == "trc-e2e-notarize" and
  .state == "failed" and
  .attempt == 1 and
  .failure_code == $failure_code
' --arg operation_id "$operation_id" --arg failure_code "$expected_fixture_failure"

persisted_trace=$(daemon_cli traces show trc-e2e-notarize)
assert_json "$persisted_trace" '
  .state == "captured" and
  .status == "notarization_failed" and
  .notarization.state == "failed" and
  .artifacts[0].sha256 == "43a39c6489f21d8976477d52b4bb184c5a4166086d069450660d5754b93c6b7d"
'

if [[ $profile == full ]]; then
  persisted_full_operation=$(daemon_operation "$full_operation_id")
  assert_json "$persisted_full_operation" '
    .operation_id == $operation_id and
    .trace_id == $trace_id and
    .state == "succeeded" and
    .attempt == 1 and
    .progress.phase == "complete"
  ' --arg operation_id "$full_operation_id" --arg trace_id "$full_trace_id"

  persisted_full_trace=$(daemon_cli traces show "$full_trace_id")
  assert_json "$persisted_full_trace" '
    .state == "notarized" and
    .status == null and
    .notarization.state == "succeeded" and
    any(.artifacts[]; .kind == "trace_package")
  '
  "${compose[@]}" exec -T "$daemon_service" \
    curl --fail --silent --show-error \
      --output /tmp/daemon-e2e-after-restart.llmtrace \
      "http://127.0.0.1:8788/v1/traces/$full_trace_id/package.llmtrace"
  restart_package_sha=$("${compose[@]}" exec -T "$daemon_service" \
    sha256sum /tmp/daemon-e2e-after-restart.llmtrace | awk '{print $1}')
  if [[ $restart_package_sha != "$full_package_sha" ]]; then
    echo "verified package digest changed across container recreation" >&2
    exit 1
  fi
  restart_verification=$(daemon_cli traces verify /tmp/daemon-e2e-after-restart.llmtrace \
    --trusted-notary-key 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)
  assert_json "$restart_verification" '
    .trace_id == $trace_id and .outcome == "passed"
  ' --arg trace_id "$full_trace_id"

  persisted_stream_operation=$(daemon_operation "$stream_operation_id")
  assert_json "$persisted_stream_operation" '
    .operation_id == $operation_id and
    .trace_id == $trace_id and
    .state == "succeeded"
  ' --arg operation_id "$stream_operation_id" --arg trace_id "$stream_trace_id"
  persisted_stream_trace=$(daemon_cli traces show "$stream_trace_id")
  assert_json "$persisted_stream_trace" '
    .streaming == true and
    .state == "notarized" and
    .status == null and
    .notarization.state == "succeeded" and
    any(.artifacts[]; .kind == "trace_package")
  '
fi

fixture_target=$(artifact_target trc-e2e-notarize capture_checkpoint)
artifact_sha=$(artifact_sha256 "$fixture_target")
expected_artifact_sha=43a39c6489f21d8976477d52b4bb184c5a4166086d069450660d5754b93c6b7d
if [[ $artifact_engine == s3 ]]; then
  expected_artifact_sha=c726feb8894aaee6ae334622714baf7a3c3bf2315eaea5345688deca2695af45
fi
if [[ $artifact_sha != "$expected_artifact_sha" ]]; then
  echo "$artifact_engine artifact digest changed across container recreation" >&2
  exit 1
fi

if [[ $metadata_engine == sqlite ]]; then
  integrity=$("${compose[@]}" exec -T "$daemon_service" sqlite3 /state/metadata.db 'PRAGMA integrity_check;')
  if [[ $integrity != ok ]]; then
    echo "SQLite integrity check failed: $integrity" >&2
    exit 1
  fi
else
  persisted_count=$(postgres_psql --tuples-only --no-align \
    --command 'SELECT COUNT(*) FROM captured.traces;')
  expected_count=2
  if [[ $artifact_engine == s3 ]]; then
    expected_count=3
  fi
  if [[ $profile == full ]]; then
    expected_count=5
    if [[ $artifact_engine == s3 ]]; then
      expected_count=6
    fi
  fi
  if [[ $persisted_count != "$expected_count" ]]; then
    echo "PostgreSQL trace count changed across daemon recreation: $persisted_count" >&2
    exit 1
  fi
  migration_count=$(postgres_psql --tuples-only --no-align \
    --command 'SELECT COUNT(*) FROM captured.schema_migrations;')
  if [[ $migration_count != "$expected_postgres_migration_count" ]]; then
    echo "PostgreSQL migration journal changed unexpectedly: $migration_count (expected $expected_postgres_migration_count)" >&2
    exit 1
  fi
fi

echo "running bounded report-only artifact reconciliation while the daemon is stopped"
"${compose[@]}" stop "$daemon_service"
if [[ $artifact_engine == s3 ]]; then
  orphan_target=$(artifact_target trc-e2e-unreferenced capture_checkpoint)
  printf 'young unreferenced reconciliation fixture' | \
    object_store_aws s3 cp - "s3://$s3_bucket/$orphan_target" >/dev/null
  young_reconciliation=$("${compose[@]}" run --rm --no-deps -T "$daemon_service" \
    reconcile-artifacts --config "$daemon_config")
  assert_json_while_daemon_stopped "$young_reconciliation" '
    .s3_scanned_objects >= 2 and .s3_unreferenced_candidates == 0
  '
fi
reconciliation=$("${compose[@]}" run --rm --no-deps -T "$daemon_service" \
  reconcile-artifacts --config "$daemon_config" --orphan-grace-days 0)
if [[ $artifact_engine == s3 ]]; then
  assert_json_while_daemon_stopped "$reconciliation" '
    .status == "findings" and
    .referenced_artifacts >= 1 and
    .corrupt_references == 1 and
    .missing_references == 0 and
    .s3_scanned_objects >= 2 and
    .s3_unreferenced_candidates == 1
  '
else
  assert_json_while_daemon_stopped "$reconciliation" '
    .status == "clean" and
    .referenced_artifacts >= 1 and
    .verified_artifacts == .referenced_artifacts and
    .s3_scanned_objects == 0
  '
fi

echo "daemon persistence E2E passed: $metadata_engine $artifact_engine 1 $profile"
