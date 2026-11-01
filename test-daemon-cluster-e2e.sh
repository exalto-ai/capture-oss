#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || ( $1 != smoke && $1 != full ) ]]; then
  echo "usage: $0 {smoke|full}" >&2
  exit 2
fi
profile=$1
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository_dir=$script_dir
project_name="captured-cluster-e2e-$$"
compose=(docker compose --project-name "$project_name" --file "$repository_dir/compose.daemon-e2e.yml")

cleanup() {
  result=$?
  trap - EXIT
  set +e
  if [[ $result -ne 0 ]]; then
    "${compose[@]}" ps >&2
    "${compose[@]}" logs --no-color postgres server-migrator object-store setup provider notary daemon-a daemon-b test-load-balancer >&2
  fi
  if [[ ${DAEMON_E2E_KEEP:-0} != 1 ]]; then
    "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1
  fi
  exit "$result"
}
trap cleanup EXIT

wait_healthy() {
  local service=$1
  local health=""
  for _ in $(seq 1 120); do
    local container
    container=$("${compose[@]}" ps --quiet "$service")
    health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container" 2>/dev/null || true)
    [[ $health == healthy ]] && return 0
    sleep 1
  done
  echo "$service did not become healthy (last state: $health)" >&2
  return 1
}

wait_ready() {
  local service=$1
  for _ in $(seq 1 60); do
    if "${compose[@]}" exec -T "$service" curl --fail --silent --max-time 3 http://127.0.0.1:8788/readyz >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "$service did not recover readiness" >&2
  return 1
}

# The load balancer health-checks its proxy (8787) and admin (8788) pools
# separately and never retries, so both must have a ready backend before the
# next request. The proxy's own /healthz never reaches the provider.
wait_load_balancer_ready() {
  for _ in $(seq 1 60); do
    if "${compose[@]}" exec -T daemon-a curl --fail --silent --max-time 3 \
        http://test-load-balancer:8788/readyz >/dev/null 2>&1 \
      && "${compose[@]}" exec -T daemon-a curl --fail --silent --max-time 3 \
        http://test-load-balancer:8787/healthz >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "test load balancer did not recover a ready backend" >&2
  return 1
}

wait_not_ready() {
  local service=$1
  for _ in $(seq 1 20); do
    [[ $(http_code "$service" /healthz) == 200 ]] || {
      echo "$service lost local liveness during a dependency outage" >&2
      return 1
    }
    [[ $(http_code "$service" /readyz) == 503 ]] && return 0
    sleep 0.25
  done
  echo "$service did not withdraw cached readiness" >&2
  return 1
}

http_code() {
  local service=$1
  local path=$2
  "${compose[@]}" exec -T "$service" curl --silent --max-time 3 --output /dev/null --write-out '%{http_code}' "http://127.0.0.1:8788$path" || true
}

psql_value() {
  "${compose[@]}" exec -T postgres psql -U daemon_e2e -d daemon_e2e -Atc "$1"
}

wait_replica_slot_released() {
  local instance_id=$1
  local live=""
  for _ in $(seq 1 60); do
    live=$(psql_value "select count(*) from captured.replicas where instance_id='$instance_id' and lease_expires_at > clock_timestamp()")
    [[ $live == 0 ]] && return 0
    sleep 1
  done
  echo "replica slot $instance_id remained live in PostgreSQL" >&2
  return 1
}

start_existing_service() {
  local service=$1
  local container
  container=$("${compose[@]}" ps --all --quiet "$service")
  [[ -n $container ]] || { echo "no existing container for $service" >&2; return 1; }
  docker start "$container" >/dev/null
}

if [[ ${DAEMON_E2E_SKIP_BUILD:-0} != 1 ]]; then
  "${compose[@]}" build daemon-a
fi
if [[ $profile == full ]]; then
  # Hold the artifact commit briefly so the event-page high-water is captured before
  # the terminal event, regardless of which replica claims the operation.
  export DAEMON_E2E_SERVER_NOTARIZATION_PAUSE_MS=3000
fi
"${compose[@]}" up --detach test-load-balancer

for service in daemon-a daemon-b test-load-balancer; do
  wait_healthy "$service"
done
wait_load_balancer_ready

basic=cluster-admin:cluster-password
admin_json() {
  local service=$1
  local path=$2
  shift 2
  "${compose[@]}" exec -T "$service" curl --fail --silent --show-error --user "$basic" "$@" "http://127.0.0.1:8788$path"
}
load_balancer_admin_json() {
  local path=$1
  shift
  "${compose[@]}" exec -T daemon-a curl --fail --silent --show-error --user "$basic" "$@" "http://test-load-balancer:8788$path"
}
session_request() {
  local service=$1
  local path=$2
  shift 2
  "${compose[@]}" exec -T "$service" curl --fail --silent --show-error \
    --header 'x-notary-request: dashboard' --header "cookie: $cookie" \
    "$@" "http://127.0.0.1:8788$path"
}
load_balancer_session_request() {
  local path=$1
  shift
  "${compose[@]}" exec -T daemon-a curl --fail --silent --show-error \
    --header 'x-notary-request: dashboard' --header "cookie: $cookie" \
    "$@" "http://test-load-balancer:8788$path"
}

status_a=$(admin_json daemon-a /v1/status)
status_b=$(admin_json daemon-b /v1/status)
printf '%s' "$status_a" | "${compose[@]}" exec -T daemon-a jq -e '.runtime_profile == "cluster" and .instance_id == "daemon-a" and .lifecycle == "ready" and .metadata_backend == "postgres" and .artifact_backend == "s3"' >/dev/null
printf '%s' "$status_b" | "${compose[@]}" exec -T daemon-b jq -e '.runtime_profile == "cluster" and .instance_id == "daemon-b" and .lifecycle == "ready"' >/dev/null
replicas=$(psql_value 'select count(*) from captured.replicas where lease_expires_at > clock_timestamp()')
[[ $replicas == 2 ]] || { echo "expected two live replicas, got $replicas" >&2; exit 1; }

# A raw dashboard token is returned only to this client. PostgreSQL stores the
# domain-separated 32-byte digest and replica B validates/revokes it.
headers=$("${compose[@]}" exec -T daemon-a curl --silent --show-error --dump-header - --output /dev/null --user "$basic" --request POST http://test-load-balancer:8788/v1/session)
cookie=$(printf '%s\n' "$headers" | awk -F': ' 'tolower($1)=="set-cookie" {sub(/;.*/,"",$2); gsub("\r","",$2); print $2}')
[[ $cookie == notary_admin_session=* ]] || { echo "cluster session cookie missing" >&2; exit 1; }
session_instances=""
for _ in $(seq 1 10); do
  session_status=$(load_balancer_session_request /v1/status)
  session_instance=$(printf '%s' "$session_status" | "${compose[@]}" exec -T daemon-a jq -er '.instance_id')
  session_instances=$(printf '%s\n%s\n' "$session_instances" "$session_instance" | sed '/^$/d' | sort -u | paste -sd, -)
  [[ $session_instances == daemon-a,daemon-b ]] && break
done
[[ $session_instances == daemon-a,daemon-b ]] || { echo "test load balancer did not validate one shared session on both replicas: $session_instances" >&2; exit 1; }
raw_token=${cookie#*=}
raw_in_database=$(psql_value "select count(*) from captured.sessions where encode(token_hash,'hex')='$raw_token'")
[[ $raw_in_database == 0 ]] || { echo "raw dashboard bearer token reached PostgreSQL" >&2; exit 1; }
load_balancer_session_request /v1/session --request DELETE >/dev/null
if session_request daemon-a /v1/status >/dev/null 2>&1; then
  echo "revoked cluster session remained valid" >&2
  exit 1
fi

if [[ $profile == full ]]; then
  echo "checking fail-closed server startup profiles"
  if "${compose[@]}" run --rm --no-deps -e CAPTURED_PLATFORM_API_KEY= daemon-a \
      --config /state/config-cluster-a.toml >/dev/null 2>&1; then
    echo "server daemon started without an injected API key" >&2
    exit 1
  fi
  if "${compose[@]}" run --rm --no-deps \
      -e CAPTURED_DESKTOP_CONTROL_STDIN=1 daemon-a \
      --config /state/config-cluster-a.toml </dev/null >/dev/null 2>&1; then
    echo "server daemon accepted desktop process control" >&2
    exit 1
  fi
  if "${compose[@]}" run --rm --no-deps --entrypoint /bin/sh daemon-a -ec \
      'dd if=/dev/zero of=/tmp/wrong-vault.key bs=32 count=1 status=none; chmod 600 /tmp/wrong-vault.key; export CAPTURED_CLUSTER_VAULT_KEY_FILE=/tmp/wrong-vault.key; exec captured --config /state/config-cluster-a.toml' \
      >/dev/null 2>&1; then
    echo "server daemon accepted incompatible vault material" >&2
    exit 1
  fi

  echo "checking dependency-specific liveness, readiness, and recovery"
  "${compose[@]}" stop object-store >/dev/null
  wait_not_ready daemon-a
  object_store_status=$("${compose[@]}" exec -T daemon-a curl --silent --max-time 3 --user "$basic" --output /dev/null --write-out '%{http_code}' http://127.0.0.1:8788/v1/status || true)
  [[ $object_store_status == 503 ]] || { echo "object store loss did not fail status" >&2; exit 1; }
  "${compose[@]}" start object-store >/dev/null
  wait_healthy object-store
  wait_ready daemon-a
  wait_ready daemon-b
  wait_load_balancer_ready

  "${compose[@]}" stop postgres >/dev/null
  wait_not_ready daemon-a
  "${compose[@]}" start postgres >/dev/null
  wait_healthy postgres
  wait_ready daemon-a
  wait_ready daemon-b
  wait_load_balancer_ready

  provider_requests_before=$("${compose[@]}" logs --no-color provider | grep -c 'POST /v1/chat/completions' || true)
  "${compose[@]}" exec -T daemon-a curl --fail --silent --show-error \
    --dump-header /tmp/server-capture.headers \
    --header 'authorization: Bearer offline-server-secret' \
    --header 'content-type: application/json' \
    --data '{"model":"fixture-model","messages":[{"role":"user","content":"server cross replica prompt"}]}' \
    http://test-load-balancer:8787/openai/v1/chat/completions >/tmp/server-provider-response.json
  provider_requests_after=$("${compose[@]}" logs --no-color provider | grep -c 'POST /v1/chat/completions' || true)
  [[ $((provider_requests_after - provider_requests_before)) == 1 ]] || { echo "test load balancer replayed one provider request" >&2; exit 1; }
  trace_id=$("${compose[@]}" exec -T daemon-a awk 'tolower($1)=="x-notary-trace-id:" {gsub("\r","",$2); print $2}' /tmp/server-capture.headers)
  [[ $trace_id == trc-* ]] || { echo "server trace ID missing" >&2; exit 1; }
  trace_b=$(admin_json daemon-b "/v1/traces/$trace_id")
  printf '%s' "$trace_b" | "${compose[@]}" exec -T daemon-b jq -e --arg id "$trace_id" \
    '.trace_id==$id and .state=="captured" and .status==null and any(.artifacts[]; .kind=="capture_checkpoint")' >/dev/null

  echo "queueing notarization through the test load balancer"
  queued=$(load_balancer_admin_json "/v1/traces/$trace_id/notarizations" --request POST)
  operation_id=$(printf '%s' "$queued" | "${compose[@]}" exec -T daemon-b jq -er '.operation.operation_id')
  echo "checking the cross-replica event snapshot"
  activity_page_before=$(admin_json daemon-a "/v1/activity?limit=1")
  activity_high_water=$(printf '%s' "$activity_page_before" | "${compose[@]}" exec -T daemon-a jq -er '.high_water_cursor')
  echo "waiting for cross-replica notarization"
  for _ in $(seq 1 120); do
    operation=$(admin_json daemon-a "/v1/operations/$operation_id")
    state=$(printf '%s' "$operation" | "${compose[@]}" exec -T daemon-a jq -r '.state')
    [[ $state == succeeded ]] && break
    [[ $state == failed || $state == interrupted ]] && { printf '%s\n' "$operation" >&2; exit 1; }
    sleep 1
  done
  [[ $state == succeeded ]] || { echo "server notarization timed out" >&2; exit 1; }
  load_balancer_admin_json "/v1/traces/$trace_id/package.llmtrace" --output /tmp/server.llmtrace
  package_verification=$(admin_json daemon-a /v1/verify \
    --request POST \
    --header 'content-type: application/vnd.exalto.notary.trace-package+zip' \
    --header 'x-notary-trusted-notary-key: 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798' \
    --data-binary @/tmp/server.llmtrace)
  printf '%s' "$package_verification" | "${compose[@]}" exec -T daemon-a jq -e --arg id "$trace_id" \
    '.trace_id==$id and .outcome=="passed" and .trust_source=="explicit_key"' >/dev/null
  owner_rows=$("${compose[@]}" exec -T postgres psql -U daemon_e2e -d daemon_e2e -Atc "select count(*) from captured.operations where operation_id='$operation_id' and owner_instance_id in ('daemon-a','daemon-b') and claim_fence is not null")
  [[ $owner_rows == 1 ]] || { echo "notarization did not retain one fenced owner" >&2; exit 1; }

  cross_replica_activity=$(admin_json daemon-b "/v1/activity?limit=200&after=$activity_high_water")
  printf '%s' "$cross_replica_activity" | "${compose[@]}" exec -T daemon-b jq -e --arg operation "$operation_id" '
    ([.items[] | select(.operation_id==$operation)] | length) >= 1 and
    ([.items[].event_id] | unique | length) == ([.items[].event_id] | length)
  ' >/dev/null

  "${compose[@]}" stop daemon-b >/dev/null
  sleep 3
  "${compose[@]}" exec -T daemon-a curl --fail --silent http://127.0.0.1:8788/readyz >/dev/null
  healthy_capture=$(psql_value "select capture_status from captured.traces where trace_id='$trace_id'")
  [[ $healthy_capture == captured ]] || { echo "peer stop corrupted completed capture" >&2; exit 1; }

  echo "forcing claim expiry and proving stale artifact/terminal fencing"
  export DAEMON_E2E_SERVER_NOTARIZATION_PAUSE_MS=30000
  "${compose[@]}" rm --stop --force daemon-a >/dev/null
  wait_replica_slot_released daemon-a
  "${compose[@]}" up --detach --no-deps daemon-a >/dev/null
  wait_healthy daemon-a
  "${compose[@]}" exec -T daemon-a curl --fail --silent --show-error \
    --dump-header /tmp/stale-capture.headers \
    --header 'authorization: Bearer offline-server-secret' \
    --header 'content-type: application/json' \
    --data '{"model":"fixture-model","messages":[{"role":"user","content":"server stale owner prompt"}]}' \
    http://127.0.0.1:8787/openai/v1/chat/completions >/dev/null
  stale_trace_id=$("${compose[@]}" exec -T daemon-a awk 'tolower($1)=="x-notary-trace-id:" {gsub("\r","",$2); print $2}' /tmp/stale-capture.headers)
  stale_queued=$(admin_json daemon-a "/v1/traces/$stale_trace_id/notarizations" --request POST)
  stale_operation_id=$(printf '%s' "$stale_queued" | "${compose[@]}" exec -T daemon-a jq -er '.operation.operation_id')
  stale_object_path="s3://captured-e2e/captured/trace-packages/$stale_trace_id/"
  stale_object_ready=0
  for _ in $(seq 1 120); do
    stale_objects=$("${compose[@]}" run --rm --no-deps -T object-store-client s3 ls --recursive "$stale_object_path" 2>/dev/null || true)
    if [[ -n $stale_objects ]]; then
      stale_object_ready=1
      break
    fi
    sleep 1
  done
  [[ $stale_object_ready == 1 ]] || { echo "stale-owner notarization never committed its claim-scoped object" >&2; exit 1; }
  daemon_a_container=$("${compose[@]}" ps --quiet daemon-a)
  docker pause "$daemon_a_container" >/dev/null
  unset DAEMON_E2E_SERVER_NOTARIZATION_PAUSE_MS
  wait_replica_slot_released daemon-b
  start_existing_service daemon-b
  wait_healthy daemon-b
  stale_state=""
  for _ in $(seq 1 30); do
    stale_operation=$(admin_json daemon-b "/v1/operations/$stale_operation_id")
    stale_state=$(printf '%s' "$stale_operation" | "${compose[@]}" exec -T daemon-b jq -r '.state')
    [[ $stale_state == interrupted ]] && break
    sleep 1
  done
  [[ $stale_state == interrupted ]] || { echo "expired notarization was not interrupted" >&2; exit 1; }
  interrupted_events=$(psql_value "select count(*) from captured.events where operation_id='$stale_operation_id' and event_type='notarization_interrupted'")
  [[ $interrupted_events == 1 ]] || { echo "expired notarization emitted $interrupted_events interruption events" >&2; exit 1; }
  stale_retry=$(admin_json daemon-b "/v1/traces/$stale_trace_id/notarizations" --request POST)
  printf '%s' "$stale_retry" | "${compose[@]}" exec -T daemon-b jq -e --arg operation "$stale_operation_id" \
    '.deduplicated==false and .operation.operation_id==$operation and .operation.state=="queued"' >/dev/null
  for _ in $(seq 1 120); do
    stale_operation=$(admin_json daemon-b "/v1/operations/$stale_operation_id")
    stale_state=$(printf '%s' "$stale_operation" | "${compose[@]}" exec -T daemon-b jq -r '.state')
    [[ $stale_state == succeeded ]] && break
    [[ $stale_state == failed ]] && { printf '%s\n' "$stale_operation" >&2; exit 1; }
    sleep 1
  done
  [[ $stale_state == succeeded ]] || { echo "retried notarization did not complete on peer" >&2; exit 1; }
  winner_locator=$(psql_value "select locator from captured.artifacts where trace_id='$stale_trace_id' and kind='trace_package'")
  docker unpause "$daemon_a_container" >/dev/null
  sleep 5
  winner_locator_after_stale=$(psql_value "select locator from captured.artifacts where trace_id='$stale_trace_id' and kind='trace_package'")
  [[ $winner_locator_after_stale == "$winner_locator" ]] || { echo "stale worker replaced the winning artifact pointer" >&2; exit 1; }
  stale_operation=$(admin_json daemon-b "/v1/operations/$stale_operation_id")
  printf '%s' "$stale_operation" | "${compose[@]}" exec -T daemon-b jq -e '
    .state=="succeeded" and .attempt==2 and
    ([.attempt_history[] | select(.state=="interrupted")] | length)==1 and
    ([.attempt_history[] | select(.state=="succeeded")] | length)==1
  ' >/dev/null
  completed_events=$(psql_value "select count(*) from captured.events where operation_id='$stale_operation_id' and event_type='notarization_completed'")
  [[ $completed_events == 1 ]] || { echo "stale retry emitted $completed_events completion events" >&2; exit 1; }
  stale_objects=$("${compose[@]}" run --rm --no-deps -T object-store-client s3 ls --recursive "$stale_object_path" 2>/dev/null || true)
  stale_object_count=$(printf '%s\n' "$stale_objects" | sed '/^$/d' | wc -l | tr -d ' ')
  [[ $stale_object_count == 2 ]] || { echo "expected isolated loser and winner objects, got $stale_object_count" >&2; exit 1; }

  echo "checking graceful drain of a running notarization"
  "${compose[@]}" rm --stop --force daemon-a >/dev/null 2>&1 || true
  wait_replica_slot_released daemon-a
  "${compose[@]}" stop daemon-b >/dev/null
  export DAEMON_E2E_SERVER_NOTARIZATION_PAUSE_MS=5000
  "${compose[@]}" up --detach --no-deps daemon-a >/dev/null
  wait_healthy daemon-a
  "${compose[@]}" exec -T daemon-a curl --fail --silent --show-error \
    --dump-header /tmp/drain-notarization.headers \
    --header 'authorization: Bearer offline-server-secret' \
    --header 'content-type: application/json' \
    --data '{"model":"fixture-model","messages":[{"role":"user","content":"server running drain prompt"}]}' \
    http://127.0.0.1:8787/openai/v1/chat/completions >/dev/null
  drain_notarization_trace=$("${compose[@]}" exec -T daemon-a awk 'tolower($1)=="x-notary-trace-id:" {gsub("\r","",$2); print $2}' /tmp/drain-notarization.headers)
  drain_queued=$(admin_json daemon-a "/v1/traces/$drain_notarization_trace/notarizations" --request POST)
  drain_operation_id=$(printf '%s' "$drain_queued" | "${compose[@]}" exec -T daemon-a jq -er '.operation.operation_id')
  drain_object_path="s3://captured-e2e/captured/trace-packages/$drain_notarization_trace/"
  for _ in $(seq 1 120); do
    drain_objects=$("${compose[@]}" run --rm --no-deps -T object-store-client s3 ls --recursive "$drain_object_path" 2>/dev/null || true)
    [[ -n $drain_objects ]] && break
    sleep 1
  done
  [[ -n ${drain_objects:-} ]] || { echo "running drain notarization did not commit an artifact" >&2; exit 1; }
  daemon_a_container=$("${compose[@]}" ps --quiet daemon-a)
  docker kill --signal TERM "$daemon_a_container" >/dev/null
  drain_with_liveness=0
  for _ in $(seq 1 20); do
    if [[ $(http_code daemon-a /healthz) == 200 && $(http_code daemon-a /readyz) == 503 ]]; then
      drain_with_liveness=1
      break
    fi
    sleep 0.25
  done
  [[ $drain_with_liveness == 1 ]] || { echo "running drain did not withdraw readiness before liveness" >&2; exit 1; }
  for _ in $(seq 1 60); do
    running=$(docker inspect --format '{{.State.Running}}' "$daemon_a_container" 2>/dev/null || true)
    [[ $running != true ]] && break
    sleep 1
  done
  drain_terminal=$(psql_value "select state from captured.operations where operation_id='$drain_operation_id'")
  [[ $drain_terminal == succeeded ]] || { echo "running notarization did not finish during drain: $drain_terminal" >&2; exit 1; }

  echo "checking rolling drain with an admitted stream and queued peer work"
  unset DAEMON_E2E_SERVER_NOTARIZATION_PAUSE_MS
  "${compose[@]}" rm --force daemon-a >/dev/null 2>&1 || true
  wait_replica_slot_released daemon-a
  "${compose[@]}" up --detach --no-deps daemon-a >/dev/null
  wait_healthy daemon-a
  "${compose[@]}" exec -T daemon-a curl --fail --silent --show-error \
    --dump-header /tmp/queued-drain.headers \
    --header 'authorization: Bearer offline-server-secret' \
    --header 'content-type: application/json' \
    --data '{"model":"fixture-model","messages":[{"role":"user","content":"server queued drain prompt"}]}' \
    http://127.0.0.1:8787/openai/v1/chat/completions >/dev/null
  queued_drain_trace=$("${compose[@]}" exec -T daemon-a awk 'tolower($1)=="x-notary-trace-id:" {gsub("\r","",$2); print $2}' /tmp/queued-drain.headers)
  slow_output=$(mktemp)
  "${compose[@]}" exec -T daemon-a curl --fail --silent --show-error \
    --dump-header /tmp/rolling-stream.headers \
    --header 'authorization: Bearer offline-server-secret' \
    --header 'content-type: application/json' \
    --data '{"model":"fixture-model","stream":true,"messages":[{"role":"user","content":"server rolling drain stream"}]}' \
    http://127.0.0.1:8787/openai/v1/chat/completions >"$slow_output" 2>&1 &
  slow_pid=$!
  rolling_trace_id=""
  for _ in $(seq 1 40); do
    rolling_trace_id=$("${compose[@]}" exec -T daemon-a awk 'tolower($1)=="x-notary-trace-id:" {gsub("\r","",$2); print $2}' /tmp/rolling-stream.headers 2>/dev/null || true)
    [[ $rolling_trace_id == trc-* ]] && break
    sleep 0.25
  done
  [[ $rolling_trace_id == trc-* ]] || { echo "rolling stream never became admitted" >&2; exit 1; }
  daemon_a_container=$("${compose[@]}" ps --quiet daemon-a)
  docker kill --signal TERM "$daemon_a_container" >/dev/null
  rolling_with_liveness=0
  for _ in $(seq 1 20); do
    if [[ $(http_code daemon-a /healthz) == 200 && $(http_code daemon-a /readyz) == 503 ]]; then
      rolling_with_liveness=1
      break
    fi
    sleep 0.25
  done
  [[ $rolling_with_liveness == 1 ]] || { echo "rolling stream drain did not withdraw readiness first" >&2; exit 1; }
  queued_during_drain=$(admin_json daemon-a "/v1/traces/$queued_drain_trace/notarizations" --request POST)
  queued_during_drain_operation=$(printf '%s' "$queued_during_drain" | "${compose[@]}" exec -T daemon-a jq -er '.operation.operation_id')
  wait "$slow_pid" || { echo "admitted streaming capture did not finish during drain" >&2; cat "$slow_output" >&2; exit 1; }
  rm -f "$slow_output"
  for _ in $(seq 1 60); do
    running=$(docker inspect --format '{{.State.Running}}' "$daemon_a_container" 2>/dev/null || true)
    [[ $running != true ]] && break
    sleep 1
  done
  wait_replica_slot_released daemon-b
  start_existing_service daemon-b
  wait_healthy daemon-b
  rolling_trace=$(admin_json daemon-b "/v1/traces/$rolling_trace_id")
  printf '%s' "$rolling_trace" | "${compose[@]}" exec -T daemon-b jq -e \
    '.streaming==true and .state=="captured" and .status==null' >/dev/null
  queued_peer_state=""
  for _ in $(seq 1 120); do
    queued_peer_operation=$(admin_json daemon-b "/v1/operations/$queued_during_drain_operation")
    queued_peer_state=$(printf '%s' "$queued_peer_operation" | "${compose[@]}" exec -T daemon-b jq -r '.state')
    [[ $queued_peer_state == succeeded ]] && break
    [[ $queued_peer_state == failed ]] && { printf '%s\n' "$queued_peer_operation" >&2; exit 1; }
    sleep 1
  done
  [[ $queued_peer_state == succeeded ]] || { echo "peer did not claim queued work after rolling drain" >&2; exit 1; }
  "${compose[@]}" rm --force daemon-a >/dev/null 2>&1 || true
  wait_replica_slot_released daemon-a
  "${compose[@]}" up --detach --no-deps daemon-a >/dev/null
  wait_healthy daemon-a
  wait_healthy test-load-balancer
fi

echo "daemon cluster E2E passed: postgres s3 2 $profile"
