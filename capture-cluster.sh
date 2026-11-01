#!/usr/bin/env bash
set -euo pipefail

runtime_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
state_dir=${CAPTURED_CLUSTER_STATE_DIR:-"$runtime_dir/.captured-cluster"}
compose_file="$runtime_dir/compose.cluster.yml"
env_file="$state_dir/.env"

usage() {
  cat <<'EOF'
Usage:
  ./capture-cluster.sh init <proxy-domain> <admin-domain> <notary-endpoint> <notary-public-key>
  ./capture-cluster.sh up
  ./capture-cluster.sh status
  ./capture-cluster.sh logs
  ./capture-cluster.sh down

Set CAPTURED_CLUSTER_STATE_DIR to keep generated configuration elsewhere.
EOF
}

compose() {
  test -f "$env_file" || {
    echo "Cluster state is not initialized. Run: $0 init <proxy-domain> <admin-domain> <notary-endpoint> <notary-public-key>" >&2
    exit 1
  }
  docker compose --env-file "$env_file" -f "$compose_file" "$@"
}

valid_domain() {
  [[ $1 =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] && [[ $1 == *.* ]]
}

init() {
  local proxy_domain=${1:-}
  local admin_domain=${2:-}
  local notary_endpoint=${3:-}
  local notary_public_key=${4:-}
  if [[ $EUID -eq 0 ]]; then
    echo "Run cluster setup as an unprivileged account that is allowed to use Docker, not with sudo." >&2
    exit 1
  fi
  if ! valid_domain "$proxy_domain" || ! valid_domain "$admin_domain" || [[ $proxy_domain == "$admin_domain" ]]; then
    echo "Provide two different DNS hostnames, for example proxy.example.com admin.example.com." >&2
    exit 1
  fi
  if [[ ! $notary_endpoint =~ ^tls://[A-Za-z0-9.-]+:[0-9]{1,5}$ ]]; then
    echo "Provide an explicit TLS notary endpoint such as tls://notary.example.com:7047." >&2
    exit 1
  fi
  if [[ ! $notary_public_key =~ ^(02|03)[0-9a-fA-F]{64}$ ]]; then
    echo "Provide the notary's compressed SEC1 public key as 66 hexadecimal characters." >&2
    exit 1
  fi
  if [[ -e $state_dir ]]; then
    echo "Cluster state already exists at $state_dir; nothing was overwritten." >&2
    exit 1
  fi
  command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }
  umask 077
  mkdir -p "$state_dir/secrets"

  local admin_password postgres_password s3_secret
  admin_password=$(openssl rand -hex 18)
  postgres_password=$(openssl rand -hex 24)
  s3_secret=$(openssl rand -hex 24)
  printf '%s' "$admin_password" > "$state_dir/secrets/admin-password"
  printf '%s' "$postgres_password" > "$state_dir/secrets/postgres-password"
  printf '%s' "postgresql://notary:${postgres_password}@postgres:5432/notary" > "$state_dir/secrets/postgres-url"
  printf '%s' 'notary' > "$state_dir/secrets/s3-access-key"
  printf '%s' "$s3_secret" > "$state_dir/secrets/s3-secret-key"
  openssl rand 32 > "$state_dir/secrets/cluster-vault.key"

  sed -e "s/__PROXY_DOMAIN__/$proxy_domain/g" \
      -e "s/__ADMIN_DOMAIN__/$admin_domain/g" \
      -e "s|__NOTARY_ENDPOINT__|$notary_endpoint|g" \
      -e "s/__NOTARY_PUBLIC_KEY__/$notary_public_key/g" \
      "$runtime_dir/deploy-cluster/config.toml.template" > "$state_dir/config.toml"
  cat > "$env_file" <<EOF
CLUSTER_STATE_DIR=$state_dir
CLUSTER_UID=$(id -u)
CLUSTER_GID=$(id -g)
CLUSTER_REPLICAS=2
CLUSTER_NETWORK_NAME=capture-cluster
EOF
  chmod 600 "$env_file" "$state_dir/config.toml" "$state_dir"/secrets/*

  echo "Initialized Notary cluster state at $state_dir"
  echo "Public admin origin: https://$admin_domain"
  echo "Username: admin"
  echo "Generated password: $admin_password"
  echo "Save that password now, then run: $0 up"
  echo "This is a reference Compose deployment; your platform owns ingress and TLS."
}

case ${1:-} in
  init)
    shift
    init "$@"
    ;;
  up)
    compose up -d --build
    echo "Started the replicated daemon service."
    echo "Docker-network endpoints: daemon:8787 (provider proxy), daemon:8788 (admin/readiness)"
    echo "The reference file intentionally leaves ingress, TLS, and public exposure to your platform."
    ;;
  status)
    compose ps
    ;;
  logs)
    compose logs --tail=200 -f daemon
    ;;
  down)
    compose down
    ;;
  *)
    usage
    exit 2
    ;;
esac
