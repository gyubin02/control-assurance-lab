#!/usr/bin/env bash
#
# Opt-in conformance run against an actual, temporary Elasticsearch 9.4.2 node.
# No Docker daemon or pre-existing Elasticsearch service is assumed.

set -Eeuo pipefail
umask 077

readonly ES_VERSION="9.4.2"
readonly ES_ARCHIVE="elasticsearch-${ES_VERSION}-linux-x86_64.tar.gz"
readonly ES_SHA512="b57636655b3807b663a6d87e74609c47ed78e6c8ba31848f0650e5fdc746b68e205005046bac6875e32563fdc71a60717f769714dfb490a0bdc85f24d556b6be"
readonly ES_DOWNLOAD_URL="https://artifacts.elastic.co/downloads/elasticsearch/${ES_ARCHIVE}"
readonly ALERT_ALIAS=".alerts-security.alerts-default"
readonly BACKING_INDEX=".internal.alerts-security.alerts-default-000001"

if [[ ${EUID} -eq 0 ]]; then
  printf '%s\n' "refusing to run Elasticsearch as root" >&2
  exit 2
fi

for command in curl find install mktemp python3 tar timeout; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    printf 'required command is unavailable: %s\n' "${command}" >&2
    exit 2
  fi
done
if ! command -v node >/dev/null 2>&1; then
  printf '%s\n' "Node.js is required for the independent verifier" >&2
  exit 2
fi
if ! node -e '
const [major, minor] = process.versions.node.split(".").map(Number);
if (major < 20 || (major === 20 && minor < 11)) process.exit(1);
'; then
  printf '%s\n' "Node.js 20.11 or newer is required" >&2
  exit 2
fi

repository_root="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd -- "${repository_root}"

cache_root="${XDG_CACHE_HOME:-${HOME}/.cache}/control-assurance-elastic"
mkdir -p -- "${cache_root}"
chmod 0700 -- "${cache_root}"
temp_root="$(python3 - "${TMPDIR:-/tmp}" <<'PY'
import os
import sys

print(os.path.realpath(sys.argv[1]))
PY
)"
mkdir -p -- "${temp_root}"
run_dir="$(mktemp -d -p "${temp_root}" control-assurance-elastic.XXXXXXXX)"
chmod 0700 -- "${run_dir}"

es_pid=""
api_key_created=0
cleanup_started=0

cleanup() {
  local status=$?
  if [[ ${cleanup_started} -eq 1 ]]; then
    return
  fi
  cleanup_started=1
  trap - EXIT INT TERM HUP

  if [[ ${api_key_created} -eq 1 && -f "${run_dir}/api-key-id.json" ]]; then
    curl \
      --config "${run_dir}/bootstrap-curl.conf" \
      --request DELETE \
      --header "Content-Type: application/json" \
      --data-binary "@${run_dir}/api-key-id.json" \
      --output /dev/null \
      --url "http://127.0.0.1:${http_port}/_security/api_key" \
      >/dev/null 2>&1 || true
  fi

  if [[ -n ${es_pid} ]] && kill -0 "${es_pid}" >/dev/null 2>&1; then
    kill -TERM "${es_pid}" >/dev/null 2>&1 || true
    for _ in {1..20}; do
      if ! kill -0 "${es_pid}" >/dev/null 2>&1; then
        break
      fi
      sleep 0.5
    done
    if kill -0 "${es_pid}" >/dev/null 2>&1; then
      kill -KILL "${es_pid}" >/dev/null 2>&1 || true
    fi
    wait "${es_pid}" >/dev/null 2>&1 || true
  fi

  case "${run_dir}" in
    "${temp_root}"/control-assurance-elastic.*)
      chmod -R u+rwX -- "${run_dir}" >/dev/null 2>&1 || true
      rm -rf -- "${run_dir}"
      ;;
    *)
      printf '%s\n' "refusing to remove an unexpected work directory" >&2
      status=1
      ;;
  esac
  exit "${status}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

resolve_elasticsearch_home() {
  local configured_home="${CONTROL_ASSURANCE_ELASTIC_HOME:-}"
  local cached_home="${cache_root}/elasticsearch-${ES_VERSION}"
  local configured_archive="${CONTROL_ASSURANCE_ELASTIC_ARCHIVE:-}"
  local cached_archive="${cache_root}/${ES_ARCHIVE}"
  local archive=""

  if [[ -n ${configured_home} ]]; then
    if [[ ! -x "${configured_home}/bin/elasticsearch" ]]; then
      printf '%s\n' "CONTROL_ASSURANCE_ELASTIC_HOME is not an Elasticsearch distribution" >&2
      return 1
    fi
    printf '%s\n' "$(CDPATH= cd -- "${configured_home}" && pwd -P)"
    return
  fi
  if [[ -x "${cached_home}/bin/elasticsearch" ]]; then
    printf '%s\n' "${cached_home}"
    return
  fi
  if [[ -n ${configured_archive} ]]; then
    archive="${configured_archive}"
  elif [[ -f ${cached_archive} ]]; then
    archive="${cached_archive}"
  elif [[ ${CONTROL_ASSURANCE_ELASTIC_DOWNLOAD:-0} == "1" ]]; then
    printf 'downloading official Elasticsearch %s archive\n' "${ES_VERSION}" >&2
    local partial="${run_dir}/${ES_ARCHIVE}.download"
    curl \
      --fail \
      --silent \
      --show-error \
      --location \
      --proto '=https' \
      --proto-redir '=https' \
      --tlsv1.2 \
      --connect-timeout 10 \
      --max-time 900 \
      --output "${partial}" \
      "${ES_DOWNLOAD_URL}"
    archive="${partial}"
  else
    printf '%s\n' \
      "Elasticsearch 9.4.2 was not found; set CONTROL_ASSURANCE_ELASTIC_HOME," \
      "set CONTROL_ASSURANCE_ELASTIC_ARCHIVE, or opt in with" \
      "CONTROL_ASSURANCE_ELASTIC_DOWNLOAD=1." >&2
    return 1
  fi

  if [[ ! -f ${archive} ]]; then
    printf '%s\n' "configured Elasticsearch archive does not exist" >&2
    return 1
  fi
  local observed_digest
  observed_digest="$(python3 - "${archive}" <<'PY'
import hashlib
import sys

digest = hashlib.sha512()
with open(sys.argv[1], "rb", buffering=0) as source:
    while block := source.read(1024 * 1024):
        digest.update(block)
print(digest.hexdigest())
PY
)"
  if [[ ${observed_digest} != "${ES_SHA512}" ]]; then
    printf '%s\n' "Elasticsearch archive SHA-512 does not match the pinned release" >&2
    return 1
  fi

  mkdir -p -- "${run_dir}/software"
  timeout --signal=TERM --kill-after=10s 180s \
    tar \
      --extract \
      --gzip \
      --file "${archive}" \
      --directory "${run_dir}/software" \
      --no-same-owner \
      --no-same-permissions
  printf '%s\n' "${run_dir}/software/elasticsearch-${ES_VERSION}"
}

elasticsearch_home="$(resolve_elasticsearch_home)"
version_output="$(
  timeout --signal=TERM --kill-after=5s 30s \
    "${elasticsearch_home}/bin/elasticsearch" --version 2>&1
)"
if [[ ${version_output} != *"Version: ${ES_VERSION}"* ]]; then
  printf 'expected Elasticsearch %s, but the distribution reported another version\n' \
    "${ES_VERSION}" >&2
  exit 1
fi

read -r http_port transport_port < <(
  python3 <<'PY'
import socket

sockets = []
try:
    for _ in range(2):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        sock.bind(("127.0.0.1", 0))
        sockets.append(sock)
    print(*(sock.getsockname()[1] for sock in sockets))
finally:
    for sock in sockets:
        sock.close()
PY
)
readonly http_port transport_port

config_dir="${run_dir}/config"
mkdir -p \
  "${config_dir}/jvm.options.d" \
  "${run_dir}/data" \
  "${run_dir}/logs" \
  "${run_dir}/tmp"
for name in jvm.options log4j2.properties roles.yml role_mapping.yml users users_roles; do
  if [[ -f "${elasticsearch_home}/config/${name}" ]]; then
    install -m 0600 "${elasticsearch_home}/config/${name}" "${config_dir}/${name}"
  fi
done
if [[ -d "${elasticsearch_home}/config/jvm.options.d" ]]; then
  while IFS= read -r -d '' option_file; do
    install -m 0600 "${option_file}" "${config_dir}/jvm.options.d/$(basename -- "${option_file}")"
  done < <(
    find "${elasticsearch_home}/config/jvm.options.d" -maxdepth 1 -type f -name '*.options' -print0
  )
fi

cat >"${config_dir}/elasticsearch.yml" <<EOF
cluster.name: control-assurance-elastic-live
node.name: control-assurance-node
discovery.type: single-node
network.host: 127.0.0.1
http.port: ${http_port}
transport.port: ${transport_port}
path.data: "${run_dir}/data"
path.logs: "${run_dir}/logs"
action.destructive_requires_name: true
cluster.routing.allocation.disk.threshold_enabled: false
ingest.geoip.downloader.enabled: false
node.store.allow_mmap: false
xpack.ml.enabled: false
xpack.security.autoconfiguration.enabled: false
xpack.security.enabled: true
xpack.security.enrollment.enabled: false
xpack.security.http.ssl.enabled: false
xpack.security.transport.ssl.enabled: false
EOF
chmod 0600 "${config_dir}/elasticsearch.yml"

python3 - "${run_dir}/bootstrap.secret" "${run_dir}/bootstrap-curl.conf" <<'PY'
import os
import secrets
import sys

secret_path, config_path = sys.argv[1:]
password = secrets.token_urlsafe(48)
for path, content in (
    (secret_path, password),
    (
        config_path,
        "\n".join(
            (
                "silent",
                "show-error",
                "noproxy = \"*\"",
                "connect-timeout = 2",
                "max-time = 10",
                f'user = "elastic:{password}"',
                "",
            )
        ),
    ),
):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, content.encode("ascii"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
PY

ES_PATH_CONF="${config_dir}" \
  "${elasticsearch_home}/bin/elasticsearch-keystore" create >/dev/null
ES_PATH_CONF="${config_dir}" \
  "${elasticsearch_home}/bin/elasticsearch-keystore" \
  add --force --stdin bootstrap.password \
  <"${run_dir}/bootstrap.secret" >/dev/null

printf 'starting isolated Elasticsearch %s on loopback\n' "${ES_VERSION}"
ES_PATH_CONF="${config_dir}" \
ES_JAVA_OPTS="-Xms512m -Xmx512m" \
ES_TMPDIR="${run_dir}/tmp" \
  "${elasticsearch_home}/bin/elasticsearch" \
  >"${run_dir}/elasticsearch.stdout.log" 2>&1 &
es_pid=$!

ready=0
for _ in {1..90}; do
  if ! kill -0 "${es_pid}" >/dev/null 2>&1; then
    printf '%s\n' "Elasticsearch exited before becoming ready" >&2
    exit 1
  fi
  status="$(
    curl \
      --config "${run_dir}/bootstrap-curl.conf" \
      --output "${run_dir}/version.json" \
      --write-out '%{http_code}' \
      --url "http://127.0.0.1:${http_port}/" \
      2>/dev/null || true
  )"
  if [[ ${status} == "200" ]]; then
    ready=1
    break
  fi
  sleep 1
done
if [[ ${ready} -ne 1 ]]; then
  printf '%s\n' "Elasticsearch did not become ready within 90 seconds" >&2
  exit 1
fi

python3 - "${run_dir}/version.json" "${ES_VERSION}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    response = json.load(source)
if response.get("version", {}).get("number") != sys.argv[2]:
    raise SystemExit("live node did not report the pinned Elasticsearch version")
if response.get("tagline") != "You Know, for Search":
    raise SystemExit("live endpoint is not Elasticsearch")
PY

cat >"${run_dir}/create-index.json" <<EOF
{
  "settings": {
    "index.hidden": true,
    "number_of_replicas": 0,
    "number_of_shards": 2
  },
  "mappings": {
    "dynamic": "strict",
    "properties": {
      "@timestamp": {"type": "date_nanos"},
      "host": {"properties": {"name": {"type": "keyword"}}},
      "kibana": {
        "properties": {
          "alert": {
            "properties": {
              "rule": {"properties": {"name": {"type": "keyword"}}},
              "severity": {"type": "keyword"}
            }
          }
        }
      },
      "user": {"properties": {"name": {"type": "keyword"}}}
    }
  },
  "aliases": {
    "${ALERT_ALIAS}": {"is_hidden": true}
  }
}
EOF

status="$(
  curl \
    --config "${run_dir}/bootstrap-curl.conf" \
    --request PUT \
    --header "Content-Type: application/json" \
    --data-binary "@${run_dir}/create-index.json" \
    --output "${run_dir}/create-index-response.json" \
    --write-out '%{http_code}' \
    --url "http://127.0.0.1:${http_port}/${BACKING_INDEX}"
)"
if [[ ${status} != "200" ]]; then
  printf '%s\n' "failed to create the hidden alert backing index" >&2
  exit 1
fi

cat >"${run_dir}/alerts.ndjson" <<EOF
{"index":{"_index":"${BACKING_INDEX}","_id":"in-window-0001"}}
{"@timestamp":"2026-07-29T00:00:00.000000000Z","host":{"name":"sensitive-host-01"},"kibana":{"alert":{"rule":{"name":"Boundary-open"},"severity":"low"}},"user":{"name":"sensitive-user-01"}}
{"index":{"_index":"${BACKING_INDEX}","_id":"in-window-0002"}}
{"@timestamp":"2026-07-29T08:15:30.123456789Z","host":{"name":"sensitive-host-02"},"kibana":{"alert":{"rule":{"name":"Credential access signal"},"severity":"medium"}},"user":{"name":"sensitive-user-02"}}
{"index":{"_index":"${BACKING_INDEX}","_id":"in-window-0003"}}
{"@timestamp":"2026-07-29T16:45:00.000000000Z","host":{"name":"sensitive-host-03"},"kibana":{"alert":{"rule":{"name":"Endpoint isolation lag"},"severity":"high"}},"user":{"name":"sensitive-user-03"}}
{"index":{"_index":"${BACKING_INDEX}","_id":"in-window-0004"}}
{"@timestamp":"2026-07-29T23:59:59.999999999Z","host":{"name":"sensitive-host-04"},"kibana":{"alert":{"rule":{"name":"Recovery validation"},"severity":"critical"}},"user":{"name":"sensitive-user-04"}}
{"index":{"_index":"${BACKING_INDEX}","_id":"end-boundary-0005"}}
{"@timestamp":"2026-07-30T00:00:00.000000000Z","host":{"name":"must-not-leave-source"},"kibana":{"alert":{"rule":{"name":"End boundary must be excluded"},"severity":"critical"}},"user":{"name":"must-not-leave-source"}}
EOF

status="$(
  curl \
    --config "${run_dir}/bootstrap-curl.conf" \
    --request POST \
    --header "Content-Type: application/x-ndjson" \
    --data-binary "@${run_dir}/alerts.ndjson" \
    --output "${run_dir}/bulk-response.json" \
    --write-out '%{http_code}' \
    --url "http://127.0.0.1:${http_port}/_bulk?refresh=true"
)"
if [[ ${status} != "200" ]]; then
  printf '%s\n' "failed to seed the real alert index" >&2
  exit 1
fi
python3 - "${run_dir}/bulk-response.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    response = json.load(source)
items = response.get("items")
if response.get("errors") is not False or not isinstance(items, list) or len(items) != 5:
    raise SystemExit("Elasticsearch bulk seed was incomplete")
if any(item.get("index", {}).get("status") not in (200, 201) for item in items):
    raise SystemExit("Elasticsearch rejected at least one seed document")
PY

cat >"${run_dir}/create-api-key.json" <<EOF
{
  "name": "control-assurance-elastic-live",
  "expiration": "15m",
  "role_descriptors": {
    "capture": {
      "cluster": [],
      "indices": [
        {
          "allow_restricted_indices": true,
          "names": ["${ALERT_ALIAS}", "${BACKING_INDEX}"],
          "privileges": ["read"]
        }
      ]
    }
  }
}
EOF
status="$(
  curl \
    --config "${run_dir}/bootstrap-curl.conf" \
    --request POST \
    --header "Content-Type: application/json" \
    --data-binary "@${run_dir}/create-api-key.json" \
    --output "${run_dir}/api-key-response.json" \
    --write-out '%{http_code}' \
    --url "http://127.0.0.1:${http_port}/_security/api_key"
)"
if [[ ${status} != "200" ]]; then
  printf '%s\n' "failed to create the short-lived capture API key" >&2
  exit 1
fi

python3 \
  - "${run_dir}/api-key-response.json" "${run_dir}/capture-api-key.secret" \
  "${run_dir}/api-key-curl.conf" "${run_dir}/api-key-id.json" <<'PY'
import json
import os
import re
import sys

response_path, secret_path, config_path, identifier_path = sys.argv[1:]
with open(response_path, encoding="utf-8") as source:
    response = json.load(source)
encoded = response.get("encoded")
identifier = response.get("id")
if (
    not isinstance(encoded, str)
    or re.fullmatch(r"[A-Za-z0-9_+/=-]{16,8192}", encoded) is None
):
    raise SystemExit("API key response did not contain a canonical encoded key")
if not isinstance(identifier, str) or not 1 <= len(identifier) <= 1024:
    raise SystemExit("API key response did not contain a bounded identifier")
outputs = (
    (secret_path, encoded),
    (
        config_path,
        "\n".join(
            (
                "silent",
                "show-error",
                'noproxy = "*"',
                "connect-timeout = 2",
                "max-time = 10",
                f'header = "Authorization: ApiKey {encoded}"',
                "",
            )
        ),
    ),
    (identifier_path, json.dumps({"ids": [identifier]}, separators=(",", ":"))),
)
for path, content in outputs:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, content.encode("ascii"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
PY
rm -f -- "${run_dir}/api-key-response.json"
api_key_created=1

# The capture principal has no cluster-monitor or write permission.  Both calls
# must fail before the connector is allowed to use the key.
cluster_status="$(
  curl \
    --config "${run_dir}/api-key-curl.conf" \
    --output "${run_dir}/denied-cluster.json" \
    --write-out '%{http_code}' \
    --url "http://127.0.0.1:${http_port}/_cluster/health"
)"
write_status="$(
  curl \
    --config "${run_dir}/api-key-curl.conf" \
    --request PUT \
    --header "Content-Type: application/json" \
    --data-binary '{"@timestamp":"2026-07-29T12:00:00Z"}' \
    --output "${run_dir}/denied-write.json" \
    --write-out '%{http_code}' \
    --url "http://127.0.0.1:${http_port}/${BACKING_INDEX}/_doc/permission-probe"
)"
if [[ ${cluster_status} != "403" || ${write_status} != "403" ]]; then
  printf '%s\n' "capture API key is more privileged than the live profile permits" >&2
  exit 1
fi

python_command="${CONTROL_ASSURANCE_PYTHON:-}"
if [[ -z ${python_command} ]]; then
  if [[ -x "${repository_root}/.venv/bin/python" ]]; then
    python_command="${repository_root}/.venv/bin/python"
  else
    python_command="$(command -v python3)"
  fi
fi

printf '%s\n' "running Python capture and independent Node verification"
CONTROL_ASSURANCE_ELASTIC_URL="http://127.0.0.1:${http_port}" \
CONTROL_ASSURANCE_ELASTIC_API_KEY_FILE="${run_dir}/capture-api-key.secret" \
CONTROL_ASSURANCE_ELASTIC_PARENT_SECRET_FILE="${run_dir}/bootstrap.secret" \
CONTROL_ASSURANCE_ELASTIC_EXPECTED_COUNT=4 \
  timeout --signal=TERM --kill-after=15s 180s \
    "${python_command}" -m pytest -q \
      tests/integration/test_elastic_security_live.py

printf '%s\n' \
  "real Elasticsearch conformance passed: 4 in-window alerts, end boundary excluded"
