#!/usr/bin/env bash

set -euo pipefail

OPENFGA_URL="${OPENFGA_URL:-http://127.0.0.1:8080}"
OPENFGA_IMAGE="${OPENFGA_IMAGE:-openfga/openfga:v1.18.0}"
OPENFGA_CONTAINER="maps-openfga-test"
ENV_FILE=".buildkite/openfga.env"
MODEL_FILE="src/test/resources/openfga-model.json"

wait_for_openfga() {
  for _ in $(seq 1 30); do
    if curl -fsS "${OPENFGA_URL}/healthz" | grep -q 'SERVING'; then
      return 0
    fi
    sleep 1
  done
  return 1
}

if ! curl -fsS "${OPENFGA_URL}/healthz" 2>/dev/null | grep -q 'SERVING'; then
  sudo docker rm -f "${OPENFGA_CONTAINER}" >/dev/null 2>&1 || true
  sudo docker run -d \
    --name "${OPENFGA_CONTAINER}" \
    --restart unless-stopped \
    -p 127.0.0.1:8080:8080 \
    "${OPENFGA_IMAGE}" \
    run --playground-enabled=false >/dev/null
fi

if ! wait_for_openfga; then
  echo "OpenFGA did not become healthy at ${OPENFGA_URL}" >&2
  sudo docker logs "${OPENFGA_CONTAINER}" >&2 || true
  exit 1
fi

STORE_RESPONSE="$(curl -fsS \
  -X POST "${OPENFGA_URL}/stores" \
  -H 'content-type: application/json' \
  -d "{\"name\":\"maps-auth-build-${BUILDKITE_BUILD_ID:-local}\"}")"

OPENFGA_STORE_ID="$(printf '%s' "${STORE_RESPONSE}" | jq -r '.id // .store.id // empty')"
if [ -z "${OPENFGA_STORE_ID}" ]; then
  echo "Unable to determine OpenFGA store id from: ${STORE_RESPONSE}" >&2
  exit 1
fi

MODEL_RESPONSE="$(curl -fsS \
  -X POST "${OPENFGA_URL}/stores/${OPENFGA_STORE_ID}/authorization-models" \
  -H 'content-type: application/json' \
  --data-binary "@${MODEL_FILE}")"

OPENFGA_MODEL_ID="$(printf '%s' "${MODEL_RESPONSE}" | jq -r '.authorization_model_id // empty')"
if [ -z "${OPENFGA_MODEL_ID}" ]; then
  echo "Unable to determine OpenFGA model id from: ${MODEL_RESPONSE}" >&2
  exit 1
fi

cat >"${ENV_FILE}" <<EOF
export OPENFGA_URL='${OPENFGA_URL}'
export OPENFGA_STORE_ID='${OPENFGA_STORE_ID}'
export OPENFGA_MODEL_ID='${OPENFGA_MODEL_ID}'
EOF

chmod 0600 "${ENV_FILE}"

echo "OpenFGA ready: store=${OPENFGA_STORE_ID}, model=${OPENFGA_MODEL_ID}"
