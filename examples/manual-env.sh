# Source from the project root: source examples/manual-env.sh
# Setup only: reads local credentials; creates no agent, approval, or entitlement.
export PATH="/Applications/Docker.app/Contents/Resources/bin:$PATH"
umask 077
mkdir -p foundation-data
if docker compose exec -T identity-foundation cat /app/state/state.json > foundation-data/manual-state.json; then
  chmod 600 foundation-data/manual-state.json
  HF_BASE=http://127.0.0.1:4191
  HF_ADMIN=$(jq -r .adminKey foundation-data/manual-state.json)
  HF_SECRET=$(jq -r .gatewayKey foundation-data/manual-state.json)
  HF_SPIFFE=spiffe://pmbu.demo/workloads/security
  HF_AGENT_ID=$(jq -r --arg id "$HF_SPIFFE" '.foundation.spiffeMappings[$id] // empty' foundation-data/manual-state.json)
  printf '%s\n' "Ready: $HF_BASE" 'Credentials loaded into shell variables; not displayed.'
  if [ -n "$HF_AGENT_ID" ]; then printf '%s\n' 'Existing security SPIFFE mapping found; skip registration in step 2.'; fi
else
  printf '%s\n' 'Could not read container state. Check docker compose ps.' >&2
fi
