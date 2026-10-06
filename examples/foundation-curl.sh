#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
command -v jq >/dev/null
BASE=${PMBU_URL:-http://127.0.0.1:4191}
STATE=${PMBU_STATE_FILE:-foundation-data/state.json}
ADMIN=$(jq -r .adminKey "$STATE")
CLIENT_SECRET=$(jq -r .gatewayKey "$STATE")
# Script approves a synthetic push as the administrator for repeatable testing.
ENROLLED=$(curl --fail-with-body -sS "$BASE/v1/admin/agents" -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' -d '{"name":"Security curl demo","deviceId":"deskside-assistant","profile":"security","owner":"demo-human"}')
AGENT_ID=$(printf '%s' "$ENROLLED" | jq -r .agent.id)
ENROLLMENT=$(printf '%s' "$ENROLLED" | jq -r .enrollmentToken)
IDENTITY=$(curl --fail-with-body -sS "$BASE/v1/identities" -H "Authorization: Bearer $ENROLLMENT" -H 'Content-Type: application/json' -d "{\"agentId\":\"$AGENT_ID\"}" | jq -r .token)
PUSH_ID=$(curl --fail-with-body -sS "$BASE/duo/push" -H "Authorization: Bearer $IDENTITY" -H 'Content-Type: application/json' -d '{}' | jq -r .id)
curl --fail-with-body -sS "$BASE/duo/admin/decide" -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' -d "{\"push_id\":\"$PUSH_ID\",\"status\":\"approved\"}" >/dev/null
DETAILS='[{"type":"urn:pmbu:authorization:network-qos","operation":"security_alert","network_context":"access","flow_id":"curl-security-01","subscriber_id":"DEMO-SUBSCRIBER","pdu_session_id":"demo-session-1","flow":{"src_ip":"192.0.2.10","dst_ip":"192.0.2.20","src_port":45000,"dst_port":443,"protocol":"tcp"}}]'
RESPONSE=$(curl --fail-with-body -sS "$BASE/oauth/token" --user "pmbu-agent-client:$CLIENT_SECRET" \
 --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
 --data-urlencode 'subject_token_type=urn:ietf:params:oauth:token-type:jwt' \
 --data-urlencode "subject_token=$IDENTITY" --data-urlencode 'audience=pmbu-pcf-adapter' \
 --data-urlencode "duo_approval_id=$PUSH_ID" --data-urlencode "authorization_details=$DETAILS")
ACCESS_TOKEN=$(printf '%s' "$RESPONSE" | jq -r .access_token)
printf '%s' "$RESPONSE" | jq '{token_type,issued_token_type,expires_in,authorization_details}'
curl --fail-with-body -sS "$BASE/oauth/introspect" --user "pmbu-pcf-adapter:$CLIENT_SECRET" --data-urlencode "token=$ACCESS_TOKEN" | jq '{active,aud,enterprise_group,qos_tier,"5qi",dscp,enforcement,authorization_details}'
# Deliberately do not print or write bearer tokens.
unset ADMIN CLIENT_SECRET ENROLLED ENROLLMENT IDENTITY RESPONSE ACCESS_TOKEN
