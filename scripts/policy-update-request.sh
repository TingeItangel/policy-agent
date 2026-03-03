#!/bin/sh
pa_service_url="https://<POLICY_AGENT_IP:PORT>"

# --- Auth ---
response=$(curl -s -k "$pa_service_url/auth")
printf 'Auth Response: %s\n' "$response"
nonce=$(echo "$response" | jq -r '.nonce')
sessionID=$(echo "$response" | jq -r '.session_id')
printf 'Nonce: %s\n' "$nonce"
# --- End Auth ---

# VORSICHT --- RACE CONDITION MÖGLICH --- 
echo "⏳ warte auf Session-Key für $sessionID ..."

while true; do
    raw=$(curl -s "http://127.0.0.1:8006/cdh/resource/default/pa-sessions/$sessionID")

    # leer? → key noch nicht da 
    if [ -z "$raw" ]; then
        sleep 1
        continue
    fi

    # Fehlermeldung vom CDH (statt Key)?
    if echo "$raw" | grep -q "Status {"; then
        echo "noch nicht bereit (Status-Fehler), warte..." >&2
        sleep 5
        continue
    fi
    break
done

echo "✅ raw key erhalten"
if echo "$raw" | grep -q "Status {"; then
  echo "Fehler vom CDH statt Key:"
  echo "$raw"
  exit 1
fi

# Konvertiere SecretKey in Hex-Format
secretKeyHex=$(printf '%s' "$raw" | od -An -tx1 | tr -d ' \n')
printf 'SecretKeyHex: %s\n' "$secretKeyHex"

# --- Patch ---
body='{
  "sessionID": "'$sessionID'",
  "deploymentName": "nginx-deployment",
  "namespace": "default",
  "commands": ["echo hello", "ls -la"],
  "image": ["nginx:latest"],
  "deny": false
}'
printf 'Request Body: %s\n' "$body"

# Hash des Payloads (SHA256)
hashHex=$(printf '%s' "$body" | sha256sum | awk '{print $1}')

# HMAC über msg → msg="hashHex.nonce" 
msg=$(printf '%s.%s' "$hashHex" "$nonce")
printf 'Message: %s\n' "$msg"

# berechne HMAC und base64-encode: HMAC-SHA256(msg, secretKey)
sig=$(printf '%s' "$msg" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$secretKeyHex" -binary | base64 | tr -d '\n')
printf 'Signature: %s\n' "$sig"

# Sende POST-Anfrage
curl -k -X POST "$pa_service_url/patch" \
  -H "Content-Type: application/json" \
  -H "X-Hash-Algorithm: SHA256" \
  -H "X-Hash-Value: $hashHex" \
  -H "X-Nonce: $nonce" \
  -H "Authorization: HMAC-SHA256 $sig" \
  -d "$body"
