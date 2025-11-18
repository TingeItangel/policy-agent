#!/bin/bash

# --- Auth ---
response=$(curl -s -k https://localhost:8443/auth)
# warte auf die Antwort und parse JSON
printf 'Auth Response: %s\n' "$response"
nonce=$(echo "$response" | jq -r '.nonce')
sessionID=$(echo "$response" | jq -r '.session_id')
secretKeyHex=$(echo "$response" | jq -r '.secret_key')
printf 'Nonce: %s\n' "$nonce"
printf 'SessionID: %s\n' "$sessionID"
printf 'SecretKey: %s\n' "$secretKeyHex"
# --- End Auth ---



# --- Patch ---
# Beispiel-JSON-Body
body='{
  "sessionID": "'$sessionID'",
  "deploymentName": "nginx-deployment",
  "namespace": "default",
  "commands": ["echo hello"],
  "image": ["nginx:latest"],
  "deny": false,
  "oldMrConfigId": "new-config-mr-value"
}'

# 1) Hash des Payloads (SHA256)
hashHex=$(printf '%s' "$body" | sha256sum | awk '{print $1}')
printf 'HashHex: %s\n' "$hashHex"

# 2) SecretKey als Binärdaten
# Zum Test wurde sechretKeyHex aus der Auth-Antwort extrahiert, muss später von Trustee geholt werden
secretKeyHex="$secretKeyHex"
secretKey=$(printf "$secretKeyHex" | xxd -r -p)

# 3) Nonce aus Auth-Antwort verwenden (bereits in Variable $nonce)

# 4) HMAC über "hashHex.nonce"
# mach erst msg = hashHex + "." + nonce
msg=$(printf '%s.%s' "$hashHex" "$nonce")
printf 'Message: %s\n' "$msg"
# berechne HMAC und base64-encode: HMAC-SHA256(msg, secretKey)
sig=$(printf '%s' "$msg" | openssl dgst -sha256 -mac HMAC -macopt hexkey:$secretKeyHex -binary | base64)
printf 'Signature: %s\n' "$sig"
# 5) Sende POST-Anfrage mit den entsprechenden Headern
curl -k -X POST https://localhost:8443/patch \
  -H "Content-Type: application/json" \
  -H "X-Hash-Algorithm: SHA256" \
  -H "X-Hash-Value: $hashHex" \
  -H "X-Nonce: $nonce" \
  -H "Authorization: HMAC-SHA256 $sig" \
  -d "$body"
