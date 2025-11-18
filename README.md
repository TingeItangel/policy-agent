# policy-agent

## Suggestions for a good README

Every project is different, so consider which of these sections apply to yours. The sections used in the template are suggestions for most open source projects. Also keep in mind that while a README can be too long and detailed, too long is better than too short. If you think your README is too long, consider utilizing another form of documentation rather than cutting out information.

## Name

Choose a self-explaining name for your project.

## Description

Let people know what your project can do specifically. Provide context and add a link to any reference visitors might be unfamiliar with. A list of Features or a Background subsection can also be added here. If there are alternatives to your project, this is a good place to list differentiating factors.

## Badges

On some READMEs, you may see small images that convey metadata, such as whether or not all the tests are passing for the project. You can use Shields to add some to your README. Many services also have instructions for adding a badge.

## Visuals

Depending on what you are making, it can be a good idea to include screenshots or even a video (you'll frequently see GIFs rather than actual videos). Tools like ttygif can help, but check out Asciinema for a more sophisticated method.

## Installation

Within a particular ecosystem, there may be a common way of installing things, such as using Yarn, NuGet, or Homebrew. However, consider the possibility that whoever is reading your README is a novice and would like more guidance. Listing specific steps helps remove ambiguity and gets people to using your project as quickly as possible. If it only runs in a specific context like a particular programming language version or operating system or has dependencies that have to be installed manually, also add a Requirements subsection.

## Usage

Use examples liberally, and show the expected output if you can. It's helpful to have inline the smallest example of usage that you can demonstrate, while providing links to more sophisticated examples if they are too long to reasonably include in the README.

## Support

Tell people where they can go to for help. It can be any combination of an issue tracker, a chat room, an email address, etc.

## Roadmap

If you have ideas for releases in the future, it is a good idea to list them in the README.

## Contributing

State if you are open to contributions and what your requirements are for accepting them.

For people who want to make changes to your project, it's helpful to have some documentation on how to get started. Perhaps there is a script that they should run or some environment variables that they need to set. Make these steps explicit. These instructions could also be useful to your future self.

You can also document commands to lint the code or run tests. These steps help to ensure high code quality and reduce the likelihood that the changes inadvertently break something. Having instructions for running tests is especially helpful if it requires external setup, such as starting a Selenium server for testing in a browser.

## Authors and acknowledgment

Show your appreciation to those who have contributed to the project.

## License

For open source projects, say how it is licensed.

## Project status

If you have run out of energy or time for your project, put a note at the top of the README saying that development has slowed down or stopped completely. Someone may choose to fork your project or volunteer to step in as a maintainer or owner, allowing your project to keep going. You can also make an explicit request for maintainers.

# Planing

## Allgemein

- [ ] Was passiert, wenn das Deployment / Pod für den request nicht da ist?
  - [ ] Response: Welcher https-Fehlercode?
- [ ] Wenn dein Agent selbst in einem TEE läuft (z. B. via Confidential Containers), dann bietet das
  - Schutz gegen Manipulation des Codes/Memory
  - Nachweis über Attestation (Agent hat keinen manipulierten Code)
  - Zugang zu Secrets (z. B. Signierschlüssel) nur im TEE
  - Das erschwert TOCTOU-Angriffe massiv, weil:
    - Die Policy-Logik (inkl. Prüfungen & kubectl patch) ist innerhalb der TCB isoliert.

## Kommunikation

- [ ] Kommunikation eines Requests
  - https-protocol mit Server-Client Zertifikate
    - [ ] https mit Challenge-Response schützt Verbindung
      - [ ] http Anfragen sollen abgeleht werden
    - [ ] HMAC über Body-Request-Hash + Nonce + secret = Replay-Schutz + Authentication
      - [ ] Nonce kommt vom policy-agent mit einer intialen GET Anfrage
      - [ ] Tolleranzfenster von +- 30 bis 120 Sekunden (dann wird Nonce ungültig)
      - [ ] Was ist mit Timestamp statt Hash? Problem: Zeitverschiebung **Problematisch daher lieber Challenge-Response mit Nonce und Hash vom Server**
            → keine Zeitprobleme. Aber: 2-Request-Workflow → höhere Latenz.
      - [ ] Client fragt zuerst `GET /auth` an.
      - [ ] Server erstellt einmalige Nonce + Ablaufzeit und merkt sich diese.
      - [ ] Client sendet diese Nonce + sessionid im Request mit.
    - [ ] Payload-Signatur für inhaltliche Authentizität (Hash über Request-Body) + Signatur: HMAC(Hash + Secret)
    - Der Client (z. B. ein attestierter Pod) signiert die Payload (z. B. mit einem Key aus dem TEE oder KBS/Trustee).
    - Der Server validiert:
      - Nonce ist einzigartig (**verhindert Replay & TOCTOU**)
      - Signatur ist gültig
  - [ ] Replay Angriffe mit Nonce verhindern => es müssen kürzlich verwendete Nonces zwischengespeichert werden und doppelte oder zu alte Anfragen ablehnen
    - [ ] Wie lange / wie viele Noncen werden zwischengespeichert?
    - [ ] Redis DB mit expiration. Wenn eine nonce verwendet wird, wird sie sofort gelöscht oder liber mit flag als `used` kennzeichnen? **Kann es race-condition geben, wenn die nonce gelöscht wird? (während eine nonce gelöscht wird, kommt eine neue Anfrage)**

### Ablauf – Challenge-Response mit Nonce

1. Client holt Nonce mit GET-Request

```zsh
curl -k https://policy-agent:8443/auth
# Antwort: {"nonce":"abc123...", "sessionID":"uuid-..."}
```

Authorization: HMAC-SHA256 <base64(signature)>

- X-Alg: HMAC-SHA256
- X-Timestamp: 2025-11-09T08:30:00Z (RFC3339/ISO8601, UTC)
- X-Nonce: <zufällige UUID>
- X-Content-SHA256: <hex(sha256(payload-bytes))>

```zsh
curl -k -X POST https://policy-agent:8443/patch \
    -H "Content-Type: application/json" \
    -d '{"nonce":"abc123...", "target":"my-deployment", ... }'

```

1. Server prüft:

- Nonce existiert noch.
- Nonce ist nicht abgelaufen.
- Nonce wurde noch nicht benutzt (One-Time-Use).

3. Server löscht Nonce nach erfolgreicher Validierung → Replay unmöglich.

## Database

```bash
# start redis in kubernetes cluster
kubectl apply -f ./deployments//redis.yaml
# check redis pod logs
kubectl logs -f redis-xxxx -n policy-agent
# podforwarding for local testing and development
kubectl port-forward svc/redis 6379:6379
```

## Logging

- [ ] Secure Audit Logging
  - [ ] Jede Anfrage (mit Timestamp, Hash und TEE Key signieren) wird persistiert
  - [ ] Optional: Unveränderlich (z. B. über append-only FS oder external log sink)

## InitData

- [ ] InitData
  - [ ] Wie kann ich bei TDX die intiData eines Pods im measurement aufnehmen? (CoCo Projekt)
  - [ ] Policy-Agent InitData ermitteln. Dem Measurement hinzufügen
  - [ ] Referenzwert von policy-agent in Trustee hinterlegen, damit dieser secrets abrufen kann

## Zertifikate

- [ ] Zertifikate in Trustee hinterlegen (Wenn verschlüsselung des policy-images ausreicht **nicht nötig**)
- [ ] Welche Secrets müssen vom Agenten zur Laufzeit von Trustee geholt werden?
- [ ] Deployment / Pod Yaml vom Cluster auslesen
  - [ ] Wie müssen die Rechte sein, damit ein Pod in einer TEE auf den unstrusted Cluster zugreifen kann?
  - [ ] Was für Sicherheitslücken gibt es, da die Isolation des Containers damit verringert wird?
  - [ ] Damit Client an Client-Zertifikat und Client-Key kommt, muss er sich bei Trustee attestiert haben.
    - [ ] Wenn policy-agent Image verschlüsselt ist, muss das Server-Zertifikate nicht von Trustee geladen? Reicht Image-Verschlüsselung aus?
    - Annahme: Trustee gibt nur Secret frei, wenn Pod in TEE läuft => zur Laufzeit sind Daten verschlüsselt und Zertifikat kann nicht abgefangen werden?
    - [ ] Client-Zertifikate und Client-Key in Trustee hinterlegen
      - nur Clients mit Zertifikate können legitime Anfragen stellen. Nur Attestierte Entitäten bekommen Zugang zum Zertifikate und Key.
      - [ ] Kann das Client-Zertifikate oder der Client-Key von einem Angreifer auslesen oder abgefangen werden?

## Cluster-Veränderungen aus dem Pod

- [ ] Wie aus dem Pod die yaml Datei verändert werden? (Berechtigungen?)
  - [ ] InitData Annotation von einem Deployment oder Pod
    - [ ] auslesen
    - [ ] verändern
    - [ ] speichern
  - [ ] Neuer Referenzwert bestimmen, kann ich das aus dem Pod?
  - [ ] Refernezwert in Trustee hintelegen (+ alten löschen)
    - [ ] Mit KBS-Client?
      - [ ] private Key und Zertifkate aus Trustee holen, um kbs-client zu nutzen.

## Image Verschlüsselung und Signierung

- [ ] Image von policy-agent verschlüsseln + signieren
  - [ ] policy-agent-Image über eine Registry bereitstellen
  - [ ] Key zum entschlüsseln in Trustee hinterlegen
  - [ ] CVM soll vor start des policy-agent ihn über Trustee attestieren, erst dann den Key zum entschlüsseln des Images laden und den Agenten als Pod starten

# Certificate

- cert.pem will be sent to the client.
- client can compare cert with cert.pem from trustee?
  - can trustee sign or vouches for the certificate?
- must be updated all 90 days

- image wird signiert und verschlüsselt sein
  - decryption key in trusee
- Pod startet und wurde attestiert
- holt TLS-Cert (cert.pem) und private.key von trustee mit kbs-client

- mTLS (mutual TLS) mit Client-Zertifikaten + Challenge-Response mit Nonce gegen Replay-Angriffe

Der Server verlangt vom Client beim TLS-Handshake ein Client-Zertifikat.

Nur Clients mit gültigem Zertifikat dürfen verbinden und Anfragen stellen.

Das Zertifikate kann in Trustee gespeichert werden. => nur wer sich in trustee attestiert hat, kann zugang dazu bekommen.

Wie kann ich absicher, dass das Cert von einam angreifer abgefangen wird und dann genutzt wird? reicht TEE dafür aus?

```zsh
# 1. CA erstellen
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt -subj "/CN=My-CA"

# 2. Server-Zertifikat + Key
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=localhost"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 3650 -sha256

# 3. Client-Zertifikat + Key
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/CN=my-client"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days 3650 -sha256
```

🐳 1. Container bauen & deployen

```zsh
docker build -t my-policy-agent:latest .
# Push in ein Registry, z. B.:
# docker tag my-policy-agent ghcr.io/yourname/my-policy-agent
# docker push ghcr.io/yourname/my-policy-agent
```

📦 Im Cluster (von einem anderen Pod):

```zsh
curl -k https://policy-agent.default.svc.cluster.local/patch
```

Oder über DNS-Kurzform:

```zsh
curl -k https://policy-agent/patch
```

Von außen (postman): Nodeport einrichten

# Testen

Starten des Https servers: `go run main.go`
`Curl`-Request:

```zsh
# GET Request for nonce, session-id
curl https://localhost:8443/auth
```


```zsh
POST /policy HTTP/1.1
Content-Type: application/json
X-Hash-Algorithm: sha256
X-Hash-Value: abcd
{
    "target": "my-deployment",
    "namespace": "default",
    "annotation": "kata-policy",
    "commands": ["echo", "hello"],
    "image": "nginx:latest",
    "isDeployment": true,
    "deny": true,
    "nonce": "abc"
}
```

## Calculate Hash of Body in Terminal

`jq -c . body.json | sha256sum`

## Postman

- Client-Zertifikat und -Key in Settings->Certificate hinzufügen
- Post-Request absetzten

# Weitere Test ideen

- Wie lange dauert es bis ein Deployment gepatcht wurde und neugestartet?

  - Wie kann die Zeit gemessen werden?
  - Wie verhält sich das System, wenn viele Requests hintereinander kommen?

- Was passiert wenn der gleiche Request zweimal gestellt wird?
-

# Schutzziele und Maßnahmen

| Bedrohung                   | Maßnahme                                                                                 | Schutzziel |
| --------------------------- | ---------------------------------------------------------------------------------------- | ---------- |
| ?                           | https                                                                                    | ?          |
| ?                           | mTLS                                                                                     | ?          |
| TOCTOU                      | Nonce, TEE zur Policy-Ausführung, Policy-Signaturen                                      | ?          |
| Replay-Angriffe             | Nonce, Challenge-Response (im https-Protokoll)                                           | ?          |
| Manipulierte Requests       | Payload-Signatur, Public-Key-Signatur mit TEE Key möglich? (macht das nicht auch https?) | ?          |
| Identitätsdiebstahl         | mTLS, TEE-basiertes Key-Provisioning                                                     | ?          |
| Unautorisierte Policy Calls | Access Control (mTLS Identity Matching)                                                  | ?          |
| ?                           | Secure Audit Logging                                                                     | ?          |

# Anmerkungen für MA

Der Patch wird über https ausgeführt. Wird da nicht eine Challenge Respone gemacht und der Server (policy-agent) schickt eine Nonce an den Client?

TLS verwendet eine Art Challenge-Response im Handshake, aber das ist nicht gleichzusetzen mit einem applikationsspezifischen Challenge-Response mit Nonce, wie man es z. B. zur Replay-Schutz und Policy-Verifikation braucht.

| Was es schützt                  | Wovor es schützt                      | Was es **nicht** schützt                        |
| ------------------------------- | ------------------------------------- | ----------------------------------------------- |
| Verbindungsaufbau + Identität   | MITM, Identitätsfälschung (wenn mTLS) | Replay, Manipulierte Nutzdaten                  |
| Austausch von Session Keys      | Abhören des Traffics                  | Authentizität der Nutzdaten _innerhalb_ des TLS |
| Server zeigt Besitz vom PrivKey | via Signature über TLS-Nonce          | Missbrauch von legitimen Requests               |

Wichtig: Das TLS-Protokoll schützt die Verbindung, nicht deine API-Semantik oder Policy-Logik.

🛡 2. Warum reicht TLS nicht für Replay-/TOCTOU-Schutz?

Ein Angreifer kann z. B.:

    Eine legitime TLS-Verbindung aufbauen (z. B. mit gestohlenem Client-Zertifikat)

    Eine alte, gültige Anfrage erneut senden (Replay-Angriff)

    Oder eine Policy zuerst checken und später erneut verwenden (TOCTOU)

Da TLS keine Kenntnis vom Request-Inhalt hat, schützt es nicht:

    Ob {"target": "my-deployment", ...} schon mal gesendet wurde

    Ob der Timestamp abgelaufen ist

    Ob der Nonce wiederverwendet wurde

    Ob die Anfrage aus einem TEE kam

✅ TLS schützt die Verbindung,
❌ nicht die Semantik deines Policy-Patch-Requests.

Wenn du also z. B. wirklich absichern willst, dass:

    Der Request nur einmal und zur richtigen Zeit gesendet wurde

    Die Daten nicht manipuliert wurden

    Der Sender attestiert und autorisiert ist

… dann brauchst du eine Anwendungsebene-Nonce + Signatur.


# Ideas
- sealed secrets für Keys zum Ver-/Entschlüsseln?


- TPM- Harware sicheheitsmoudle die Schlüssel verwlten (verfügbarkeit der Schlüssel gewährleisten und zu schützen)
  - non-voleteil Keys zu speichern
  - Angreifer löscht Schlüssel
- Verfügbarkeit von Schlüsseln ist ein wichtiges Thema!
- Enclave haben keinen extra abgeschirmten Speicher für Keys.

- Requester schickte Quote an Agent => Agent schickt Quote an AS von Trustee => Attestierung => Okay?
  - Frage: Wie kommt Workload an Quote. Nur CVM Guest-components haben Zugriff darauf. Workload ist absichtlich davon isoliert
  - Wie findet der API Request zwischen Coco Guest-Komponenten und Trustee statt? Dies muss auch irgendwie gehen. Idee: Workload schickt Request, Policy-Agenten schickt darauf einen Request an die API von der Guest-Komponente um Quote zu bekommen? Wie geht das?
# KBS Protocol

# Remote Access from trusted cluster in untrusted cluster

🔐 1. Principle: “API access = control”

Anyone with access to the Kubernetes API server can change workloads.

So the connection between trusted → untrusted must be locked down with the same care as root access.

🛠 2. Minimal RBAC in the untrusted cluster

In the untrusted cluster, create a ServiceAccount + RBAC binding that only allows what the trusted agent needs:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: policy-agent
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: default # or target namespace
  name: patcher-role
rules:
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["get", "list", "watch", "patch", "update"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: patcher-binding
  namespace: default
subjects:
  - kind: ServiceAccount
    name: policy-agent
    namespace: kube-system
roleRef:
  kind: Role
  name: patcher-role
  apiGroup: rbac.authorization.k8s.io
```

In the untrusted cluster: `kubectl apply -f ~/project/policy-agent/deployments/service-account-untrusted-cluster.yaml`

This way the trusted agent can’t delete nodes, secrets, etc. — only touch Deployments.

🔑 3. Export kubeconfig for that ServiceAccount

Extract a kubeconfig that uses that ServiceAccount’s token and the untrusted cluster’s API server:

```bash
kubectl --context=untrusted \
  -n kube-system create token policy-agent > sa.token

kubectl --context=untrusted config view \
  --minify -o jsonpath='{.clusters[0].cluster.server}'
# e.g. https://untrusted-control-plane:6443
```

Then build a dedicated kubeconfig (only with that token + CA + server).
This kubeconfig goes into the trusted cluster (secret mounted into the patch-agent pod).

🔒 4. Secure network channel

You have a few options:

VPN / WireGuard / Tailscale / Istio mTLS → connect the trusted pod to the untrusted API server over encrypted tunnel.

NetworkPolicy / firewall rules → restrict API server to accept requests only from the trusted cluster’s CIDR.

mTLS ingress (last resort) → expose untrusted API server behind a hardened ingress with client cert auth.

⚠️ Never expose https://<untrusted>:6443 directly to the internet without mutual TLS.

🧾 5. Trusted patch-agent usage

Now in the trusted cluster, your patch-agent pod just needs:

The untrusted kubeconfig mounted as a secret.

A Kubernetes client library (Go client-go, Python client, etc.) configured to use that kubeconfig.

When a request comes in (with token/nonce), it patches the untrusted Deployment via the kubeconfig context.

✅ Security benefits

Untrusted cluster runs no policy-agent (attack surface reduced).

Redis + nonce logic stays in the trusted cluster.

Even if the untrusted cluster is fully compromised, the attacker cannot impersonate the trusted agent because they don’t have the ServiceAccount token or secure tunnel.

Replay protection still handled inside trusted cluster (Redis).

## Create a ServiceAccount Token

```
kubectl apply -f - << EOF
apiVersion: v1
kind: Secret
metadata:
  name: policy-agent-token
  namespace: kube-system
  annotations:
    kubernetes.io/service-account.name: policy-agent
type: kubernetes.io/service-account-token
EOF
```

`kubectl -n kube-system get secret policy-agent-token -o yaml`

That token: value (after base64 decode) is what your trusted-cluster policy-agent will use.

`kubectl cluster-info | grep "control plane"`

Kubernetes control plane is running at https://127.0.0.1:45833

apiVersion: v1
data:
ca.crt: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURCVENDQWUyZ0F3SUJBZ0lJQkREa1Nlbm1HU2d3RFFZSktvWklodmNOQVFFTEJRQXdGVEVUTUJFR0ExVUUKQXhNS2EzVmlaWEp1WlhSbGN6QWVGdzB5TlRBNE1qY3hORFExTlRSYUZ3MHpOVEE0TWpVeE5EVXdOVFJhTUJVeApFekFSQmdOVkJBTVRDbXQxWW1WeWJtVjBaWE13Z2dFaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLCkFvSUJBUURUbVI2cVk2WU4yTHlaMnZ4endsTVk0R3VyTisra2t3OFFodFdENFdmV1lIRVQ3S3RGZ1phVzNjeDEKUkFaaWptNHlkTURKYitMNzFIY1hQc0liL0JTOWNqY3A4Qmd5M1Jpa1FhZ1ZQeG0wMjhYN2doYVp6Q1h5dVJCcQpiNGFpWWxxQjBQZDFuRVZjdkZIc2Z1eUxhaStFWXdpQ3pSYTRuQ1NQb2t4UWdhLzQyOVluYmxPUWZCQms2U3M2CjB4R1hxMnlLN3UycUVibDkyT3pHZnVld2VvaUl5NDI0YjVpd3NoUWRnc1Jwd0FVV2ptR0tHakdGYzVBOW9uN28KQW1Ob3pRNnVSOTdTcXh6NlJHN0RBQ09TekgxaVBNcVh5UTZoKy9MZW5DaTNucUdaYlVjODBlbytCRGVqS0JhZApOSFFkRE5BRFB3bExOM2JiQXhoNDlhQjg2T2poQWdNQkFBR2pXVEJYTUE0R0ExVWREd0VCL3dRRUF3SUNwREFQCkJnTlZIUk1CQWY4RUJUQURBUUgvTUIwR0ExVWREZ1FXQkJSalE4bEJiclBZelYwRW1mWjgzdHQwL3ZXLzVqQVYKQmdOVkhSRUVEakFNZ2dwcmRXSmxjbTVsZEdWek1BMEdDU3FHU0liM0RRRUJDd1VBQTRJQkFRQ0pTUy9ybzRtWApWMWpKclhGOWlqZEl2dmwvSFgrSVI0Y1N1Z2ZnejNFK1JzM1oxS3dFenZjWW85NHNrdGh1QkM5Vk4rYnNWYXM0ClF2RmdoZG90ZDRENWdFTml5b1UwbUplYXEwaXMwblZKc0VCZTQ5ZlNGQjR4TndKYVhrc1ZUZ3lpMldTbFVZcVEKY1NqVzh2MDZOcnZyUjAxd0Qxb2tDc0p5a3FCME9RbzJtTnFrVzAwdWhLV3Y4Z1BkQkNONCtXbDhMeEtaa21HNwpKdXRsUmN0ek9IQkVIOTZkbEdlNXRSbjBkcmFndTNhdzFZUldVUE1ISXRGck81TUZhUFo4Rjl0S29jVFRpckRXCmNTaWpmVHJnREh4L1M4TU9Uc0hMNC83RXJCT283dlIwbEVJaXhlanE5dHNPVTVYOVI4TXluMFF0M0NzcUhxTG8KUGFWVzdPeXllTnhsCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K
namespace: a3ViZS1zeXN0ZW0=
token: ZXlKaGJHY2lPaUpTVXpJMU5pSXNJbXRwWkNJNklsbHNZbTVMZGtWSFRWcEhSMmgzTFZwbE9WVldaVTVKTm1sQmN6ZFZSbUprUWtSdlVXSmhkVUUyTVUwaWZRLmV5SnBjM01pT2lKcmRXSmxjbTVsZEdWekwzTmxjblpwWTJWaFkyTnZkVzUwSWl3aWEzVmlaWEp1WlhSbGN5NXBieTl6WlhKMmFXTmxZV05qYjNWdWRDOXVZVzFsYzNCaFkyVWlPaUpyZFdKbExYTjVjM1JsYlNJc0ltdDFZbVZ5Ym1WMFpYTXVhVzh2YzJWeWRtbGpaV0ZqWTI5MWJuUXZjMlZqY21WMExtNWhiV1VpT2lKd2IyeHBZM2t0WVdkbGJuUXRkRzlyWlc0aUxDSnJkV0psY201bGRHVnpMbWx2TDNObGNuWnBZMlZoWTJOdmRXNTBMM05sY25acFkyVXRZV05qYjNWdWRDNXVZVzFsSWpvaWNHOXNhV041TFdGblpXNTBJaXdpYTNWaVpYSnVaWFJsY3k1cGJ5OXpaWEoyYVdObFlXTmpiM1Z1ZEM5elpYSjJhV05sTFdGalkyOTFiblF1ZFdsa0lqb2lPRFF6WlRWak9XSXRNVEJsWmkwME9URTVMVGxrTnpVdE5qTmhPRGcyWWpnMk1UWmlJaXdpYzNWaUlqb2ljM2x6ZEdWdE9uTmxjblpwWTJWaFkyTnZkVzUwT210MVltVXRjM2x6ZEdWdE9uQnZiR2xqZVMxaFoyVnVkQ0o5Lld6bW4ydFp3d3pDTERLc0ZsSTRrWk42dmpLM2c0LXdjdHdlS25BbW5CYWRsVGdXNmM4dmtTSnpVVUlrN2lVaTR1S29zalVydHRER0tsZDNocVBNT25sQUhPb3NrNTV1Zmd5RUk3RDRzQkZqOFFzNjNDYXZORjBCeUM0Q0JqU0N6WG13QU5GT0U4QmZFdl85TmtZUXJGaG5NSGlzbGh0R0tvMUR1aUNVbzRCMGwwbWJXSnVlWTg2N0JEZHlwMnB1NTYyVFNULS1GRkRkdjBneE9naTVXTzZzUE1yWnBKQ29QbndMc2EwZ3VPMl9MNWRvV3RkQmZVeVFMbWt4d0p3U2ZMZ0M2MUw5ZlRiU3gzdmprS0FVbXlscHVLZUVWeFFuMXlCdTNhblQ2OEtxQlgyaUozdUlsTjNsRGlmYWdxYlVMSHJ4dzhGQ19tYm93Q3JaaWNiRG1sdw==
kind: Secret
metadata:
annotations:
kubectl.kubernetes.io/last-applied-configuration: |
{"apiVersion":"v1","kind":"Secret","metadata":{"annotations":{"kubernetes.io/service-account.name":"policy-agent"},"name":"policy-agent-token","namespace":"kube-system"},"type":"kubernetes.io/service-account-token"}
kubernetes.io/service-account.name: policy-agent
kubernetes.io/service-account.uid: 843e5c9b-10ef-4919-9d75-63a886b8616b
creationTimestamp: "2025-08-28T17:19:21Z"
name: policy-agent-token
namespace: kube-system
resourceVersion: "81137"
uid: 00848df3-cd0e-4e1d-a60d-5c580f83b9a0
type: kubernetes.io/service-account-token

# Port Forwarding Redis for Local Development

```bash
kubectl port-forward svc/redis -n policy-agent 6379:6379
```

# Example https Request with Curl

```bash
# Authenticate and get a session information
# ssl-no-revoke to skip certificate revocation check for self-signed certs
curl --ssl-no-revoke https://localhost:8443/auth
# alternatively with client certs:
curl --cacert ca.crt https://localhost:8443/auth
```

## Ablauf der Installation

### Remote Cluster with Coco

1. ServiceAccount im Remote-Cluster anlegen + RBAC.

- `kubectl apply -f ./deployments/remoteCluster-rbac.yaml`
- WICHTIG: die RBAC Regeln müssen so gesetzt werden, dass nur die nötigsten Rechte vergeben werden (z. B. nur auf Deployments im namespace `confidential-containers-system` oder `operators`).

2. ServiceAccount Token im Remote-Cluster erzeugen:
   - `kubectl -n confidential-containers-system create token policy-agent-sa > /tmp/policy-agent-sa.token`

- WICHTIG: die token datei wird im lokalen Cluster im policy-agent Pod als secret gemountet.

3. CA holen (vom Remote-Cluster):
   cluster-context anpassen! (kind-c1 ist nur ein beispiel)

```bash
kubectl config view --raw -o jsonpath='{.clusters[?(@.name=="kind-c1")].cluster.certificate-authority-data}' \
| base64 -d > /tmp/remote.ca.crt
```

4. API-Server-URL des Remote-Clusters aus kubeconfig:
   cluster-context anpassen! (kind-c1 ist nur ein beispiel)

```bash
kubectl config view -o jsonpath='{.clusters[?(@.name=="kind-c1")].cluster.server}'
```

5. Deployments die gepatcht werden sollen im Remote-Cluster anpassen

- Es muss folgender command erlaubt sein:

```bash
`curl -s http://127.0.0.1:8006/aa/token?token_type=kbs \
		 | jq -r '.token' \
		 | cut -d '.' -f2 \
		 | base64 -d \
		 | jq -r '.submods.cpu."ear.veraison.annotated-evidence".tdx.quote.body.mr_config_id'`,
```

- Es müssen api calls vom Pod zur Guest-CVM erlaubt sein, um den Token zu bekommen:`io.katacontainers.config.hypervisor.kernel_params: "agent.guest_components_rest_api=all"`

### Trusted Cluster

1. redis im trusted Cluster deployen (z. B. im namespace policy-agent)
   - `kubectl apply -f ./deployments/redis.yaml`
2. rbac für den policy-agent anlegen

- `kubectl apply -f ./deployments/rbac-trusted-cluster.yaml`

3. policy-agent service erstellen, um den pod erreichbar zu machen (ClusterIP oder NodePort)

- `kubectl apply -f ./deployments/service-policy-agent.yaml`

4. policy-agent deployment erstellen

- `kubectl apply -f ./deployments/deployment-policy-agent.yaml`
- WICHTIG: im Deployment yaml müssen die ENV Variablen für den remote cluster gesetzt werden (API-Server-URL, token, namespace, serviceaccount name)
  - `REDIS_ADDR`: redis:6379 (wenn im gleichen namespace deployed)
  - `KBS_NAMESPACE`: namespace in dem trustee auf dem lokalen cluster läuft (z. B. confidential-containers-system oder operators)
  - `REMOTE_API_SERVER_URL`: URL des API-Servers des remote clusters (z. B. https://<remote-cluster-ip>:6443)

5. Secrets im lokalen Cluster anlegen (remote-cluster-cred im Namespace `policy-agent`)

```bash
kubectl -n policy-agent create secret generic remote-cluster-cred \
  --from-literal=api-server-url="https://<remote-apiserver>" \
  --from-file=token=/tmp/policy-agent-sa.token \
  --from-file=ca.crt=/tmp/remote.ca.crt
```

# Limitationen oder offene Fragen

- [ ] mehrere keys werden unter dem gleichen k8s secret gespeichert. Gibt es eine Limitation der Größe von k8s secrets? Sonst müsste für jede session ein eigenes secret angelegt werden. Wie verhält sich das k8s system wenn ganz viele secrets angelegt werden?
- [ ] Es wird hart auf essentielle Regeln in der `.toml` Datei geprüft. Wie kann ich das flexibler gestalten? Problem: initData Datei mit kann komplett frei gestaltet werden.

# Entscheidung:

## Vor-Hash des Payloads – ja oder nein?

Direkt HMAC über den Body: korrekt, einfach, aber du musst denselben Bytestrom exakt signieren (inkl. Whitespaces).

Vor-Hash (empfohlen): du signierst eine kleine kanonische Zeichenkette und nur den Hash des Bodys. Das ist bei großen Bodies effizienter und ergibt eine klarere Trennung von „Inhalt“ und „Metadaten“. Es ist das gängigste Muster (z. B. AWS SigV4 rechnet auch SHA256(payload) und signiert dann Metadaten + diesen Hash).

Wenn du JSON kanonisieren willst (Leerzeichen/Key-Order), brauchst du eine definierte Serialisierung – für den Anfang reicht der rohe Body-Hash.

# Reuqest Payload Beispiel

```json
{
  "target": "my-deployment",
  "namespace": "default",
  "annotation": "kata-policy",
  "commands": ["echo", "hello"],
  "image": "nginx:latest",
  "isDeployment": true,
  "deny": true,
  "nonce": "abc"
}
```

🧩 Grundgedanke

HMAC sichert Integrität und Authentizität einer Nachricht.
Aber: es schützt nicht automatisch gegen Wiederverwendung (Replay) derselben Nachricht.

payloadHash = SHA256(body)
message = payloadHash + nonce
expectedSignature = Base64Encode( HMAC-SHA256(message, secretKey) )

#
