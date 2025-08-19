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
      - [ ] Test: http Anfragen werden abgeleht
      - [ ] Wie kann ich es noch testen oder reicht es aus?
    - [ ] Hash über Body-Request und Nonce im Payload eines Requests für Replay-Schutz
      - [ ] Nonce kommt vom policy-agent mit einer intialen GET Anfrage
      - [ ] Tolleranzfenster von +- 30 bis 120 Sekunden (dann wird Nonce ungültig)
      - [ ] Was ist mit Timestamp statt Hash? Problem: Zeitverschiebung **Problematisch daher lieber Challenge-Response mit Nonce und Hash vom Server**
            → keine Zeitprobleme. Aber: 2-Request-Workflow → höhere Latenz.
      - [ ] Client fragt zuerst `GET /nonce` an.
      - [ ] Server erstellt einmalige Nonce + Ablaufzeit und merkt sich diese.
      - [ ] Client sendet diese Nonce im Request mit.
    - [ ] Payload-Signatur für inhaltliche Authentizität (Hash über Request-Body)
    - [ ] mTLS + Zertifikat + Policy Check für Identität und Autorisierung
  - [ ] Signierte Policy-Requests
    - Der Client (z. B. ein attestierter Pod) signiert die Payload (z. B. mit einem Key aus dem TEE oder KBS/Trustee).
    - Der Server (policy-agent) prüft die Signatur mit einem bekannten Public Key.
      - **Zusätzlich zu Hash über Request-Body oder kann das den Hash ersezten? Problem: nur Clients die in TEE laufen können einen Request erstellen?**
    - Der Server validiert:
      - Nonce ist einzigartig (verhindert Replay & TOCTOU)
      - Signatur ist gültig
  - [ ] Replay Angriffe mit Nonce verhindern => es müssen kürzlich verwendete Nonces zwischengespeichert werden und doppelte oder zu alte Anfragen ablehnen
    - [ ] Wie lange / wie viele Noncen werden zwischengespeichert?
    - [ ] Redis DB mit expiration. Wenn eine nonce verwendet wird, wird sie sofort gelöscht oder liber mit flag als `used` kennzeichnen? **Kann es race-condition geben, wenn die nonce gelöscht wird? (während eine nonce gelöscht wird, kommt eine neue Anfrage)**

### Ablauf – Challenge-Response mit Nonce

1. Client holt Nonce mit GET-Request

```zsh
curl -k https://policy-agent:8443/nonce
# Antwort: {"nonce":"abc123..."}
```

Server erstellt zufällige Nonce, speichert sie temporär mit kurzer Ablaufzeit (z. B. 30 Sekunden) und gibt sie zurück. 2. Client sendet POST-Request + Nonce

```zsh
curl -k -X POST https://policy-agent:8443/patch \
    -H "Content-Type: application/json" \
    -d '{"nonce":"abc123...", "target":"my-deployment", ... }'

```

3. Server prüft:

- Nonce existiert noch.
- Nonce ist nicht abgelaufen.
- Nonce wurde noch nicht benutzt (One-Time-Use).

3. Server löscht Nonce nach erfolgreicher Validierung → Replay unmöglich.

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

`sha256sum body.json`

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
