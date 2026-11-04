# Secure Enterprise Document Pipeline & DLP Microservice

Upload a text document → it is scanned for sensitive data (credit cards, SSNs, emails, AWS keys) →
the sensitive values are **masked** → an **audit record** (metadata only, never raw PII) is stored in
**MongoDB** → the clean file is forwarded to a second microservice that uploads it to **Box**.

```
                     POST /api/v1/documents/scan
  client  ───────────────────────────────────────►  scanner-service  (Python / FastAPI, :8000)
                                                       │   1. validate upload
                                                       │   2. regex + Luhn DLP scan, mask PII
                                                       │   3. audit record ──────►  MongoDB
                                                       │   4. POST /upload (masked file + X-Internal-Api-Key)
                                                       ▼
                                                    box-service  (Node / TypeScript / Express, :3000)
                                                       │   uploads to Box REST API
                                                       ▼        (or an in-memory mock when BOX_MOCK_MODE=true)
                                                      Box
```

## What's in the box

```
secure-doc-pipeline/
├── docker-compose.yml          ← one-command local stack (includes MongoDB)
├── .env.example                ← optional settings (copy to .env)
├── k8s-deployment.yaml         ← Kubernetes: Deployments, Services, ConfigMap, NetworkPolicy
├── k8s/local-mongo.yaml        ← optional in-cluster MongoDB for Minikube demos
├── .github/workflows/ci-cd.yml ← lint, test, validate K8s, build images, simulated deploy
├── scanner-service/            ← Microservice 1 (Python 3.12, FastAPI, pymongo, httpx)
│   ├── main.py  Dockerfile  requirements*.txt  pytest.ini
│   └── tests/test_dlp.py
├── box-service/                ← Microservice 2 (Node 20, TypeScript, Express)
│   ├── src/index.ts  Dockerfile  package.json  package-lock.json  tsconfig.json
│   └── test/api.test.ts
├── sample-data/                ← sample.txt, customers.csv, clean.txt to try it out
└── scripts/smoke-test.sh|.ps1  ← upload a file and print the whole result
```

---

## Option A: Docker Compose (recommended, ~2 minutes)

**You need:** [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Windows / macOS) or Docker Engine + Compose plugin (Linux). Nothing else — no Box or MongoDB account.

```bash
cd secure-doc-pipeline
docker compose up --build
```

Wait until you see `box_service_listening` and `mongodb_ready` in the logs. Then, in a **second terminal**:

**macOS / Linux / Git Bash**
```bash
./scripts/smoke-test.sh                          # sample-data/sample.txt
./scripts/smoke-test.sh sample-data/customers.csv
```

**Windows PowerShell**
```powershell
.\scripts\smoke-test.ps1
.\scripts\smoke-test.ps1 -File sample-data\customers.csv
```

**Or by hand with curl** (on Windows PowerShell use `curl.exe`, not `curl`):
```bash
curl -F "file=@sample-data/sample.txt" http://localhost:8000/api/v1/documents/scan
```

You will see the masked output that "Box" received:

```
Email: j***@example.com
Card:  ****-****-****-1111
SSN:   ***-**-6789
AWS key found in config: [REDACTED_AWS_KEY]
```

You can also use the interactive API docs at **http://localhost:8000/docs** (upload a file from the browser).

Stop everything: `Ctrl+C`, then `docker compose down` (add `-v` to also delete the MongoDB data).

### Use real Box instead of the mock
1. Create a free account at <https://developer.box.com>, create a **Custom App** (Server Authentication), and on the app's *Configuration* tab click **Generate Developer Token** (valid 60 minutes).
2. `cp .env.example .env` and set:
   ```
   BOX_MOCK_MODE=false
   BOX_DEVELOPER_TOKEN=<paste token>
   ```
3. `docker compose up --build` — files now appear in your Box sandbox (root folder `0`, or set `BOX_PARENT_FOLDER_ID`).

For a long-running setup use Client Credentials Grant instead: set `BOX_CLIENT_ID`, `BOX_CLIENT_SECRET`, `BOX_ENTERPRISE_ID` (and authorize the app in the Box admin console).

### Use MongoDB Atlas instead of the local container
Set `MONGODB_URI=mongodb+srv://<user>:<password>@<cluster>.mongodb.net/?retryWrites=true&w=majority` in `.env`
(Atlas free M0 cluster; add your IP under *Network Access*). The bundled `mongo` container is then simply unused.

---

## Option B: Run without Docker

**You need:** Python 3.12+, Node 20+, and a MongoDB (free Atlas URI, or any local `mongod`).

**Terminal 1: box-service**
```bash
cd box-service
npm install
INTERNAL_API_KEY=devkey BOX_MOCK_MODE=true npm run dev
```
PowerShell: `$env:INTERNAL_API_KEY="devkey"; $env:BOX_MOCK_MODE="true"; npm run dev`

**Terminal 2: scanner-service**
```bash
cd scanner-service
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt
MONGODB_URI='mongodb://localhost:27017' INTERNAL_API_KEY=devkey \
BOX_SERVICE_URL=http://localhost:3000 uvicorn main:app --port 8000
```
PowerShell: set `$env:MONGODB_URI`, `$env:INTERNAL_API_KEY`, `$env:BOX_SERVICE_URL` first, then run `uvicorn main:app --port 8000`.

**Terminal 3:** `INTERNAL_API_KEY=devkey ./scripts/smoke-test.sh`

---

## Option C: Kubernetes with Minikube

**You need:** Docker, [Minikube](https://minikube.sigs.k8s.io/docs/start/), `kubectl`.

```bash
# 1. Start a cluster and build images *inside* it (no registry needed)
minikube start --driver=docker --cpus=2 --memory=3g
eval $(minikube docker-env)          # PowerShell: & minikube -p minikube docker-env --shell powershell | Invoke-Expression
docker build -t scanner-service:local ./scanner-service
docker build -t box-service:local     ./box-service

# 2. Namespace + secrets (BOX_MOCK_MODE is "true" in the ConfigMap, so no Box token needed)
kubectl create namespace doc-pipeline --dry-run=client -o yaml | kubectl apply -f -
kubectl -n doc-pipeline create secret generic pipeline-secrets \
  --from-literal=MONGODB_URI='mongodb://mongo:27017' \
  --from-literal=INTERNAL_API_KEY='minikube-demo-key'

# 3. Deploy a throwaway in-cluster MongoDB + both services
kubectl apply -f k8s/local-mongo.yaml
kubectl apply -f k8s-deployment.yaml
kubectl -n doc-pipeline scale deploy/box-service --replicas=1   # mock files live in pod memory
kubectl -n doc-pipeline rollout status deploy/scanner-service
kubectl -n doc-pipeline get pods,svc

# 4. Reach the services from your machine (keep these running, one terminal each)
kubectl -n doc-pipeline port-forward svc/scanner-service 8000:8000
kubectl -n doc-pipeline port-forward svc/box-service 3000:3000

# 5. Test
INTERNAL_API_KEY=minikube-demo-key ./scripts/smoke-test.sh
```

Inside the cluster the scanner reaches Box service at `http://box-service:3000` (a ClusterIP Service), and a NetworkPolicy lets only scanner pods call it.
Using Atlas instead of the local Mongo: skip `local-mongo.yaml` and put your `mongodb+srv://…` URI in the `MONGODB_URI` secret.
Using real Box: set `BOX_MOCK_MODE: "false"` in the ConfigMap and add `BOX_DEVELOPER_TOKEN` (or the CCG trio) to the secret, then `kubectl -n doc-pipeline rollout restart deploy/box-service`.

Cleanup: `minikube delete`.

---

## Run the tests

```bash
# Python (ruff lint + 13 tests, no MongoDB needed)
cd scanner-service && pip install -r requirements.txt -r requirements-dev.txt
ruff check . && python -m pytest -v

# TypeScript (typecheck + 9 tests, no Box account needed)
cd box-service && npm install && npm run lint && npm test
```

## API reference

| Service | Endpoint | Purpose |
|---|---|---|
| scanner `:8000` | `POST /api/v1/documents/scan` | multipart field `file` (`.txt .csv .json .md .log`, UTF-8, ≤ 5 MB). Returns `scan_id`, `decision` (`clean` / `masked`), per-type `findings`, Box result |
| scanner | `GET /api/v1/scans/{scan_id}` | audit record (counts + SHA-256, never raw PII) |
| scanner | `GET /health`, `GET /ready` | liveness / readiness (ready checks MongoDB) |
| box `:3000` | `POST /upload` | internal; requires `X-Internal-Api-Key`, fields `file` + `scan_id` (UUID) |
| box | `GET /mock/files/{id}` | mock mode only: read back what "Box" received |

Status codes: `200` ok · `401` bad API key · `413` too large · `415` bad type/encoding · `422` blocked by policy · `502` Box service failed · `503` audit log (MongoDB) unavailable.

**Policy switch:** `DLP_BLOCK_ON_FINDINGS=true` rejects any file that contains PII (HTTP 422) instead of masking and forwarding it.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `port is already allocated` | Something uses 8000/3000/27017. Stop it, or change the left-hand port in `docker-compose.yml`. |
| Scanner `/ready` returns 503 | MongoDB unreachable. With Compose, wait for the `mongo` healthcheck; with Atlas, allow your IP under *Network Access* and check user/password. |
| Upload returns `502 Upstream failure` | `INTERNAL_API_KEY` differs between the two services, or (real Box) the token expired. See `docker compose logs box-service`. |
| `FATAL: INTERNAL_API_KEY is required` | Set it for box-service (Compose provides a default). |
| `Box auth not configured` | Either `BOX_MOCK_MODE=true`, or provide a developer token / CCG credentials. |
| Box returns `item_name_in_use` | Not possible by design: file names are prefixed with the scan id. |
| `ImagePullBackOff` in Minikube | You built images outside Minikube's Docker. Re-run `eval $(minikube docker-env)` and rebuild. |
| Windows: `./scripts/smoke-test.sh` fails | Use `.\scripts\smoke-test.ps1`, or run the .sh in Git Bash / WSL. |
| Windows: curl prints PowerShell errors | Use `curl.exe` (PowerShell's `curl` is an alias for something else). |

## Design notes

- **No raw PII is persisted anywhere.** MongoDB stores counts per type, a SHA-256 of the original file and status only.
- **The audit log fails closed**: if MongoDB can't be written, the file is not forwarded (HTTP 503).
- **Luhn validation** keeps random 13–19 digit numbers from being treated as cards; SSN rules exclude invalid areas (000, 666, 9xx).
- **Service-to-service auth** via a shared key compared in constant time; stored in a Kubernetes Secret.
- **Container hardening:** multi-stage builds, non-root users, read-only root filesystem, all Linux capabilities dropped, resource limits, NetworkPolicy.
- **Scope:** text-based files only. PDF/Office support would add a text-extraction step (natural next step). Regex DLP is rule-based and will not catch every format of sensitive data.
