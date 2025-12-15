# Dockerized MLOps Platform Skeleton (Airflow + MLflow + Postgres + MinIO + Jenkins)

This repo is a **platform-engineering focused MLOps skeleton** designed for the assignment:

#### Supplement repos:

1. > https://github.com/saikumarpochireddygari/platform-setup-repo-lc
2. > https://github.com/saikumarpochireddygari/cookiecutter-mlops-spoke-template/tree/main/%7B%7Bcookiecutter.project_slug%7D%7D
3. > https://github.com/saikumarpochireddygari/spoke-repo
4. > https://github.com/saikumarpochireddygari/platform-service/tree/main

## Overview
This repo provisions a **local “HUB” MLOps platform** using Docker Compose. The hub provides shared services that enable teams (spokes) to:
- Orchestrate pipelines (Airflow)
- Track experiments and register models (MLflow)
- Store metadata reliably (Postgres)
- Store artifacts in S3-compatible storage (MinIO)
- Onboard/deploy team DAGs with guardrails (Jenkins)

In a **hub–spoke** model:
- **HUB** = the shared platform runtime (this docker-compose stack).
- **SPOKE** = a team/project repo containing DAGs and a `project.json` manifest. Jenkins validates and deploys spoke DAGs into the hub’s Airflow DAGs mount.

---

## High-Level Architecture (Hub–Spoke)
### HUB (local docker environment)
- **Jenkins**: CI/CD + governance gate + spoke onboarding
- **Airflow**: orchestration runtime
- **Postgres**: metadata store for Airflow + MLflow
- **MinIO**: artifact store (S3 mock)
- **MLflow**: experiment tracking + model registry

### SPOKE (team repo)
- DAG code + project manifest (`project.json`)
- Jenkins pipeline deploys DAGs into the hub under an environment/project path


## What this platform provides

### Self-service Jobs (for Data Scientists)
- A local, reproducible MLOps stack via **Docker Compose**
- Cookie Cutter remplate for Dags & Project Configuration & sample pipeline lifecycle:
  1) ingest → 2) validate → 3) “train” → 4) register (MLflow)
- MLflow tracking 
- Airflow Orchestrator

### Platform guardrails (for Operators)
- Central metadata store (Postgres)
- Artifact store (MinIO S3-compatible)
- Structured logs persisted locally in Platform repo for now due to simplicity

### Setup the Local Docker Environment using this Repo
> https://github.com/saikumarpochireddygari/platform-setup-repo-lc

### Cookiecutter Template for Team adaptability
> https://github.com/saikumarpochireddygari/cookiecutter-mlops-spoke-template/tree/main/%7B%7Bcookiecutter.project_slug%7D%7D

### Sample Spoke Repo
> https://github.com/saikumarpochireddygari/spoke-repo

### Platform Services Repo
> https://github.com/saikumarpochireddygari/platform-service/tree/main


### Local endpoints (what you can demo)

- **Airflow UI**: `http://localhost:8080`
- **MLflow UI**: `http://localhost:5001`
- **MinIO Console**: `http://localhost:9001`
- **MinIO S3 endpoint**: `http://localhost:9000`
- **Jenkins**: `http://localhost:8081/jenkins`


---

---



## Architecture Local Setup
### High Level Architecture
![alt text](<architecture_images/Highlevel-Architecture.png>)

### Control Flow 
![alt text](<architecture_images/Control-Flow.png>)

### Multi Level Environment Architecture

![alt text](architecture_images/multi-env-level-architecture.png)

## Production Ready setup, Detailed Flows and Cloud architecture Darft with Deepdives for few components (WIP**)
> https://app.eraser.io/workspace/f7xIJLO4iWpWl5WHBcB8?origin=share
> #### Note This works if you create a free account. 
> ## I encourage to visit this first as the above local setup is very limited. The proper Production ready setup is being designed using an diagram tool called Eraser and I couldn't accomodate all of the design here.

#### _Few Screenshots_:
![alt text](<architecture_images/prod-ready-arch.png>)

---
---
![alt text](<architecture_images/prod-stub-services.png>)

---


## Core Design Decisions (Why each component exists Local assignment Scope only)

### 1) Postgres as the shared metadata backbone
**Decision:** Run one Postgres container and logically separate concerns.
- Airflow metadata DB: `airflow`
- MLflow backend store DB: `mlflow` (created by `postgres-mlflow-init`)

**Why:** Mirrors production setups where metadata is centralized but isolated by system for ownership, migrations, and governance.

---

### 2) MinIO as artifact storage + bucket bootstrap
**Decision:** Use MinIO as an S3-compatible artifact store and create required buckets at bootstrap time.
- `minio` runs the object store
- `minio-init` runs once and creates `mlflow-artifacts`

**Why:** Artifact persistence is required for reproducibility (models, metrics, plots, serialized outputs). Creating the bucket early prevents runtime failures when MLflow first logs artifacts.

**Compose note:** `minio/mc` behaves differently than a typical shell image; using:
- `entrypoint: ["/bin/sh"]`
- `command: ["-ec", "..."]`
is the reliable way to run init scripting.

---

### 3) MLflow storage split: metadata vs artifacts
**Decision:** Split MLflow storage responsibilities:
- **Backend store** → Postgres (`MLFLOW_BACKEND_STORE_URI`)
- **Artifacts** → MinIO (`MLFLOW_DEFAULT_ARTIFACT_ROOT=s3://mlflow-artifacts` + `MLFLOW_S3_ENDPOINT_URL=http://minio:9000`)

**Why:** This matches production patterns (RDS/Aurora + S3). Postgres stores run metadata; object storage holds binaries/artifacts.

---

### 4) Init-jobs pattern for deterministic bootstrapping
**Decision:** Use one-time “init services” that run and exit successfully:
- `postgres-mlflow-init`: create `mlflow` DB if missing
- `minio-init`: create required buckets if missing
- `mlflow-db-init`: initialize MLflow SQL schema

**Why:** Makes the environment reproducible and avoids race conditions.

**How enforced:** `depends_on` with conditions:
- `service_healthy` for Postgres readiness
- `service_completed_successfully` for init jobs

---

### 5) Airflow as orchestration layer (platform demo)
**Decision:** Run Airflow with `LocalExecutor` for a local skeleton.
- `airflow-init` migrates DB and creates an admin user
- `airflow-webserver` + `airflow-scheduler` run the orchestration runtime

**Why:** Demonstrates the full lifecycle: ingest → validate → train → register, while staying lightweight locally. In production, this evolves to Celery/KubernetesExecutor.

---

### 6) Jenkins as the “control plane” for hub–spoke onboarding
**Decision:** Jenkins represents the enterprise CI/CD and governance entry point:
- Validates spoke repo structure (`project.json`, DAG layout)
- Performs mock authorization checks (`authz.py`)
- Deploys DAGs into the shared Airflow DAGs mount (via a host/container bind mount)

**Why:** Demonstrates:
- self-service onboarding
- consistent validation/guardrails
- an audit trail in build logs (who deployed what, when)

---

## Hub–Spoke Workflow (Conceptual)
1. Team pushes DAGs + manifest to a **spoke repo**.
2. Jenkins pipeline is triggered with:
   - `USER_REPO_URL`, `USER_REPO_BRANCH`
   - `ENV` (dev/stage/prod)
   - `TRIGGERING_USER`
3. Jenkins:
   - AuthZ check (mock)
   - Validates `project.json` + DAG structure
   - Copies DAGs into: `/workspace/airflow/dags/<env>/<project>`
4. Airflow discovers DAGs and runs them.
5. DAG tasks log runs/models to MLflow; artifacts are written to MinIO.

---

## Environment Separation (dev/stage/prod)
**Decision (current skeleton):** Use path-based separation for deployed DAGs:
- `/workspace/airflow/dags/dev/<project>`
- `/workspace/airflow/dags/stage/<project>`
- `/workspace/airflow/dags/prod/<project>`

**Why:** Demonstrates multi-env separation without multiplying containers.

**Production evolution:** isolate further by:
- separate Postgres instances/schemas per env
- separate buckets/prefixes per env
- separate MLflow servers per env
- IAM roles + network boundaries per env

---

## Governance & Guardrails (Simulated)
This skeleton demonstrates where governance would be enforced:
- **Run ownership**: Jenkins captures `TRIGGERING_USER` (owner)
- **Policy hooks**: structural validation before deployment
- **Audit trail**: Jenkins job logs for deployments
- **Promotion stub**: extend to MLflow model stages (None → Staging → Production) gated by scripts
- **Airflow**: structured JSON logging for tasks Check Airflow Audit Logs
---

## Observability & Scaling (Minimal by design)
**Current:** Docker logs + service UIs (Jenkins, Airflow).

**Planned extensions (assignment narrative):**
- Prometheus + Grafana (metrics)
- drift checks as scheduled DAGs -- Completed
## Visit the Deepdive URL To Check for production ready setup with all of the components.
---
 > https://app.eraser.io/workspace/f7xIJLO4iWpWl5WHBcB8?origin=share