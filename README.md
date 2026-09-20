#  NyxVault: Adaptive AI Deception System for Banking Threat Detection
> **Built for the AWS BuildTour Hackathon**

[![AWS Amplify](https://img.shields.io/badge/AWS-Amplify%20Gen%202-FF9900?logo=aws-amplify&logoColor=white)](https://aws.amazon.com/amplify/)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/Frontend-React%2018%20%2B%20TypeScript-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![Neo4j](https://img.shields.io/badge/Database-Neo4j%20AuraDB-008CC1?logo=neo4j&logoColor=white)](https://neo4j.com/cloud/platform/aura-graph-database/)
[![Scikit-Learn](https://img.shields.io/badge/ML-Isolation%20Forest-F7931E?logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)

---

##  Executive Summary

**NyxVault** is a next-generation, AI-driven cyber deception and threat detection platform built for financial institutions. Modern advanced persistent threats (APTs) and insider attackers evade perimeter defenses by quietly hopping across banking infrastructure. 

NyxVault solves this by transforming the bank's digital topology into an active, deceptive minefield:
1. **Cognitive Honeytokens**: Injects decoy clearing accounts, administrative API endpoints, and executive credentials into the banking graph.
2. **Polymorphic Adaptation**: An automated mutation engine periodically rotates decoy parameters, preventing attackers from mapping the deception layer.
3. **Graph Intelligence & Lateral Movement Prediction**: Leverages Neo4j and NetworkX (Dijkstra shortest-path & PageRank) to predict an attacker's lateral movement toward critical assets.
4. **Unsupervised Behavioral Anomaly Detection**: Employs Scikit-learn's `IsolationForest` to identify behavioral outliers across transaction velocities and access spikes.
5. **Explainable AI (XAI) Threat Dossiers**: Translates raw graph centrality metrics, isolation scores, and blast radii into plain-English incident summaries and defensive playbooks.

---

##  Cloud Architecture & AWS Integration

### Why AWS Amplify (Gen 2)?
> **Hackathon Architecture Note**:  
> In our AWS hackathon sandbox environment, traditional container services (Amazon ECR and Amazon ECS Fargate) encountered restrictive organizational Service Control Policies (SCPs) that prohibited container registry and VPC resource provisioning. 
>
> To ensure seamless cloud delivery, we integrated **AWS Amplify (Gen 2)**:
> - **Full-Stack Serverless Backend**: Powered by Amplify's code-first TypeScript constructs (`amplify/backend.ts` and `amplify/my-first-function`).
> - **Instant CI/CD**: Automatic build and deployment triggered on git pushes to the repository.
> - **Zero-Config Hosting**: Hosts the responsive React + Vite SOC dashboard globally on AWS's edge CDN.

```text
                               ┌───────────────────────────┐
                               │   AWS Amplify (Gen 2)     │
                               │   CI/CD + Cloud Functions │
                               └─────────────┬─────────────┘
                                             │
                       ┌─────────────────────┴─────────────────────┐
                       ▼                                           ▼
             ┌───────────────────┐                       ┌───────────────────┐
             │  React Frontend   │                       │ Amplify Functions │
             │  Vite + Cytoscape │                       │ (Serverless API)  │
             └─────────┬─────────┘                       └───────────────────┘
                       │ REST / WebSockets
                       ▼
             ┌───────────────────┐
             │  FastAPI Backend  │
             │  Analytics Engine │
             └─────────┬─────────┘
                       │
         ┌─────────────┴─────────────┐
         ▼                           ▼
┌──────────────────┐       ┌──────────────────┐
│   Neo4j AuraDB   │       │ Scikit-Learn ML  │
│  (Graph Topology)│       │(Isolation Forest)│
└──────────────────┘       └──────────────────┘
```

---

##  Project Structure

```text
nyxvault/
├── amplify/                        # AWS Amplify Gen 2 Cloud Backend
│   ├── backend.ts                  # Amplify backend definition & function registration
│   ├── tsconfig.json               # TypeScript configuration for Amplify
│   └── my-first-function/          # Serverless cloud function
│       ├── resource.ts             # Function resource definition
│       └── handler.ts              # Event handler logic
├── amplify.yml                     # AWS Amplify CI/CD build specification
│
├── backend/                        # FastAPI Python Analytics Engine
│   ├── main.py                     # API entry point & WebSocket event stream
│   ├── config.py                   # Pydantic configuration loader
│   ├── requirements.txt            # Python dependencies
│   ├── Dockerfile                  # Container definition
│   ├── api/                        # REST endpoint routers (graph, honeytokens, risk, simulation, stats)
│   ├── models/schemas.py           # Pydantic schemas & response validation
│   ├── services/
│   │   ├── anomaly_detector.py     # Isolation Forest behavioral anomaly detection
│   │   ├── attack_path.py          # Lateral movement Dijkstra path predictor
│   │   ├── blast_radius.py         # Subgraph financial exposure calculator
│   │   ├── explainer.py            # Explainable AI (XAI) risk narrator
│   │   ├── fraud_ring.py           # Strongly Connected Components fraud ring detector
│   │   ├── generator.py            # Synthetic banking ecosystem seeder
│   │   ├── mutator.py              # Dynamic honeytoken mutation engine
│   │   ├── neo4j_client.py         # Neo4j AuraDB connection pool
│   │   ├── simulator.py            # Threat simulation generator
│   │   └── threat_scorer.py        # Composite PageRank + Anomaly threat scoring
│   └── tests/                      # Automated unit test suite
│
└── frontend/                       # React 18 + TypeScript SOC Dashboard
    ├── src/
    │   ├── components/Sidebar.tsx  # Navigation with live threat alerts badge
    │   ├── pages/
    │   │   ├── Overview.tsx        # Executive dashboard & What-If attack simulator
    │   │   ├── GraphExplorer.tsx   # Interactive Cytoscape graph & XAI inspection drawer
    │   │   ├── ThreatCenter.tsx    # Live telemetry feed & incident audit log
    │   │   └── MutationActivity.tsx# Polymorphic honeytoken rotation logs
    │   └── services/
    │       ├── api.ts              # REST client with dynamic cloud URL support
    │       └── websocket.ts        # Live event streaming hook
    ├── package.json
    └── vite.config.ts
```

---

##  Quickstart & Local Execution

### 1. Prerequisites
- **Python 3.11+**
- **Node.js 18+** & **npm**
- Active **Neo4j AuraDB** cloud instance

### 2. Backend Setup
```powershell
cd backend

# 1. Install dependencies
pip install -r requirements.txt

# 2. Configure environment variables (create backend/.env)
# NEO4J_URI=neo4j+s://<INSTANCE_ID>.databases.neo4j.io
# NEO4J_USERNAME=<USERNAME>
# NEO4J_PASSWORD=<PASSWORD>

# 3. Seed synthetic banking graph & honeytokens
python -m services.generator

# 4. Start the FastAPI server
uvicorn main:app --reload --port 8000
```
* Interactive API Docs: [http://localhost:8000/docs](http://localhost:8000/docs)
* Health Check: [http://localhost:8000/health](http://localhost:8000/health)

### 3. Frontend Setup
```powershell
cd frontend

# 1. Install dependencies
npm install

# 2. Launch Vite dev server
npm run dev
```
* Web Dashboard: [http://localhost:5173](http://localhost:5173)



## 👥 Team & Submission
* **Event**: AWS BuildTour Hackathon
* **Project**: NyxVault 
* **Repository**: [https://github.com/Prakruthi-codes/Nyxvault.git](https://github.com/Prakruthi-codes/Nyxvault.git)
