# Antrea NetMonitor - Deployment Guide

## 🚀 Quick Start (Local Development)

### 1. Start Backend (Mock Mode)
```bash
cd backend
CAPTURE_MODE=mock go run cmd/server/main.go
```

### 2. Start Frontend
```bash
cd frontend
npm run dev
```

### 3. Access Dashboard
Open http://localhost:5173 in your browser

---

## 🌐 Kubernetes Deployment with Real Antrea Integration

### Prerequisites
- Kubernetes cluster with Antrea CNI installed
- `kubectl` configured to access your cluster
- Docker for building images

### Step 1: Build Docker Images

```bash
# Build backend image
cd backend
docker build -t network-monitor-backend:latest .

# Build frontend image
cd ../frontend
docker build -t network-monitor-frontend:latest .
```

### Step 2: Push to Container Registry (if using remote cluster)

```bash
# Tag for your registry
docker tag network-monitor-backend:latest your-registry.io/network-monitor-backend:latest
docker tag network-monitor-frontend:latest your-registry.io/network-monitor-frontend:latest

# Push
docker push your-registry.io/network-monitor-backend:latest
docker push your-registry.io/network-monitor-frontend:latest
```

### Step 3: Deploy RBAC for Antrea Access

```bash
kubectl apply -f k8s/rbac.yaml
```

This creates:
- `ServiceAccount`: network-monitor
- `ClusterRole`: network-monitor-role (access to Antrea CRDs)
- `ClusterRoleBinding`: Binds the role to the service account

### Step 4: Deploy Application

```bash
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
```

### Step 5: (Optional) Deploy Antrea Flow Aggregator

For enhanced flow data collection:
```bash
kubectl apply -f k8s/antrea-flow-aggregator.yaml
```

### Step 6: Verify Deployment

```bash
# Check pods are running
kubectl get pods -l app=network-monitor

# Check logs
kubectl logs -l app=network-monitor -c backend

# Port forward to access locally
kubectl port-forward svc/network-monitor 8080:80
```

---

## 📊 Capture Modes

### Mock Mode (Development)
```bash
CAPTURE_MODE=mock go run cmd/server/main.go
```
- Generates simulated network traffic
- No Kubernetes/Antrea required
- Great for UI development and testing

### Antrea Mode (Production)
```bash
CAPTURE_MODE=antrea go run cmd/server/main.go
```
- Captures real network traffic from Antrea
- Requires running inside Kubernetes cluster
- Uses:
  - `antctl trace` for packet tracing
  - Flow Exporter for IPFIX data
  - PacketCapture CRDs for deep inspection

---

## 🔧 Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CAPTURE_MODE` | `mock` | `mock` or `antrea` |
| `PORT` | `8080` | Backend server port |
| `ANTREA_AGENT_ADDR` | `antrea-agent.kube-system:10350` | Antrea agent address |
| `FLOW_AGGREGATOR_ADDR` | `flow-aggregator.flow-aggregator:4739` | Flow aggregator address |

---

## 🛡️ Antrea Features Used

### 1. PacketCapture CRD
Captures packets matching specific criteria:
```yaml
apiVersion: crd.antrea.io/v1alpha1
kind: PacketCapture
metadata:
  name: network-monitor-capture
spec:
  source:
    pod:
      namespace: default
  destination:
    ip: 0.0.0.0/0
  packet:
    protocol: TCP
```

### 2. Traceflow
Traces packet path through the cluster:
```bash
antctl traceflow -S pod/nginx -D pod/backend -f tcp,80
```

### 3. Flow Exporter (IPFIX)
Exports flow records for traffic analysis:
- Connection tracking
- Bandwidth metrics
- Protocol distribution

---

## ☁️ Render Deployment (Recommended Free Tier)

This deploys the **backend (Go API)** on Render. The **frontend** is created as a Static Site directly in Render.

### 1. Push repository to GitHub
Render connects to your GitHub repo.

### 2. Create backend from render.yaml
In Render Dashboard:
- New → **Blueprint** → select your repo
- Render will detect [render.yaml](render.yaml) and create:
  - `antrea-netmonitor-backend`

### 3. Create frontend as Static Site
In Render Dashboard:
- New → **Static Site** → select your repo
- Root Directory: `frontend`
- Build Command: `npm install && npm run build`
- Publish Directory: `dist`

### 4. Set frontend API URL
After the backend is created, copy its public URL and update the frontend env:

- Render → `antrea-netmonitor-frontend` → Environment
- Set:
  - `VITE_API_URL=https://YOUR-BACKEND.onrender.com`
- Trigger a redeploy

### 5. Verify
- Backend: `https://YOUR-BACKEND.onrender.com/health`
- Frontend: `https://YOUR-FRONTEND.onrender.com`

> Note: Free Render services may sleep when idle. First request can be slower.

---

## 📈 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/api/v1/stats/live` | GET | Current traffic statistics |
| `/api/v1/stats/historical` | GET | Historical traffic data |
| `/api/v1/connections` | GET | Active connections |
| `/api/v1/alerts` | GET | Security alerts |
| `/api/v1/topology` | GET | Network topology |
| `/ws/stream` | WebSocket | Live packet stream |
| `/ws/stats` | WebSocket | Live stats stream |

---

## 🐛 Troubleshooting

### Backend won't start
```bash
# Check Go modules
cd backend && go mod tidy

# Verify capture mode
echo $CAPTURE_MODE
```

### Can't connect to Antrea
```bash
# Verify Antrea is running
kubectl get pods -n kube-system | grep antrea

# Check RBAC permissions
kubectl auth can-i get packetcaptures --as=system:serviceaccount:default:network-monitor
```

### WebSocket not connecting
- Ensure proxy is configured in Vite
- Check CORS settings in backend
- Verify both services are running

---

## 📁 Project Structure

```
antrea-netmonitor/
├── backend/
│   ├── cmd/server/main.go       # Entry point
│   ├── internal/
│   │   ├── api/routes.go        # REST API
│   │   ├── capture/
│   │   │   ├── engine.go        # Mock capture
│   │   │   ├── antrea_capture.go # Real Antrea capture
│   │   │   └── factory.go       # Mode switching
│   │   └── websocket/hub.go     # WebSocket streaming
│   └── pkg/models/              # Data models
├── frontend/
│   ├── src/
│   │   ├── pages/               # Dashboard, Packets, etc.
│   │   ├── components/          # UI components
│   │   └── hooks/               # WebSocket hooks
│   └── vite.config.ts           # Proxy configuration
└── k8s/
    ├── deployment.yaml          # Kubernetes deployment
    ├── service.yaml             # Service definition
    ├── rbac.yaml                # Antrea access permissions
    └── antrea-flow-aggregator.yaml
```

---

## 🎯 Next Steps

1. **Add Authentication**: Implement JWT-based auth
2. **Persistent Storage**: Add PostgreSQL for historical data
3. **Alerting**: Integrate with PagerDuty/Slack
4. **Custom Dashboards**: Allow users to create custom views
5. **Export**: Add CSV/JSON export for reports
