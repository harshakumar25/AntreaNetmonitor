#!/bin/bash

# Deploy Network Monitor to Kubernetes with Antrea Integration
# This script sets up the complete monitoring system

set -e

NAMESPACE="${NAMESPACE:-default}"
REGISTRY="${REGISTRY:-}"

echo "🚀 Deploying Network Monitor with Antrea Integration..."
echo "   Namespace: $NAMESPACE"

# Check if Antrea is installed
echo "🔍 Checking Antrea installation..."
if kubectl get pods -n kube-system -l app=antrea | grep -q antrea; then
    echo "✅ Antrea is installed"
else
    echo "⚠️  Antrea not detected. Install Antrea first or use mock mode."
    echo "   To install Antrea: kubectl apply -f https://github.com/antrea-io/antrea/releases/latest/download/antrea.yml"
fi

# Check if Flow Aggregator is installed (optional)
echo "🔍 Checking Flow Aggregator..."
if kubectl get namespace flow-aggregator &>/dev/null; then
    echo "✅ Flow Aggregator namespace found"
else
    echo "⚠️  Flow Aggregator not installed (optional for advanced metrics)"
    echo "   See: https://antrea.io/docs/v1.7.0/docs/network-flow-visibility/"
fi

# Build images (if not using pre-built)
if [ -z "$REGISTRY" ]; then
    echo "📦 Building Docker images locally..."
    
    # Build backend
    echo "   Building backend..."
    docker build -t network-monitor-backend:latest ./backend
    
    # Build frontend
    echo "   Building frontend..."
    docker build -t network-monitor-frontend:latest ./frontend
    
    # If using kind, load images
    if command -v kind &>/dev/null && kind get clusters 2>/dev/null | grep -q .; then
        echo "📤 Loading images into kind cluster..."
        kind load docker-image network-monitor-backend:latest
        kind load docker-image network-monitor-frontend:latest
    fi
else
    echo "📤 Using registry: $REGISTRY"
    docker tag network-monitor-backend:latest $REGISTRY/network-monitor-backend:latest
    docker tag network-monitor-frontend:latest $REGISTRY/network-monitor-frontend:latest
    docker push $REGISTRY/network-monitor-backend:latest
    docker push $REGISTRY/network-monitor-frontend:latest
fi

# Apply Kubernetes manifests
echo "📋 Applying Kubernetes manifests..."

# RBAC first (for Antrea access)
kubectl apply -f k8s/rbac.yaml
echo "   ✅ RBAC configured"

# ConfigMaps and Secrets
kubectl apply -f k8s/configmap.yaml
echo "   ✅ ConfigMaps applied"

# Deployments
kubectl apply -f k8s/deployment.yaml
echo "   ✅ Deployments created"

# Services
kubectl apply -f k8s/service.yaml
echo "   ✅ Services created"

# HPA (optional)
kubectl apply -f k8s/hpa.yaml 2>/dev/null || echo "   ⚠️  HPA skipped (metrics-server may not be installed)"

# Network Policy
kubectl apply -f k8s/network-policy.yaml 2>/dev/null || echo "   ⚠️  NetworkPolicy skipped"

# Wait for rollout
echo "⏳ Waiting for deployments to be ready..."
kubectl rollout status deployment/network-monitor-backend -n $NAMESPACE --timeout=120s
kubectl rollout status deployment/network-monitor-frontend -n $NAMESPACE --timeout=120s

# Get service info
echo ""
echo "🎉 Deployment complete!"
echo ""
echo "📊 Access the dashboard:"

# Check for LoadBalancer IP
LB_IP=$(kubectl get svc network-monitor-lb -n $NAMESPACE -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null)
if [ -n "$LB_IP" ]; then
    echo "   LoadBalancer: http://$LB_IP"
else
    echo "   Port-forward: kubectl port-forward svc/network-monitor-frontend 3000:80"
    echo "   Then open: http://localhost:3000"
fi

echo ""
echo "🔧 To check logs:"
echo "   kubectl logs -l app=network-monitor,component=backend -f"
echo ""
echo "📈 Capture mode: ANTREA (real packet data)"
echo "   Make sure pods have network activity to see real traffic!"
