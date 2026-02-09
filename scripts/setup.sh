#!/bin/bash

# Network Monitor - Development Setup Script
# This script sets up the development environment

set -e

echo "🚀 Setting up Network Monitor development environment..."

# Check prerequisites
check_prerequisites() {
    echo "📋 Checking prerequisites..."
    
    if ! command -v go &> /dev/null; then
        echo "❌ Go is not installed. Please install Go 1.21+"
        exit 1
    fi
    
    if ! command -v node &> /dev/null; then
        echo "❌ Node.js is not installed. Please install Node.js 20+"
        exit 1
    fi
    
    if ! command -v docker &> /dev/null; then
        echo "⚠️  Docker is not installed. Docker Compose won't work."
    fi
    
    echo "✅ Prerequisites check passed!"
}

# Setup backend
setup_backend() {
    echo "🔧 Setting up Go backend..."
    cd backend
    go mod download
    go mod tidy
    cd ..
    echo "✅ Backend setup complete!"
}

# Setup frontend
setup_frontend() {
    echo "🎨 Setting up React frontend..."
    cd frontend
    npm install
    cd ..
    echo "✅ Frontend setup complete!"
}

# Create necessary directories
create_directories() {
    echo "📁 Creating directories..."
    mkdir -p prometheus grafana/provisioning/dashboards grafana/provisioning/datasources
    echo "✅ Directories created!"
}

# Main
main() {
    check_prerequisites
    create_directories
    setup_backend
    setup_frontend
    
    echo ""
    echo "🎉 Setup complete! You can now run:"
    echo ""
    echo "   Docker Compose:  docker-compose up -d"
    echo ""
    echo "   Or manually:"
    echo "   - Backend:  cd backend && go run cmd/server/main.go"
    echo "   - Frontend: cd frontend && npm run dev"
    echo ""
    echo "   Access the app at http://localhost:3000"
}

main "$@"
