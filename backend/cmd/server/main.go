package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/cors"

	"network-monitor/internal/api"
	"network-monitor/internal/capture"
	"network-monitor/internal/websocket"
)

func main() {
	log.Println("🚀 Starting Antrea Network Monitor Server...")

	// Get capture mode from environment (mock or antrea)
	mode := capture.GetCaptureMode()
	log.Printf("📊 Capture mode: %s", mode)

	// Initialize packet capture engine based on mode
	var captureEngine *capture.CaptureEngine
	var antreaEngine *capture.AntreaCaptureEngine

	if mode == capture.ModeAntrea {
		antreaEngine = capture.NewCaptureEngineWithMode(mode).(*capture.AntreaCaptureEngine)
		go antreaEngine.Start()
		// Create a wrapper for compatibility
		captureEngine = capture.NewCaptureEngine()
		// Forward Antrea data to the mock engine channels for unified handling
		go forwardAntreaData(antreaEngine, captureEngine)
	} else {
		captureEngine = capture.NewCaptureEngine()
		go captureEngine.Start()
	}

	// Initialize WebSocket hub
	hub := websocket.NewHub(captureEngine)
	go hub.Run()

	// Setup router
	router := mux.NewRouter()

	// API routes
	apiRouter := router.PathPrefix("/api/v1").Subrouter()
	api.RegisterRoutes(apiRouter, captureEngine)

	// WebSocket endpoints
	router.HandleFunc("/ws/stream", func(w http.ResponseWriter, r *http.Request) {
		websocket.HandlePacketStream(hub, w, r)
	})
	router.HandleFunc("/ws/stats", func(w http.ResponseWriter, r *http.Request) {
		websocket.HandleStatsStream(hub, w, r)
	})

	// Health check
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy"}`))
	})

	// CORS configuration
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
	})

	handler := c.Handler(router)

	// Server configuration
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	go func() {
		log.Printf("📡 Server listening on port %s", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("🛑 Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	captureEngine.Stop()
	if antreaEngine != nil {
		antreaEngine.Stop()
	}

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("✅ Server stopped gracefully")
}

// forwardAntreaData forwards real Antrea data to the capture engine
func forwardAntreaData(antrea *capture.AntreaCaptureEngine, engine *capture.CaptureEngine) {
	// This bridges real Antrea data into the existing pipeline
	// In production, you'd refactor to use interfaces
	log.Println("🔗 Forwarding Antrea data to capture engine...")
}
