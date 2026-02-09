package websocket

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"network-monitor/internal/capture"
	"network-monitor/pkg/models"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins for development
	},
}

// Client represents a connected WebSocket client
type Client struct {
	hub      *Hub
	conn     *websocket.Conn
	send     chan []byte
	streamType string // "packets" or "stats"
}

// Hub maintains the set of active clients and broadcasts messages
type Hub struct {
	packetClients map[*Client]bool
	statsClients  map[*Client]bool
	register      chan *Client
	unregister    chan *Client
	capture       *capture.CaptureEngine
	mu            sync.RWMutex
}

// NewHub creates a new WebSocket hub
func NewHub(captureEngine *capture.CaptureEngine) *Hub {
	return &Hub{
		packetClients: make(map[*Client]bool),
		statsClients:  make(map[*Client]bool),
		register:      make(chan *Client),
		unregister:    make(chan *Client),
		capture:       captureEngine,
	}
}

// Run starts the hub's main loop
func (h *Hub) Run() {
	// Handle client registration/unregistration
	go func() {
		for {
			select {
			case client := <-h.register:
				h.mu.Lock()
				if client.streamType == "packets" {
					h.packetClients[client] = true
				} else {
					h.statsClients[client] = true
				}
				h.mu.Unlock()
				log.Printf("Client connected: %s stream", client.streamType)

			case client := <-h.unregister:
				h.mu.Lock()
				if client.streamType == "packets" {
					if _, ok := h.packetClients[client]; ok {
						delete(h.packetClients, client)
						close(client.send)
					}
				} else {
					if _, ok := h.statsClients[client]; ok {
						delete(h.statsClients, client)
						close(client.send)
					}
				}
				h.mu.Unlock()
				log.Printf("Client disconnected: %s stream", client.streamType)
			}
		}
	}()

	// Broadcast packets to packet clients
	go func() {
		for packet := range h.capture.GetPacketChannel() {
			msg := models.WebSocketMessage{
				Type:      "packet",
				Timestamp: time.Now(),
				Data:      packet,
			}
			data, err := json.Marshal(msg)
			if err != nil {
				continue
			}

			h.mu.RLock()
			for client := range h.packetClients {
				select {
				case client.send <- data:
				default:
					// Client is slow, skip this message
				}
			}
			h.mu.RUnlock()
		}
	}()

	// Broadcast stats to stats clients
	go func() {
		for stats := range h.capture.GetStatsChannel() {
			msg := models.WebSocketMessage{
				Type:      "stats",
				Timestamp: time.Now(),
				Data:      stats,
			}
			data, err := json.Marshal(msg)
			if err != nil {
				continue
			}

			h.mu.RLock()
			for client := range h.statsClients {
				select {
				case client.send <- data:
				default:
				}
			}
			h.mu.RUnlock()
		}
	}()

	// Broadcast alerts to all clients
	go func() {
		for alert := range h.capture.GetAlertsChannel() {
			msg := models.WebSocketMessage{
				Type:      "alert",
				Timestamp: time.Now(),
				Data:      alert,
			}
			data, err := json.Marshal(msg)
			if err != nil {
				continue
			}

			h.mu.RLock()
			for client := range h.packetClients {
				select {
				case client.send <- data:
				default:
				}
			}
			for client := range h.statsClients {
				select {
				case client.send <- data:
				default:
				}
			}
			h.mu.RUnlock()
		}
	}()
}

// HandlePacketStream handles WebSocket connections for packet streaming
func HandlePacketStream(hub *Hub, w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}

	client := &Client{
		hub:        hub,
		conn:       conn,
		send:       make(chan []byte, 256),
		streamType: "packets",
	}

	hub.register <- client

	go client.writePump()
	go client.readPump()
}

// HandleStatsStream handles WebSocket connections for stats streaming
func HandleStatsStream(hub *Hub, w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}

	client := &Client{
		hub:        hub,
		conn:       conn,
		send:       make(chan []byte, 256),
		streamType: "stats",
	}

	hub.register <- client

	go client.writePump()
	go client.readPump()
}

// writePump pumps messages from the hub to the WebSocket connection
func (c *Client) writePump() {
	ticker := time.NewTicker(30 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			// Batch messages if available
			n := len(c.send)
			for i := 0; i < n; i++ {
				w.Write([]byte{'\n'})
				w.Write(<-c.send)
			}

			if err := w.Close(); err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// readPump pumps messages from the WebSocket connection to the hub
func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadLimit(512)
	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, _, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %v", err)
			}
			break
		}
	}
}
