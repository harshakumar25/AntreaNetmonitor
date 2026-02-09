import { useEffect, useRef, useState, useCallback } from 'react'
import type { WebSocketMessage, Packet, TrafficStats, Alert } from '@/types'

interface UseWebSocketOptions {
  onPacket?: (packet: Packet) => void
  onStats?: (stats: TrafficStats) => void
  onAlert?: (alert: Alert) => void
  reconnectInterval?: number
  maxReconnectAttempts?: number
}

interface UseWebSocketReturn {
  isConnected: boolean
  error: string | null
  reconnect: () => void
  disconnect: () => void
}

export function useWebSocket(
  endpoint: string,
  options: UseWebSocketOptions = {}
): UseWebSocketReturn {
  const {
    onPacket,
    onStats,
    onAlert,
    reconnectInterval = 3000,
    maxReconnectAttempts = 5,
  } = options

  const [isConnected, setIsConnected] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectAttemptsRef = useRef(0)
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const wsUrl = `${protocol}//${window.location.host}${endpoint}`
    
    try {
      const ws = new WebSocket(wsUrl)
      wsRef.current = ws

      ws.onopen = () => {
        setIsConnected(true)
        setError(null)
        reconnectAttemptsRef.current = 0
        console.log(`WebSocket connected: ${endpoint}`)
      }

      ws.onmessage = (event) => {
        try {
          // Handle batched messages (newline separated)
          const messages = event.data.split('\n').filter(Boolean)
          
          messages.forEach((msgStr: string) => {
            const message: WebSocketMessage = JSON.parse(msgStr)
            
            switch (message.type) {
              case 'packet':
                onPacket?.(message.data as Packet)
                break
              case 'stats':
                onStats?.(message.data as TrafficStats)
                break
              case 'alert':
                onAlert?.(message.data as Alert)
                break
            }
          })
        } catch (err) {
          console.error('Failed to parse WebSocket message:', err)
        }
      }

      ws.onclose = (event) => {
        setIsConnected(false)
        console.log(`WebSocket closed: ${endpoint}`, event.code, event.reason)

        // Attempt reconnection
        if (reconnectAttemptsRef.current < maxReconnectAttempts) {
          reconnectAttemptsRef.current++
          const delay = reconnectInterval * Math.pow(2, reconnectAttemptsRef.current - 1)
          
          reconnectTimeoutRef.current = setTimeout(() => {
            console.log(`Reconnecting... Attempt ${reconnectAttemptsRef.current}`)
            connect()
          }, delay)
        } else {
          setError('Max reconnection attempts reached')
        }
      }

      ws.onerror = (event) => {
        console.error('WebSocket error:', event)
        setError('WebSocket connection error')
      }
    } catch (err) {
      setError('Failed to create WebSocket connection')
      console.error('WebSocket creation error:', err)
    }
  }, [endpoint, onPacket, onStats, onAlert, reconnectInterval, maxReconnectAttempts])

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current)
    }
    if (wsRef.current) {
      wsRef.current.close()
      wsRef.current = null
    }
    setIsConnected(false)
  }, [])

  const reconnect = useCallback(() => {
    disconnect()
    reconnectAttemptsRef.current = 0
    connect()
  }, [connect, disconnect])

  useEffect(() => {
    connect()
    return () => disconnect()
  }, [connect, disconnect])

  return { isConnected, error, reconnect, disconnect }
}

// Hook for packet streaming
export function usePacketStream(onPacket: (packet: Packet) => void) {
  return useWebSocket('/ws/stream', { onPacket })
}

// Hook for stats streaming
export function useStatsStream(
  onStats: (stats: TrafficStats) => void,
  onAlert?: (alert: Alert) => void
) {
  return useWebSocket('/ws/stats', { onStats, onAlert })
}
