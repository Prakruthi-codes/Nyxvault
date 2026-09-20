import { useEffect, useState, useRef } from "react";
import { type SecurityEvent } from "./api";

const WS_URL = import.meta.env.VITE_WS_URL || "ws://localhost:8000/ws/events";

export function useWebSocket(onEvent: (event: SecurityEvent) => void) {
  const [isConnected, setIsConnected] = useState(false);
  const socketRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<number | null>(null);

  useEffect(() => {
    function connect() {
      console.log("Connecting to WebSocket event stream...");
      const ws = new WebSocket(WS_URL);
      socketRef.current = ws;

      ws.onopen = () => {
        console.log("WebSocket connected successfully");
        setIsConnected(true);
      };

      ws.onmessage = (event) => {
        try {
          const securityEvent: SecurityEvent = JSON.parse(event.data);
          onEvent(securityEvent);
        } catch (error) {
          console.error("Failed to parse WebSocket event:", error);
        }
      };

      ws.onclose = (event) => {
        console.log(`WebSocket disconnected: ${event.reason} (code: ${event.code})`);
        setIsConnected(false);
        
        // Auto-reconnect after 3 seconds
        reconnectTimeoutRef.current = window.setTimeout(() => {
          connect();
        }, 3000);
      };

      ws.onerror = (error) => {
        console.error("WebSocket error:", error);
        ws.close();
      };
    }

    connect();

    return () => {
      if (socketRef.current) {
        // Remove close listener to prevent loop on clean unmount
        socketRef.current.onclose = null;
        socketRef.current.close();
      }
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
    };
  }, [onEvent]);

  return { isConnected };
}
