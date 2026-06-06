import { useState, useEffect, useRef, useCallback } from 'react';

export interface SecurityEvent {
  event_id: string;
  event_type: string;
  agent_id: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  details: Record<string, any>;
  timestamp: string;
  source: string;
}

interface UseWebSocketReturn {
  events: SecurityEvent[];
  connected: boolean;
  lastEvent: SecurityEvent | null;
}

// Module-level event buffer — survives React component unmounts and tab changes.
// This ensures events are NEVER cleared when the user switches tabs / screens.
const _persistedEvents: SecurityEvent[] = [];
const _seenEventIds = new Set<string>();

export function useWebSocket(url: string): UseWebSocketReturn {
  const [events, setEvents] = useState<SecurityEvent[]>([..._persistedEvents]);
  const [connected, setConnected] = useState(false);
  const [lastEvent, setLastEvent] = useState<SecurityEvent | null>(
    _persistedEvents[0] ?? null
  );

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<number | null>(null);
  const reconnectAttemptsRef = useRef(0);
  const maxReconnectDelay = 10000; // max 10s backoff

  const addEvent = useCallback((newEvent: SecurityEvent) => {
    // De-duplicate using the module-level seen-set
    if (_seenEventIds.has(newEvent.event_id)) return;
    _seenEventIds.add(newEvent.event_id);

    // Prepend to the persisted buffer (newest first), cap at 500
    _persistedEvents.unshift(newEvent);
    if (_persistedEvents.length > 500) {
      _persistedEvents.splice(500);
    }

    // Sync React state — shallow copy so React sees a new reference
    setLastEvent(newEvent);
    setEvents([..._persistedEvents]);
  }, []);

  const connect = useCallback(() => {
    try {
      const ws = new WebSocket(url);

      ws.onopen = () => {
        console.log('WebSocket connected:', url);
        setConnected(true);
        reconnectAttemptsRef.current = 0;
      };

      ws.onmessage = (message) => {
        try {
          const data = JSON.parse(message.data);

          // Basic validation to ensure it looks like a SecurityEvent
          if (data && data.event_id && data.event_type) {
            addEvent(data as SecurityEvent);
          }
        } catch (err) {
          console.error('Failed to parse WebSocket message', err);
        }
      };

      ws.onclose = () => {
        console.log('WebSocket disconnected:', url);
        setConnected(false);
        wsRef.current = null;

        // Exponential backoff reconnect
        const delay = Math.min(
          1000 * Math.pow(1.5, reconnectAttemptsRef.current),
          maxReconnectDelay
        );
        reconnectAttemptsRef.current += 1;

        console.log(`Scheduling reconnect in ${Math.round(delay)}ms...`);
        reconnectTimeoutRef.current = window.setTimeout(connect, delay);
      };

      ws.onerror = (err) => {
        console.error('WebSocket error:', err);
        ws.close();
      };

      wsRef.current = ws;
    } catch (err) {
      console.error('Error establishing WebSocket:', err);
    }
  }, [url, addEvent]);

  useEffect(() => {
    connect();

    return () => {
      if (reconnectTimeoutRef.current) {
        window.clearTimeout(reconnectTimeoutRef.current);
      }
      if (wsRef.current) {
        // Prevent reconnect loop on unmount
        wsRef.current.onclose = null;
        wsRef.current.close();
      }
    };
  }, [connect]);

  return { events, connected, lastEvent };
}
