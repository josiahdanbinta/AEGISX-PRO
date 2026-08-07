import { useEffect, useRef, useCallback, useState } from 'react';
import { useAuthStore } from '../store/authStore';

type WSStatus = 'connecting' | 'open' | 'closed' | 'error';

interface UseWebSocketOptions {
  endpoint: string;
  onMessage?: (data: any) => void;
  reconnectInterval?: number;
  maxRetries?: number;
}

export function useWebSocket({ endpoint, onMessage, reconnectInterval = 3000, maxRetries = 10 }: UseWebSocketOptions) {
  const wsRef = useRef<WebSocket | null>(null);
  const retryCount = useRef(0);
  const timerRef = useRef<ReturnType<typeof setTimeout>>();
  const [status, setStatus] = useState<WSStatus>('closed');
  const [lastMessage, setLastMessage] = useState<any>(null);
  const token = useAuthStore((s) => s.token);

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const baseUrl = import.meta.env.VITE_WS_URL || `${protocol}://${window.location.host}`;
    const url = `${baseUrl}/api/v1/live${endpoint}?token=${encodeURIComponent(token || '')}`;

    setStatus('connecting');
    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      setStatus('open');
      retryCount.current = 0;
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        setLastMessage(data);
        onMessage?.(data);
      } catch {
        onMessage?.({ raw: event.data });
      }
    };

    ws.onclose = (event) => {
      setStatus('closed');
      wsRef.current = null;

      if (!event.wasClean && retryCount.current < maxRetries) {
        retryCount.current += 1;
        timerRef.current = setTimeout(connect, reconnectInterval);
      }
    };

    ws.onerror = () => {
      setStatus('error');
    };
  }, [endpoint, token, reconnectInterval, maxRetries, onMessage]);

  const disconnect = useCallback(() => {
    if (timerRef.current) clearTimeout(timerRef.current);
    if (wsRef.current) {
      wsRef.current.close(1000, 'Client disconnect');
      wsRef.current = null;
    }
    setStatus('closed');
  }, []);

  const send = useCallback((data: any) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(data));
    }
  }, []);

  useEffect(() => {
    if (token) connect();
    return () => disconnect();
  }, [token, connect, disconnect]);

  return { status, lastMessage, send, disconnect, reconnect: connect };
}

export function useAlertWebSocket(onAlert?: (alert: any) => void) {
  const [alerts, setAlerts] = useState<any[]>([]);
  const [connected, setConnected] = useState(false);

  const ws = useWebSocket({
    endpoint: '/alerts',
    onMessage: (data) => {
      if (data.type === 'alerts_connected') {
        setConnected(true);
      } else if (data.type === 'alert') {
        setAlerts((prev) => [data.payload, ...prev].slice(0, 200));
        onAlert?.(data.payload);
      }
    },
  });

  return { ...ws, alerts, connected, clearAlerts: () => setAlerts([]) };
}

export function useDashboardWebSocket() {
  const [stats, setStats] = useState<any>(null);
  const [connected, setConnected] = useState(false);

  const ws = useWebSocket({
    endpoint: '/dashboard',
    onMessage: (data) => {
      if (data.type === 'dashboard_init' || data.type === 'dashboard_update') {
        setStats(data.payload);
        setConnected(true);
      }
    },
  });

  return { ...ws, stats, connected };
}

export function useIncidentWebSocket(incidentId: string | undefined) {
  const [updates, setUpdates] = useState<any[]>([]);

  const ws = useWebSocket({
    endpoint: incidentId ? `/incidents/${incidentId}` : '',
    onMessage: (data) => {
      setUpdates((prev) => [...prev, data].slice(0, 500));
    },
  });

  return { ...ws, updates, clearUpdates: () => setUpdates([]) };
}
