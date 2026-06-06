import { useMemo } from 'react';
import { useWebSocket, SecurityEvent } from './useWebSocket';

interface UseSecurityEventsReturn {
  events: SecurityEvent[];
  connected: boolean;
  metrics: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    recoveries: number;
  };
}

export function useSecurityEvents(wsUrl: string): UseSecurityEventsReturn {
  const { events, connected } = useWebSocket(wsUrl);

  const metrics = useMemo(() => {
    return events.reduce(
      (acc, event) => {
        acc.total++;
        if (event.severity === 'CRITICAL') acc.critical++;
        else if (event.severity === 'HIGH') acc.high++;
        else if (event.severity === 'MEDIUM') acc.medium++;
        else if (event.severity === 'LOW') acc.low++;

        if (event.event_type === 'RECOVERY_COMPLETE') {
          acc.recoveries++;
        }
        return acc;
      },
      { total: 0, critical: 0, high: 0, medium: 0, low: 0, recoveries: 0 }
    );
  }, [events]);

  return { events, connected, metrics };
}
