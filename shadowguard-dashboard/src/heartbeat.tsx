import { useEffect, useRef, useState } from 'react';
import { api, useMocks } from './api';

/** Three real states, not decoration:
 *  - live: a new event genuinely landed since the last poll (brief bright pulse)
 *  - healthy-idle: the Wazuh connector's own last-reported poll succeeded, just
 *    nothing new arrived (steady dim teal, no pulse) -- this is the common case
 *    with the current fleet's bursty event cadence, and it must NOT look broken
 *  - down: the connector's last poll failed, or its heartbeat is stale (missed
 *    ~2.5 expected cycles), or /health itself is unreachable (dim gray)
 */
export type HeartbeatState = 'live' | 'healthy-idle' | 'down' | 'unknown';

export interface HeartbeatInfo {
  state: HeartbeatState;
  lastEventAt: string | null;
  connectorStatus: 'ok' | 'error' | null;
  connectorDetail: string | null;
  connectorPolledAt: string | null;
}

const POLL_MS = 25_000;
// The connector polls every 60s per its own config -- call it down if we
// haven't heard a heartbeat in ~2.5x that, i.e. it's missed multiple cycles,
// not just a little late.
const CONNECTOR_STALE_MS = 150_000;
const LIVE_PULSE_MS = 2_200;

/** Polls GET /health and derives the 3-state heartbeat. Real state only --
 * in mock mode there is no live connector to report on, so this returns a
 * fixed, honestly-labeled demo state instead of polling a fabricated one. */
export function useHeartbeat(onNewEvent?: () => void): HeartbeatInfo {
  const [info, setInfo] = useState<HeartbeatInfo>({
    state: useMocks ? 'healthy-idle' : 'unknown',
    lastEventAt: null,
    connectorStatus: null,
    connectorDetail: null,
    connectorPolledAt: null,
  });
  const lastEventAtRef = useRef<string | null>(null);
  const hasPolledRef = useRef(false);
  const pulseTimeoutRef = useRef<number | undefined>(undefined);

  useEffect(() => {
    if (useMocks) return; // fixed demo state above; nothing to poll
    let live = true;

    const poll = async () => {
      try {
        const health = await api.health();
        if (!live) return;

        const polledAtMs = health.connector?.polledAt ? new Date(health.connector.polledAt).getTime() : null;
        const isStale = polledAtMs === null || Date.now() - polledAtMs > CONNECTOR_STALE_MS;
        const connectorDown = isStale || health.connector?.status === 'error';

        // Only the SECOND poll onward can meaningfully detect "new" -- the
        // first poll has nothing prior to compare against.
        const isNewEvent = hasPolledRef.current && !!health.lastEventAt && health.lastEventAt !== lastEventAtRef.current;
        lastEventAtRef.current = health.lastEventAt ?? lastEventAtRef.current;
        hasPolledRef.current = true;

        const state: HeartbeatState = connectorDown ? 'down' : isNewEvent ? 'live' : 'healthy-idle';

        setInfo({
          state,
          lastEventAt: health.lastEventAt,
          connectorStatus: health.connector?.status ?? null,
          connectorDetail: health.connector?.detail ?? null,
          connectorPolledAt: health.connector?.polledAt ?? null,
        });

        if (state === 'live') {
          onNewEvent?.();
          window.clearTimeout(pulseTimeoutRef.current);
          pulseTimeoutRef.current = window.setTimeout(() => {
            if (live) setInfo((prev) => (prev.state === 'live' ? { ...prev, state: 'healthy-idle' } : prev));
          }, LIVE_PULSE_MS);
        }
      } catch {
        if (live) setInfo((prev) => ({ ...prev, state: 'down' }));
      }
    };

    poll();
    const interval = window.setInterval(poll, POLL_MS);
    return () => {
      live = false;
      window.clearInterval(interval);
      window.clearTimeout(pulseTimeoutRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return info;
}

function relativeTime(iso: string | null): string {
  if (!iso) return 'never';
  const ms = Date.now() - new Date(iso).getTime();
  if (ms < 0) return 'just now';
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  return `${h}h ago`;
}

function absoluteTime(iso: string | null): string {
  if (!iso) return '';
  return new Date(iso).toISOString().slice(11, 19) + ' UTC';
}

const STATE_LABEL: Record<HeartbeatState, string> = {
  live: 'Live',
  'healthy-idle': 'Watching',
  down: 'Connection lost',
  unknown: 'Connecting…',
};

/** Header-mounted, visible on every page -- the one element that says "this
 * is watching something live". Not mouse-following, not decorative. Takes
 * `info` as a prop (rather than calling useHeartbeat itself) so the App root
 * can own the single polling interval and reuse its "new event" signal to
 * refresh on-screen alert data -- two independent hook instances would double
 * the network calls for no benefit. */
export function HeartbeatIndicator({ info }: { info: HeartbeatInfo }) {
  const tooltip = useMocks
    ? 'Demo data — no live connector to report on.'
    : info.state === 'down'
      ? `Connection lost. ${info.connectorDetail ? info.connectorDetail.slice(0, 120) + ' — ' : ''}Last known-good poll: ${relativeTime(info.connectorPolledAt)}.`
      : `Last event: ${relativeTime(info.lastEventAt)} (${absoluteTime(info.lastEventAt) || 'none yet'}). Connector last polled: ${relativeTime(info.connectorPolledAt)}.`;

  return (
    <div className="heartbeat" title={tooltip} tabIndex={0} aria-label={tooltip}>
      <span className={`heartbeat-dot ${info.state}`} aria-hidden="true" />
      <span className="heartbeat-label">{useMocks ? 'Demo' : STATE_LABEL[info.state]}</span>
    </div>
  );
}
