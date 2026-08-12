import type { Alert, PolicyTrigger, Severity } from './types';

/** Section 9's action library, keyed by category: the standing recommended
 * response once a category shows up as a trend, not a per-alert judgment.
 * Wording here is modeled on the tone of the per-alert `recommendation`
 * strings already in the dataset (see mock.ts) -- it is a PLACEHOLDER for
 * the real Section 9 copy, which I don't have verbatim. The shape (one
 * standing action per category) is what this feed depends on; swap the
 * strings in when the real text is available, nothing else needs to change. */
const ACTION_LIBRARY: Record<string, { label: string; detail: string }> = {
  'Shadow AI': {
    label: 'Evaluate a sanctioned alternative',
    detail: 'When a Shadow AI tool sees broad peer use rather than one-off use, recommend evaluating it for sanctioned status instead of case-by-case enforcement.',
  },
  'Personal cloud': {
    label: 'Escalate for security review',
    detail: 'Personal-cloud destinations go to security for human review. Do not take automated enforcement action based on volume alone.',
  },
  'Unauthorized SaaS': {
    label: 'Notify + self-audit prompt',
    detail: 'First-observed unauthorized SaaS use gets a notification to the employee and a self-audit prompt before any escalation.',
  },
};
const DEFAULT_ACTION = { label: 'Route to manual triage', detail: 'No standing action is defined yet for this category -- route it to manual triage rather than guessing at one.' };

const WEEK_MS = 7 * 24 * 60 * 60 * 1000;

/** Groups alerts from the last 7 days by category and turns each group into
 * a policy trigger card: how many distinct people, the dominant severity,
 * and the matching action-library entry. Pure function over Alert[] -- it
 * doesn't know or care whether those alerts came from mock.ts or a real
 * API response, so mock mode and real mode run the exact same aggregation
 * (see api.ts's `trends()` for where the two data sources converge). Against
 * today's real dataset (25 events, one category) this will legitimately
 * produce zero or one card -- that's the honest answer, not a bug. */
export function computeTrends(alerts: Alert[], now: number = Date.now()): PolicyTrigger[] {
  const recent = alerts.filter(a => now - new Date(a.createdAt).getTime() <= WEEK_MS);
  const byCategory = new Map<string, Alert[]>();
  for (const a of recent) {
    const list = byCategory.get(a.category);
    if (list) list.push(a); else byCategory.set(a.category, [a]);
  }
  const triggers: PolicyTrigger[] = [];
  for (const [category, rows] of byCategory) {
    const affectedUsers = new Set(rows.map(r => r.userId)).size;
    const severityBreakdown: Record<Severity, number> = { low: 0, medium: 0, high: 0, critical: 0 };
    for (const r of rows) severityBreakdown[r.severity]++;
    const dominantSeverity = (Object.entries(severityBreakdown) as [Severity, number][])
      .sort((a, b) => b[1] - a[1])[0][0];
    triggers.push({
      category,
      affectedUsers,
      totalAlerts: rows.length,
      dominantSeverity,
      severityBreakdown,
      summary: `${affectedUsers} employee${affectedUsers === 1 ? '' : 's'} flagged for ${category} usage this week, mostly ${dominantSeverity} severity.`,
      action: ACTION_LIBRARY[category] ?? DEFAULT_ACTION,
    });
  }
  return triggers.sort((a, b) => b.affectedUsers - a.affectedUsers);
}
