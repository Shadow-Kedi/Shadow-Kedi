export type Role = 'viewer' | 'analyst';
export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type RecommendationTier = 'R2' | 'R3' | 'R4' | 'R5' | 'R6';
export interface Evidence { label: string; detail: string; observedAt: string; strength: 'observed' | 'context'; }
export interface Alert { id: string; userId: string; userName: string; department: string; severity: Severity; score: number; app: string; category: string; status: 'new' | 'under_review' | 'resolved'; createdAt: string; tier: RecommendationTier; evidence: Evidence[]; recommendation: string; }
export interface UserProfile { id: string; name: string; department: string; baseline: 'established' | 'learning'; trend: number[]; inventory: string[]; alerts: Alert[]; }
export interface AppInventory { id: string; name: string; category: string; approval: 'sanctioned' | 'unapproved' | 'review'; activeUsers: number; review: 'needed' | 'in progress' | 'complete'; }
// fileIntegrityCount is routine FIM/syscheck noise (already included in
// severityCounts, almost always "low") broken out separately so the UI can
// say "N of these are routine file-integrity checks" instead of showing one
// undifferentiated total with no way to explain it. Optional: real backend
// always sends it (see GET /overview); mock data has none to report, so it's
// legitimately absent there rather than hardcoded to 0.
// dailyTrend feeds each metric card's sparkline: 7 days, oldest-first, per
// severity, plus "reviewed" (by AlertStatusRow.reviewed_at, not alert
// occurrence date -- a different question). No "newApps" series here on
// purpose -- see GET /overview's comment for why faking one would be
// fabrication, not degradation. Optional (not every caller provides it),
// but mock.ts DOES provide a full 7-day series -- unlike fileIntegrityCount,
// this is the actual feature being demoed, so mock mode should show it
// working with real variety, not omit it.
export interface Overview { severityCounts: Record<Severity, number>; newApps: number; reviewedThisWeek: number; topRisk: Alert[]; weeklyTrend?: number[]; fileIntegrityCount?: number; dailyTrend?: { critical: number[]; high: number[]; medium: number[]; low: number[]; reviewed: number[] }; }
export interface Page<T> { items: T[]; page: number; pageSize: number; total: number; }
export type LeaderboardEntry = { userId: string; userName: string; alertCount: number; maxScore: number; topSeverity: string };
// One "policy trigger" card on the Trends & Policy feed: a category rollup of
// recent alerts (spec Section 10 -- "N employees flagged for X this week")
// paired with the standing action for that category (Section 9's
// action-library). Computed client-side from Alert[] by trends.ts, so the
// same function runs whether that Alert[] came from mock data or the real
// API -- see trends.ts for the full reasoning.
export interface PolicyTrigger {
  category: string;
  affectedUsers: number;
  totalAlerts: number;
  dominantSeverity: Severity;
  severityBreakdown: Record<Severity, number>;
  summary: string;
  action: { label: string; detail: string };
}
