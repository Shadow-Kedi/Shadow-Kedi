export type Role = 'viewer' | 'analyst';
export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type RecommendationTier = 'R2' | 'R3' | 'R4' | 'R5' | 'R6';
export interface Evidence { label: string; detail: string; observedAt: string; strength: 'observed' | 'context'; }
export interface Alert { id: string; userId: string; userName: string; department: string; severity: Severity; score: number; app: string; category: string; status: 'new' | 'under_review' | 'resolved'; createdAt: string; tier: RecommendationTier; evidence: Evidence[]; recommendation: string; }
export interface UserProfile { id: string; name: string; department: string; baseline: 'established' | 'learning'; trend: number[]; inventory: string[]; alerts: Alert[]; }
export interface AppInventory { id: string; name: string; category: string; approval: 'sanctioned' | 'unapproved' | 'review'; activeUsers: number; review: 'needed' | 'in progress' | 'complete'; }
export interface Overview { severityCounts: Record<Severity, number>; newApps: number; reviewedThisWeek: number; topRisk: Alert[]; }
export interface Page<T> { items: T[]; page: number; pageSize: number; total: number; }
