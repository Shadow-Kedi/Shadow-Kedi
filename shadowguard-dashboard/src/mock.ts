import type { Alert, AppInventory, LeaderboardEntry, Overview, UserProfile } from './types';

export const alerts: Alert[] = [
 { id:'AL-1042', userId:'u-1', userName:'Maya Chen', department:'Marketing', severity:'high', score:78, app:'Perplexity AI', category:'Shadow AI', status:'new', createdAt:'2026-08-10T09:14:00Z', tier:'R3', recommendation:'Flag for IT review. Confirm whether a sanctioned research tool meets the team’s need.', evidence:[{label:'New application observed',detail:'Perplexity AI is not in the approved application inventory.',observedAt:'09:14',strength:'observed'},{label:'Usage outside baseline',detail:'Activity occurred 3 hours after Maya’s established work window.',observedAt:'09:14',strength:'observed'},{label:'Peer context',detail:'12% of Marketing has used this app; below evaluation threshold.',observedAt:'09:15',strength:'context'}] },
 { id:'AL-1041', userId:'u-2', userName:'Jordan Rivers', department:'Sales', severity:'critical', score:93, app:'Personal Google Drive', category:'Personal cloud', status:'under_review', createdAt:'2026-08-10T02:18:00Z', tier:'R6', recommendation:'Escalate to security for human review. Do not take automated enforcement action.', evidence:[{label:'Volume anomaly',detail:'Upload volume is 4.8× the 30-day user baseline.',observedAt:'02:18',strength:'observed'},{label:'Time anomaly',detail:'Activity occurred outside the user’s normal work hours.',observedAt:'02:18',strength:'observed'},{label:'Known personal-cloud category',detail:'Destination is categorized as personal cloud storage.',observedAt:'02:19',strength:'context'}] },
 { id:'AL-1039', userId:'u-3', userName:'Alex Morgan', department:'Sales', severity:'medium', score:66, app:'Notion AI', category:'Shadow AI', status:'new', createdAt:'2026-08-09T15:33:00Z', tier:'R4', recommendation:'Recommend sanctioned-alternative evaluation because use is widespread in this peer group.', evidence:[{label:'Peer prevalence',detail:'43% of Sales has active use of this application.',observedAt:'15:34',strength:'observed'},{label:'Unapproved app',detail:'Notion AI is not yet approved for this tenant.',observedAt:'15:33',strength:'observed'}] },
 { id:'AL-1037', userId:'u-1', userName:'Maya Chen', department:'Marketing', severity:'low', score:42, app:'Canva', category:'Unauthorized SaaS', status:'resolved', createdAt:'2026-08-08T11:20:00Z', tier:'R2', recommendation:'Notify employee and offer a self-audit prompt.', evidence:[{label:'First observation',detail:'First observed use in the current review window.',observedAt:'11:20',strength:'observed'}] },
 // The four rows below exist to give the Trends & Policy feed (trends.ts) real
 // category variety to aggregate -- without them, "Shadow AI" only has 2 distinct
 // users, short of a believable weekly-trend trigger. Chosen so Shadow AI lands at
 // 6 distinct users, mostly low severity, matching the example in the spec.
 { id:'AL-1031', userId:'u-4', userName:'Priya Nair', department:'Engineering', severity:'low', score:24, app:'Notion AI', category:'Shadow AI', status:'new', createdAt:'2026-08-11T13:40:00Z', tier:'R2', recommendation:'Notify employee and confirm whether a sanctioned research tool meets the team’s need.', evidence:[{label:'New application observed',detail:'Notion AI is not in the approved application inventory.',observedAt:'13:40',strength:'observed'}] },
 { id:'AL-1030', userId:'u-5', userName:'Sam Osei', department:'Engineering', severity:'low', score:29, app:'Perplexity AI', category:'Shadow AI', status:'new', createdAt:'2026-08-10T18:05:00Z', tier:'R2', recommendation:'Notify employee and confirm whether a sanctioned research tool meets the team’s need.', evidence:[{label:'New application observed',detail:'Perplexity AI is not in the approved application inventory.',observedAt:'18:05',strength:'observed'}] },
 { id:'AL-1029', userId:'u-6', userName:'Dana Kim', department:'Product', severity:'low', score:21, app:'Notion AI', category:'Shadow AI', status:'resolved', createdAt:'2026-08-09T09:12:00Z', tier:'R2', recommendation:'Notify employee and confirm whether a sanctioned research tool meets the team’s need.', evidence:[{label:'New application observed',detail:'Notion AI is not in the approved application inventory.',observedAt:'09:12',strength:'observed'}] },
 { id:'AL-1028', userId:'u-7', userName:'Leo Fischer', department:'Product', severity:'medium', score:57, app:'Perplexity AI', category:'Shadow AI', status:'under_review', createdAt:'2026-08-07T21:30:00Z', tier:'R3', recommendation:'Recommend sanctioned-alternative evaluation because use is widespread in this peer group.', evidence:[{label:'Peer prevalence',detail:'31% of Product has active use of this application.',observedAt:'21:30',strength:'observed'},{label:'Unapproved app',detail:'Perplexity AI is not yet approved for this tenant.',observedAt:'21:30',strength:'observed'}] }
];
// Sorted most-recent-first immediately after declaration (in place, so every
// downstream export below inherits it -- filters/slices preserve order) --
// matches GET /alerts's real `.desc()` behavior. Was previously just
// authoring order, which wasn't chronological at all (AL-1031, the actual
// newest alert, was 5th in the array) -- silently wrong for both the main
// Alerts page and, via `profiles` below, the Detail page's "Other alerts for
// this user" list. Same bug independently found and fixed server-side in
// GET /users/{id} (see app/api.py) -- the real endpoint was sorting oldest-
// first; this is the equivalent fix for mock mode, not a hand-copy of it.
alerts.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
// Expanded from the original 4 apps / 3 categories -- too sparse to
// demonstrate the per-category mini-donuts (item 2) or the bubble cluster
// (item 3) meaningfully, both of which need real category/approval variety
// to look like anything other than 3-4 dots. Categories deliberately span a
// realistic range: some genuinely mostly-unapproved (Personal cloud,
// Unauthorized SaaS -- that's what those categories usually look like in
// practice), some mostly-sanctioned (Collaboration, Developer tools), one
// meaningfully mixed (Shadow AI, since ChatGPT being sanctioned while
// Perplexity/Notion/Claude aren't is a believable real policy split), and
// one single-app category (VPN) to exercise the mini-donut's single-state
// path too.
export const applications: AppInventory[] = [
 {id:'a1',name:'Perplexity AI',category:'Shadow AI',approval:'unapproved',activeUsers:7,review:'needed'},
 {id:'a2',name:'Notion AI',category:'Shadow AI',approval:'review',activeUsers:18,review:'in progress'},
 {id:'a5',name:'Claude.ai',category:'Shadow AI',approval:'unapproved',activeUsers:5,review:'needed'},
 {id:'a6',name:'ChatGPT',category:'Shadow AI',approval:'sanctioned',activeUsers:22,review:'complete'},
 {id:'a3',name:'Google Workspace',category:'Collaboration',approval:'sanctioned',activeUsers:148,review:'complete'},
 {id:'a7',name:'Slack',category:'Collaboration',approval:'sanctioned',activeUsers:132,review:'complete'},
 {id:'a8',name:'Miro',category:'Collaboration',approval:'review',activeUsers:9,review:'in progress'},
 {id:'a4',name:'Personal Google Drive',category:'Personal cloud',approval:'unapproved',activeUsers:3,review:'needed'},
 {id:'a9',name:'Dropbox',category:'Personal cloud',approval:'unapproved',activeUsers:9,review:'needed'},
 {id:'a10',name:'Canva',category:'Unauthorized SaaS',approval:'review',activeUsers:14,review:'in progress'},
 {id:'a11',name:'Figma (personal)',category:'Unauthorized SaaS',approval:'unapproved',activeUsers:6,review:'needed'},
 {id:'a12',name:'GitHub',category:'Developer tools',approval:'sanctioned',activeUsers:41,review:'complete'},
 {id:'a13',name:'npm registry',category:'Developer tools',approval:'sanctioned',activeUsers:55,review:'complete'},
 {id:'a14',name:'Postman (public workspace)',category:'Developer tools',approval:'unapproved',activeUsers:3,review:'needed'},
 {id:'a15',name:'NordVPN',category:'VPN',approval:'unapproved',activeUsers:4,review:'needed'},
];
// topRisk was `alerts.slice(0,3)` -- the first 3 array elements, not actually
// sorted by score despite the label. Happened to line up with the 3 highest
// scores by coincidence of authoring order; broke that coincidence the
// moment `alerts` above got sorted by date instead. Real backend sorts by
// score explicitly (see GET /overview: `sorted(alert_dicts, key=...score,
// reverse=True)[:3]`) -- mirrored here rather than assumed to still work.
const topRisk = [...alerts].sort((a, b) => b.score - a.score).slice(0, 3);
// 7 days, oldest-first, matching the shape GET /overview's dailyTrend sends
// -- illustrative like weeklyTrend above it, not required to sum exactly to
// severityCounts (that's a live snapshot total; these are a week's history).
const dailyTrend = {
  critical: [0, 0, 1, 0, 0, 0, 1],
  high: [1, 2, 1, 3, 2, 4, 4],
  medium: [3, 4, 3, 5, 6, 5, 9],
  low: [4, 3, 5, 4, 6, 5, 6],
  reviewed: [1, 2, 1, 3, 2, 4, 3],
};
export const overview: Overview = { severityCounts:{low:6,medium:9,high:4,critical:1}, newApps:3, reviewedThisWeek:14, topRisk, weeklyTrend:[7,9,12,10,13,14], dailyTrend };
export const profiles: Record<string, UserProfile> = {
 'u-1': {id:'u-1',name:'Maya Chen',department:'Marketing',baseline:'established',trend:[32,38,41,55,61,78],inventory:['Canva','Perplexity AI','Google Workspace'],alerts:alerts.filter(a=>a.userId==='u-1')},
 'u-2':{id:'u-2',name:'Jordan Rivers',department:'Sales',baseline:'established',trend:[25,22,28,31,64,93],inventory:['Google Workspace','Personal Google Drive'],alerts:alerts.filter(a=>a.userId==='u-2')},
 'u-3':{id:'u-3',name:'Alex Morgan',department:'Sales',baseline:'learning',trend:[20,24,33,45,55,66],inventory:['Notion AI','Google Workspace'],alerts:alerts.filter(a=>a.userId==='u-3')},
 'u-4':{id:'u-4',name:'Priya Nair',department:'Engineering',baseline:'established',trend:[10,12,14,18,20,24],inventory:['Notion AI','Google Workspace'],alerts:alerts.filter(a=>a.userId==='u-4')},
 'u-5':{id:'u-5',name:'Sam Osei',department:'Engineering',baseline:'established',trend:[8,11,15,19,26,29],inventory:['Perplexity AI','Google Workspace'],alerts:alerts.filter(a=>a.userId==='u-5')},
 'u-6':{id:'u-6',name:'Dana Kim',department:'Product',baseline:'learning',trend:[9,10,13,15,18,21],inventory:['Notion AI','Google Workspace'],alerts:alerts.filter(a=>a.userId==='u-6')},
 'u-7':{id:'u-7',name:'Leo Fischer',department:'Product',baseline:'established',trend:[22,27,35,41,49,57],inventory:['Perplexity AI','Google Workspace'],alerts:alerts.filter(a=>a.userId==='u-7')},
};
// Was previously just `[]` in api.ts's mock fallback, which is why Leaderboard
// showed "No alert data yet" in mock mode while Alerts/Overview (which do have
// real fallback data) worked fine -- this wasn't a rendering bug, the mock data
// for this one endpoint simply never existed. Computed here, from the same
// `alerts` array every other mock page already reads, using the identical
// grouping the real backend uses (see GET /leaderboard in app/api.py: group by
// userId, take the highest-scoring alert as maxScore/topSeverity, count all of
// that user's alerts) -- so this can't drift out of sync with Alerts the way a
// hand-authored parallel list could.
export const leaderboard: LeaderboardEntry[] = (() => {
  const byUser = new Map<string, Alert[]>();
  for (const a of alerts) {
    const list = byUser.get(a.userId);
    if (list) list.push(a); else byUser.set(a.userId, [a]);
  }
  const rows: LeaderboardEntry[] = [];
  for (const [userId, userAlerts] of byUser) {
    const top = userAlerts.reduce((best, a) => (a.score > best.score ? a : best));
    rows.push({ userId, userName: top.userName, alertCount: userAlerts.length, maxScore: top.score, topSeverity: top.severity });
  }
  return rows.sort((a, b) => b.maxScore - a.maxScore);
})();
