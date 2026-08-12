import { alerts, applications, leaderboard, overview, profiles } from './mock';
import type { Alert, AppInventory, LeaderboardEntry, Overview, Page, PolicyTrigger, UserProfile } from './types';
import { computeTrends } from './trends';
export const useMocks = import.meta.env.VITE_USE_MOCKS !== 'false';
const baseUrl = import.meta.env.VITE_API_URL ?? 'http://localhost:8000/api/v1';
const isRecord=(x:unknown):x is Record<string,unknown> => typeof x==='object' && x!==null;
const delay=(ms:number)=>new Promise(r=>setTimeout(r,ms));
async function request<T>(path:string, fallback:T):Promise<T>{ if(useMocks){ await new Promise(r=>setTimeout(r,220)); return fallback; } const response=await fetch(`${baseUrl}${path}`,{credentials:'include',headers:{Accept:'application/json'}}); if(!response.ok) throw new Error(`Request failed (${response.status})`); const data:unknown=await response.json(); if(!isRecord(data) && !Array.isArray(data)) throw new Error('Invalid API response'); return data as T; }

export type { LeaderboardEntry };
export type HealthResponse = {
  status: string;
  lastEventAt: string | null;
  connector: { status: 'ok' | 'error'; eventsFound: number; detail: string | null; polledAt: string } | null;
};

export const api={
  overview:()=>request<Overview>('/overview',overview),
  // No mock fallback that fabricates connector state -- the heartbeat hook
  // skips polling entirely in mock mode instead of calling this (see
  // heartbeat.tsx), so this fallback is only ever hit if that guard changes.
  health:()=>request<HealthResponse>('/health', { status:'ok', lastEventAt:null, connector:null }),
  alerts:async(query:{page:number;search:string;severity:string;status:string})=>{const rows=alerts.filter(a=>(!query.search||`${a.userName} ${a.app}`.toLowerCase().includes(query.search.toLowerCase()))&&(!query.severity||a.severity===query.severity)&&(!query.status||a.status===query.status));const pageSize=5;const params=new URLSearchParams({page:String(query.page),search:query.search,severity:query.severity,status:query.status});return request<Page<Alert>>(`/alerts?${params}`, {items:rows.slice((query.page-1)*pageSize,query.page*pageSize),page:query.page,pageSize,total:rows.length});},
  alert:(id:string)=>{const item=alerts.find(a=>a.id===id);if(!item) return Promise.reject(new Error('Alert not found'));return request<Alert>(`/alerts/${id}`,item);},
  user:async(id:string)=>{
    const item=profiles[id];
    // `item` is only a stand-in fallback for mock mode; against the real API, absence
    // of a matching *mock* profile says nothing about whether the id is real, so only
    // short-circuit here when we're actually serving mocks.
    if(useMocks && !item)return Promise.reject(new Error('User not found'));
    // A momentary fetch failure can be a race with the background connector still
    // writing this user's data, not a real "doesn't exist" — so give it one quick
    // retry before treating it as a genuine failure/404.
    try{ return await request<UserProfile>(`/users/${id}`,item as UserProfile); }
    catch(firstError){
      await delay(400);
      try{ return await request<UserProfile>(`/users/${id}`,item as UserProfile); }
      catch{ throw firstError; }
    }
  },
  apps:()=>request<AppInventory[]>('/applications',applications),

  // Mock fallback used to be `[]`, which is the actual bug: Leaderboard showed
  // "No alert data yet" in mock mode while every other page worked, because
  // this was the one endpoint whose mock data never existed rather than a
  // rendering problem. `leaderboard` (mock.ts) computes it from the same
  // `alerts` array Alerts/Overview already read, using the real backend's own
  // grouping logic, so it can't drift out of sync with what Alerts shows.
  leaderboard:()=>request<LeaderboardEntry[]>('/leaderboard',leaderboard),

  // Trends & Policy feed. One aggregation function (computeTrends, in trends.ts)
  // runs regardless of data source -- the only thing that differs between mock
  // and real mode here is how we gather the Alert[] to feed it, same as every
  // other method in this file. Real mode walks /alerts a page at a time because
  // that endpoint's page size is fixed server-side at 5; fine at today's volume
  // (dozens of events), but if real alert volume grows meaningfully this should
  // become a dedicated backend aggregation endpoint instead of an N-page walk.
  trends: async ():Promise<PolicyTrigger[]> => {
    if (useMocks) { await new Promise(r=>setTimeout(r,220)); return computeTrends(alerts); }
    const all:Alert[] = [];
    for (let page=1; page<=200; page++) {
      const res = await request<Page<Alert>>(`/alerts?page=${page}&pageSize=5&search=&severity=&status=`, {items:[],page,pageSize:5,total:0});
      all.push(...res.items);
      if (res.items.length===0 || all.length>=res.total) break;
    }
    return computeTrends(all);
  },

  reviewAlert: async (id: string, status: string) => {
    if (useMocks) { await new Promise(r=>setTimeout(r,220)); return { ok: true }; }
    const response = await fetch(`${baseUrl}/alerts/${id}`, {
      method: 'PATCH',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status }),
    });
    if (!response.ok) throw new Error(`Request failed (${response.status})`);
    return response.json();
  },

  // Mock mode used to just `return` here, no-op, no download, no error -- the
  // button's onClick still resolved "successfully" and showed "CSV export
  // downloaded." even though nothing happened. Real endpoint (GET /exports.csv,
  // see app/api.py) exports the full alerts dataset, NOT the apps table this
  // button happens to live next to on the Discovery map page -- same columns,
  // same filename, same csv.DictWriter field order. Mirrored client-side here
  // so mock mode downloads a real file with the same shape, not a stand-in.
  downloadCsv: async () => {
    if (useMocks) {
      await new Promise(r=>setTimeout(r,220));
      const fields: (keyof Alert)[] = ['id','userId','userName','department','severity','score','app','category','status','createdAt','tier'];
      const escape = (v: unknown) => {
        const s = String(v ?? '');
        return /[",\n]/.test(s) ? `"${s.replace(/"/g,'""')}"` : s;
      };
      const lines = [fields.join(','), ...alerts.map(a => fields.map(f => escape(a[f])).join(','))];
      const blob = new Blob([lines.join('\r\n')], { type: 'text/csv' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'shadow_kedi_alerts.csv';
      a.click();
      URL.revokeObjectURL(url);
      return;
    }
    const response = await fetch(`${baseUrl}/exports.csv`, { credentials: 'include' });
    if (!response.ok) throw new Error(`Request failed (${response.status})`);
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'shadow_kedi_alerts.csv';
    a.click();
    URL.revokeObjectURL(url);
  },
};