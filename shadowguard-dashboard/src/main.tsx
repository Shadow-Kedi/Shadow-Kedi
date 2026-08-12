import { useEffect, useRef, useState, type Dispatch, type SetStateAction } from 'react';
import { createRoot } from 'react-dom/client';
// Self-hosted (no external font CDN) -- must load before ./charts, which reads
// the resulting CSS custom properties at module init. See tokens.css.
import '@fontsource/inter/400.css';
import '@fontsource/inter/500.css';
import '@fontsource/inter/600.css';
import '@fontsource/inter/700.css';
import '@fontsource/jetbrains-mono/400.css';
import '@fontsource/jetbrains-mono/500.css';
import '@fontsource/jetbrains-mono/700.css';
import './tokens.css';
import { api, useMocks, type LeaderboardEntry } from './api';
import type { Alert, AppInventory, Overview, PolicyTrigger, Role, UserProfile } from './types';
import { ACCENT, BarChart, DonutChart, LineTrendChart, SEVERITY_COLORS, SEVERITY_ORDER } from './charts';
import { HeartbeatIndicator, useHeartbeat } from './heartbeat';
import './styles.css';
import './overrides.css';
import './effects.css';

type View='overview'|'alerts'|'detail'|'user'|'apps'|'leaderboard'|'trends';
type AlertQuery={page:number;search:string;severity:string;status:string};
const severityRank={critical:4,high:3,medium:2,low:1};
function Badge({children,kind}:{children:React.ReactNode;kind:string}){return <span className={`badge ${kind}`}>{children}</span>}
// A risk score readout: counts up from its previous value (or 0 on first mount, for the
// terminal-readout feel) and briefly flashes only when the SAME row's score genuinely
// changes between renders -- e.g. a heartbeat-triggered refresh reveals a new value, not
// a demo animation. React's key-based identity is what makes "same row" well-defined:
// call sites key the surrounding row by alert/user id, so a different alert scrolling
// into view mounts fresh (counts up, no flash) rather than reading as a change.
function Score({value}:{value:number}){
  const [display,setDisplay]=useState(0);
  const [flashing,setFlashing]=useState(false);
  const prevRef=useRef<number|null>(null);
  const rafRef=useRef<number|undefined>(undefined);
  useEffect(()=>{
    const reduceMotion=window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const changed=prevRef.current!==null&&prevRef.current!==value;
    prevRef.current=value;
    if(reduceMotion){setDisplay(value);return}
    if(changed){setFlashing(true);const t=window.setTimeout(()=>setFlashing(false),700);return ()=>window.clearTimeout(t)}
    return undefined;
  },[value]);
  useEffect(()=>{
    if(window.matchMedia('(prefers-reduced-motion: reduce)').matches)return;
    const from=display;
    const duration=500;const start=performance.now();
    cancelAnimationFrame(rafRef.current!);
    const tick=(now:number)=>{
      const t=Math.min(1,(now-start)/duration);
      const eased=1-Math.pow(1-t,3);
      setDisplay(Math.round(from+(value-from)*eased));
      if(t<1)rafRef.current=requestAnimationFrame(tick);
    };
    rafRef.current=requestAnimationFrame(tick);
    return ()=>cancelAnimationFrame(rafRef.current!);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  },[value]);
  return <span className={`mono score-value${flashing?' score-flash':''}`}>{display}</span>;
}
function ErrorBox({message}:{message:string}){return <div className="error" role="alert">Couldn’t load this data: {message}. <button onClick={()=>location.reload()}>Try again</button></div>}
// api.user() already retries once internally, so landing here means that also failed —
// most often a race with the background connector still writing this user's data. Keep
// the tone reassuring rather than alarming, and let the person retry on their own terms
// instead of us silently looping.
function ProfileErrorBox({onRetry,retrying}:{onRetry:()=>void;retrying:boolean}){return <div className="profile-error" role="alert">Couldn’t load this profile right now. Try again in a moment. <button onClick={onRetry} disabled={retrying}>{retrying?'Retrying…':'Try again'}</button></div>}

// Indicative MITRE ATT&CK mapping by alert category. This supports triage context —
// it is not a determination that the technique was actually used.
const MITRE_BY_CATEGORY: Record<string,{id:string;name:string;url:string}> = {
  'Shadow AI': { id:'T1567.002', name:'Exfiltration to Cloud Storage', url:'https://attack.mitre.org/techniques/T1567/002/' },
  'Personal cloud': { id:'T1567.002', name:'Exfiltration to Cloud Storage', url:'https://attack.mitre.org/techniques/T1567/002/' },
  'Unauthorized SaaS': { id:'T1526', name:'Cloud Service Discovery', url:'https://attack.mitre.org/techniques/T1526/' },
};
const MITRE_FALLBACK = { id:'T1078', name:'Valid Accounts', url:'https://attack.mitre.org/techniques/T1078/' };
const APPROVAL_COLOR: Record<string,string> = { sanctioned:SEVERITY_COLORS.low, review:SEVERITY_COLORS.medium, unapproved:SEVERITY_COLORS.high };

function countBy(values: string[]): Record<string, number> {
  return values.reduce<Record<string, number>>((acc, v) => { acc[v] = (acc[v] ?? 0) + 1; return acc }, {});
}

/** Trailing dot + ring that follows the pointer, grows over interactive elements, and
 * shrinks on press. Inert on touch devices and when the user prefers reduced motion. */
function CustomCursor(){
  const dotRef=useRef<HTMLDivElement>(null); const ringRef=useRef<HTMLDivElement>(null);
  useEffect(()=>{
    if(!window.matchMedia('(hover: hover) and (pointer: fine)').matches) return;
    if(window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    document.body.classList.add('cursor-fx');
    let ringX=window.innerWidth/2, ringY=window.innerHeight/2, targetX=ringX, targetY=ringY, raf=0;
    const move=(e:MouseEvent)=>{
      targetX=e.clientX; targetY=e.clientY;
      if(dotRef.current) dotRef.current.style.transform=`translate(${targetX}px, ${targetY}px) translate(-50%, -50%)`;
      const interactive=(e.target as HTMLElement)?.closest?.('button, a, input, select, .row, .approw');
      ringRef.current?.classList.toggle('is-interactive', !!interactive);
    };
    const down=()=>ringRef.current?.classList.add('is-down');
    const up=()=>ringRef.current?.classList.remove('is-down');
    const leave=()=>{dotRef.current?.classList.add('is-hidden'); ringRef.current?.classList.add('is-hidden')};
    const enter=()=>{dotRef.current?.classList.remove('is-hidden'); ringRef.current?.classList.remove('is-hidden')};
    const tick=()=>{
      ringX+=(targetX-ringX)*0.18; ringY+=(targetY-ringY)*0.18;
      if(ringRef.current) ringRef.current.style.transform=`translate(${ringX}px, ${ringY}px) translate(-50%, -50%)`;
      raf=requestAnimationFrame(tick);
    };
    window.addEventListener('mousemove',move); window.addEventListener('mousedown',down); window.addEventListener('mouseup',up);
    document.addEventListener('mouseleave',leave); document.addEventListener('mouseenter',enter);
    raf=requestAnimationFrame(tick);
    return ()=>{
      document.body.classList.remove('cursor-fx');
      window.removeEventListener('mousemove',move); window.removeEventListener('mousedown',down); window.removeEventListener('mouseup',up);
      document.removeEventListener('mouseleave',leave); document.removeEventListener('mouseenter',enter);
      cancelAnimationFrame(raf);
    };
  },[]);
  return <><div className="cursor-dot" ref={dotRef}/><div className="cursor-ring" ref={ringRef}/></>;
}

function App(){const [role,setRole]=useState<Role>('viewer');const [view,setView]=useState<View>('overview');const [overview,setOverview]=useState<Overview>();const [alertRows,setAlertRows]=useState<Alert[]>([]);const [selected,setSelected]=useState<Alert>();const [profile,setProfile]=useState<UserProfile>();const [apps,setApps]=useState<AppInventory[]>([]);const [leaderboard,setLeaderboard]=useState<LeaderboardEntry[]>([]);const [trends,setTrends]=useState<PolicyTrigger[]>();const [error,setError]=useState('');const [query,setQuery]=useState({page:1,search:'',severity:'',status:''});const [total,setTotal]=useState(0);const [exportMessage,setExportMessage]=useState('');
 const [profileError,setProfileError]=useState<string>(); const [profileLoading,setProfileLoading]=useState(false);
 const loadOverview=()=>api.overview().then(setOverview).catch(e=>setError(e.message));
 const loadAlerts=()=>api.alerts(query).then(r=>{setAlertRows(r.items);setTotal(r.total)}).catch(e=>setError(e.message));
 useEffect(()=>{if(view==='overview')loadOverview(); if(view==='alerts')loadAlerts(); if(view==='apps')api.apps().then(setApps).catch(e=>setError(e.message)); if(view==='leaderboard')api.leaderboard().then(setLeaderboard).catch(e=>setError(e.message)); if(view==='trends')api.trends().then(setTrends).catch(e=>setError(e.message));},[view,query.page,query.search,query.severity,query.status]);
 // Ref, not a direct closure passed to useHeartbeat: the hook's poll effect mounts once
 // ([] deps, see heartbeat.tsx) and would otherwise capture a stale `view`/`query` forever.
 // Kept to the two list views a new alert would actually appear in -- Detail/User show a
 // single already-fetched item, and silently refetching underneath someone mid-review is
 // more surprising than useful. Background refresh failures are swallowed, not surfaced via
 // setError -- a transient miss on a passive sync shouldn't interrupt whatever's on screen.
 const refreshRef=useRef<()=>void>(()=>{});
 useEffect(()=>{refreshRef.current=()=>{
   if(view==='overview')api.overview().then(setOverview).catch(()=>{});
   if(view==='alerts')api.alerts(query).then(r=>{setAlertRows(r.items);setTotal(r.total)}).catch(()=>{});
   if(view==='leaderboard')api.leaderboard().then(setLeaderboard).catch(()=>{});
   if(view==='trends')api.trends().then(setTrends).catch(()=>{});
 }});
 const heartbeat=useHeartbeat(()=>refreshRef.current());
 const openAlert=(a:Alert)=>{setSelected(a);setView('detail')};
 // api.user() already retries once internally (transient-vs-real-404); if it still fails
 // here, show the friendlier inline banner instead of the generic ErrorBox, and let the
 // person retry manually rather than looping automatically.
 const openUser=(id:string)=>{setProfileLoading(true);setProfileError(undefined);return api.user(id).then(x=>{setProfile(x);setProfileError(undefined);setView('user')}).catch(()=>setProfileError(id)).finally(()=>setProfileLoading(false))};
 const nav=(to:View)=>{setError('');setProfileError(undefined);setView(to)};
 const onReviewed=async(id:string)=>{try{await api.reviewAlert(id,'resolved');nav('alerts')}catch(e){setError((e as Error).message)}};
 return <><CustomCursor/><main><a className="skip" href="#content">Skip to content</a><header><div><span className="logo">◐</span><strong>Shadow Kedi</strong><span className="sub">Human-reviewed Shadow IT triage</span><HeartbeatIndicator info={heartbeat}/></div><label>Role <select value={role} onChange={e=>setRole(e.target.value as Role)} aria-label="Demo role"><option value="viewer">Viewer</option><option value="analyst">Analyst</option></select></label></header>{useMocks&&<div className="demo"><b>Demo</b><span>This dashboard is using clearly marked mock records, not live data. Configure <code>VITE_API_URL</code> and set <code>VITE_USE_MOCKS=false</code> to connect your API.</span></div>}<div className="shell"><nav aria-label="Primary navigation"><button className={view==='overview'?'active':''} onClick={()=>nav('overview')}>Overview</button><button className={view==='alerts'||view==='detail'?'active':''} onClick={()=>nav('alerts')}>Alerts</button><button className={view==='leaderboard'?'active':''} onClick={()=>nav('leaderboard')}>Leaderboard</button><button className={view==='trends'?'active':''} onClick={()=>nav('trends')}>Trends &amp; Policy</button><button className={view==='apps'?'active':''} onClick={()=>nav('apps')}>Discovery map</button></nav><section id="content" key={view} className="content page-fade-in">{error&&<ErrorBox message={error}/>} {profileError&&<ProfileErrorBox retrying={profileLoading} onRetry={()=>openUser(profileError)}/>} {view==='overview'&&<OverviewPage data={overview} openAlert={openAlert} openUser={openUser}/>} {view==='alerts'&&<AlertsPage rows={alertRows} total={total} query={query} setQuery={setQuery} openAlert={openAlert}/>} {view==='detail'&&selected&&<DetailPage alert={selected} role={role} back={()=>nav('alerts')} openUser={openUser} onReviewed={onReviewed} openAlert={openAlert}/>} {view==='user'&&profile&&<UserPage profile={profile} openAlert={openAlert} back={()=>nav('alerts')}/>} {view==='leaderboard'&&<LeaderboardPage rows={leaderboard} openUser={openUser}/>} {view==='trends'&&<TrendsPage triggers={trends}/>} {view==='apps'&&<AppsPage apps={apps} role={role} requestExport={async()=>{try{await api.downloadCsv();setExportMessage('CSV export downloaded.')}catch(e){setError((e as Error).message)}}} message={exportMessage}/>}</section></div></main></>}

function OverviewPage({data,openAlert,openUser}:{data?:Overview;openAlert:(a:Alert)=>void;openUser:(id:string)=>void}){
  if(!data)return <p className="loading">Loading overview…</p>;
  const severityLabels=SEVERITY_ORDER.filter(k=>data.severityCounts[k]!==undefined);
  const severityValues=severityLabels.map(k=>data.severityCounts[k]);
  const severityColors=severityLabels.map(k=>SEVERITY_COLORS[k]);
  const trend=data.weeklyTrend??[];
  return <>
    <div className="title"><div><p className="eyebrow">Security operations</p><h1>Review what needs attention</h1><p>Signals support a human decision; they do not prove intent.</p></div></div>
    <div className="cards">{Object.entries(data.severityCounts).sort(([a],[b])=>severityRank[b as keyof typeof severityRank]-severityRank[a as keyof typeof severityRank]).map(([k,v])=><article className="metric" key={k}><span className={`dot ${k}${k==='critical'&&v>0?' pulse-critical':''}`}/><b><Score value={v}/></b><span>{k} alerts</span></article>)}<article className="metric"><b><Score value={data.newApps}/></b><span>new apps this week</span></article><article className="metric"><b><Score value={data.reviewedThisWeek}/></b><span>reviewed this week</span></article></div>
    {typeof data.fileIntegrityCount==='number'&&data.fileIntegrityCount>0&&<p className="hint fim-note" title="Routine file-integrity / registry checksum checks (Wazuh's FIM module) -- not Shadow IT activity. Still counted in the totals above since they're real events, broken out here so the total doesn't read as more signal than it is.">Includes <b className="mono">{data.fileIntegrityCount}</b> routine file-integrity check{data.fileIntegrityCount===1?'':'s'} (not Shadow IT activity) — hover for detail</p>}
    <div className="chart-grid">
      <div className="panel chart-panel"><h3>Severity mix</h3><DonutChart labels={severityLabels} values={severityValues} colors={severityColors} height={190} ariaLabel="Alert severity mix"/></div>
      <div className="panel chart-panel"><h3>New apps vs. reviewed</h3><BarChart labels={['New apps','Reviewed']} values={[data.newApps,data.reviewedThisWeek]} colors={[ACCENT,SEVERITY_COLORS.low]} height={190} ariaLabel="New applications compared to alerts reviewed this week"/></div>
      <div className="panel chart-panel"><h3>Alerts reviewed, last 6 weeks</h3>{trend.length?<LineTrendChart labels={trend.map((_,i)=>`W${i+1}`)} values={trend} label="Reviewed" height={190} ariaLabel="Alerts reviewed over the last six weeks"/>:<p className="empty">No trend data yet.</p>}</div>
    </div>
    <section className="panel"><h2>Top risk for review</h2><div className="table">{data.topRisk.map(a=><button className={`row${a.severity==='critical'?' pulse-critical':''}`} onClick={()=>openAlert(a)} key={a.id}><span><b className="mono">{a.userName}</b><small>{a.department} · <span className="mono">{a.app}</span></small></span><Badge kind={a.severity}>{a.severity}</Badge><b><Score value={a.score}/></b><span aria-hidden>›</span></button>)}</div><button className="link" onClick={()=>openUser(data.topRisk[0].userId)}>Open user risk profile</button></section>
  </>;
}

function AlertsPage({rows,total,query,setQuery,openAlert}:{rows:Alert[];total:number;query:AlertQuery;setQuery:Dispatch<SetStateAction<AlertQuery>>;openAlert:(a:Alert)=>void}){
  const pages=Math.max(1,Math.ceil(total/5));
  const mix=countBy(rows.map(r=>r.severity));
  const mixLabels=SEVERITY_ORDER.filter(k=>mix[k]);
  return <>
    <div className="title"><div><p className="eyebrow">Alert queue</p><h1>Evidence-first review</h1></div></div>
    <div className="filters"><input aria-label="Search alerts" placeholder="Search person or app" value={query.search} onChange={e=>setQuery({...query,search:e.target.value,page:1})}/><select aria-label="Severity" value={query.severity} onChange={e=>setQuery({...query,severity:e.target.value,page:1})}><option value="">All severities</option>{['low','medium','high','critical'].map(x=><option key={x}>{x}</option>)}</select><select aria-label="Status" value={query.status} onChange={e=>setQuery({...query,status:e.target.value,page:1})}><option value="">All statuses</option><option value="new">New</option><option value="under_review">Under review</option><option value="resolved">Resolved</option></select></div>
    {rows.length>0&&<div className="panel chart-panel"><h3>Severity mix · this page</h3><BarChart labels={mixLabels} values={mixLabels.map(k=>mix[k])} colors={mixLabels.map(k=>SEVERITY_COLORS[k as keyof typeof SEVERITY_COLORS])} height={130} ariaLabel="Severity mix of alerts on this page"/></div>}
    <section className="panel"><div className="table header"><span>Person / application</span><span>Severity</span><span>Score</span><span/></div>{rows.length?rows.map(a=><button className={`row${a.severity==='critical'?' pulse-critical':''}`} key={a.id} onClick={()=>openAlert(a)}><span><b className="mono">{a.userName}</b><small className="mono">{a.app} · {a.category} · {a.id}</small></span><Badge kind={a.severity}>{a.severity}</Badge><b><Score value={a.score}/></b><span>›</span></button>):<p className="empty">No alerts match these filters.</p>}<div className="pagination"><span className="mono">{total} alert{total===1?'':'s'}</span><button disabled={query.page===1} onClick={()=>setQuery({...query,page:query.page-1})}>Previous</button><span>Page <span className="mono">{query.page}</span> of <span className="mono">{pages}</span></span><button disabled={query.page===pages} onClick={()=>setQuery({...query,page:query.page+1})}>Next</button></div></section>
  </>;
}

function DetailPage({alert,role,back,openUser,onReviewed,openAlert}:{alert:Alert;role:Role;back:()=>void;openUser:(id:string)=>void;onReviewed:(id:string)=>void;openAlert:(a:Alert)=>void}){
  const [related,setRelated]=useState<Alert[]|null>(null);
  useEffect(()=>{
    let live=true; setRelated(null);
    api.user(alert.userId).then(p=>{if(live)setRelated(p.alerts.filter(a=>a.id!==alert.id))}).catch(()=>{if(live)setRelated([])});
    return ()=>{live=false};
  },[alert.id,alert.userId]);
  const mitre=MITRE_BY_CATEGORY[alert.category]??MITRE_FALLBACK;
  const evidenceMix=countBy(alert.evidence.map(e=>e.strength));
  const evidenceLabels=Object.keys(evidenceMix);
  const evidenceColors=evidenceLabels.map(k=>k==='observed'?ACCENT:SEVERITY_COLORS.medium);
  return <>
    <button className="back" onClick={back}>← All alerts</button>
    <div className="title"><div><p className="eyebrow mono">{alert.id} · {alert.category}</p><h1>{alert.app} activity for <span className="mono">{alert.userName}</span></h1><p><Badge kind={alert.severity}>{alert.severity}</Badge> Risk score <b><Score value={alert.score}/>/100</b> · Recommendation tier <b className="mono">{alert.tier}</b> <a className="mitre-tag" href={mitre.url} target="_blank" rel="noreferrer" title={`MITRE ATT&CK — ${mitre.name} (indicative, not confirmed)`}><span className="mono">{mitre.id}</span><small>{mitre.name}</small></a></p></div><button className="link" onClick={()=>openUser(alert.userId)}>Open user profile</button></div>
    <div className="detailgrid">
      <section className="panel">
        <h2>What we observed</h2><p className="hint">These contributors are evidence and context, not a determination of intent.</p>
        <ol className="timeline">{alert.evidence.map((e,i)=><li key={i}><span className={`point ${e.strength}`}/><div><b>{e.label}</b><small className="mono">{e.observedAt} · {e.strength==='observed'?'Observed signal':'Review context'}</small><p>{e.detail}</p></div></li>)}</ol>
        <div className="chart-panel"><h3>Evidence mix</h3><DonutChart labels={evidenceLabels} values={evidenceLabels.map(k=>evidenceMix[k])} colors={evidenceColors} height={160} ariaLabel="Mix of observed signals versus review context"/></div>
      </section>
      <aside className="panel action"><p className="eyebrow">Recommended human action</p><h2>{alert.recommendation}</h2><p>Reviewers should validate the evidence and policy context before changing access or notifying anyone.</p>{role==='analyst'?<button className="primary" onClick={()=>onReviewed(alert.id)}>Mark as reviewed</button>:<><button className="primary" disabled>Mark as reviewed</button><small>Viewer role: review controls are unavailable.</small></>}</aside>
    </div>
    <section className="panel related-panel"><h2>Other alerts for <span className="mono">{alert.userName}</span></h2>{related===null?<p className="loading">Loading related alerts…</p>:related.length?related.map(a=><button className={`row${a.severity==='critical'?' pulse-critical':''}`} key={a.id} onClick={()=>openAlert(a)}><span><b className="mono">{a.app}</b><small className="mono">{a.category} · {new Date(a.createdAt).toLocaleString()}</small></span><Badge kind={a.severity}>{a.severity}</Badge><b><Score value={a.score}/></b><span>›</span></button>):<p className="related-empty">No other alerts for this user.</p>}</section>
  </>;
}

function UserPage({profile,openAlert,back}:{profile:UserProfile;openAlert:(a:Alert)=>void;back:()=>void}){
  const alertMix=countBy(profile.alerts.map(a=>a.severity));
  const alertMixLabels=SEVERITY_ORDER.filter(k=>alertMix[k]);
  return <>
    <button className="back" onClick={back}>← Alerts</button>
    <div className="title"><div><p className="eyebrow">User risk profile</p><h1>{profile.name}</h1><p>{profile.department} · Baseline <Badge kind={profile.baseline}>{profile.baseline}</Badge></p></div></div>
    <div className="detailgrid">
      <section className="panel"><h2>Risk trend</h2><LineTrendChart labels={profile.trend.map((_,i)=>`P${i+1}`)} values={profile.trend} label="Risk score" height={190} ariaLabel="Risk trend over six review periods"/><p className="hint">Trend shows scores across six review periods. It is not a prediction.</p></section>
      <section className="panel"><h2>Application inventory</h2>{profile.inventory.map(x=><div className="inventory" key={x}><span>{x}</span><Badge kind="review">Observed</Badge></div>)}</section>
    </div>
    <section className="panel">
      <h2>Alert history</h2>
      {alertMixLabels.length>0&&<div className="chart-panel"><h3>Severity mix</h3><BarChart labels={alertMixLabels} values={alertMixLabels.map(k=>alertMix[k])} colors={alertMixLabels.map(k=>SEVERITY_COLORS[k as keyof typeof SEVERITY_COLORS])} height={130} ariaLabel="Severity mix of this user's alerts"/></div>}
      {profile.alerts.map(a=><button className={`row${a.severity==='critical'?' pulse-critical':''}`} key={a.id} onClick={()=>openAlert(a)}><span><b>{a.app}</b><small>{new Date(a.createdAt).toLocaleString()}</small></span><Badge kind={a.severity}>{a.severity}</Badge><b>{a.score}</b><span>›</span></button>)}
    </section>
  </>;
}

function LeaderboardPage({rows,openUser}:{rows:LeaderboardEntry[];openUser:(id:string)=>void}){
  return <>
    <div className="title"><div><p className="eyebrow">User risk</p><h1>Leaderboard</h1><p>Users ranked by their highest single alert score.</p></div></div>
    {rows.length>0&&<div className="panel chart-panel"><h3>Max score by user</h3><BarChart labels={rows.map(u=>u.userName)} values={rows.map(u=>u.maxScore)} colors={rows.map(u=>SEVERITY_COLORS[u.topSeverity as keyof typeof SEVERITY_COLORS]??ACCENT)} horizontal suggestedMax={100} height={Math.max(160,rows.length*34)} ariaLabel="Maximum alert score by user"/></div>}
    <section className="panel"><div className="table header leaderboard-row"><span>User</span><span>Top severity</span><span>Max score</span><span>Alerts</span></div>{rows.length?rows.map(u=><button className={`row leaderboard-row${u.topSeverity==='critical'?' pulse-critical':''}`} key={u.userId} onClick={()=>openUser(u.userId)}><span><b className="mono">{u.userName}</b></span><Badge kind={u.topSeverity}>{u.topSeverity}</Badge><b><Score value={u.maxScore}/></b><span className="mono">{u.alertCount}</span></button>):<p className="empty">No alert data yet.</p>}</section>
  </>;
}

// Category rollups of recent alert volume, each paired with its standing
// action-library entry -- "what changed this week" and "what to do about it",
// distinct from Alerts (individual triage) and Leaderboard (per-person
// ranking). triggers===undefined means still loading; [] is a real, honest
// "nothing crossed the threshold this week" result, not a loading state.
function TrendsPage({triggers}:{triggers?:PolicyTrigger[]}){
  return <>
    <div className="title"><div><p className="eyebrow">Trends &amp; policy</p><h1>What changed this week</h1><p>Category-level rollups, each paired with the standing recommended action — not a substitute for reviewing individual alerts.</p></div></div>
    {triggers===undefined&&<p className="loading">Loading trends…</p>}
    {triggers&&triggers.length===0&&<p className="empty">No category crossed the weekly threshold. Check back after more alerts come in.</p>}
    {triggers&&triggers.length>0&&<div className="triggers">{triggers.map(t=>
      <section className="panel trigger-card" key={t.category}>
        <div className="trigger-head"><h2>{t.category}</h2><span className="mono trigger-count">{t.affectedUsers} employee{t.affectedUsers===1?'':'s'}</span></div>
        <p>{t.summary}</p>
        <div className="trigger-breakdown">{SEVERITY_ORDER.filter(k=>t.severityBreakdown[k]).map(k=><Badge kind={k} key={k}><span className="mono">{t.severityBreakdown[k]}</span> {k}</Badge>)}</div>
        <div className="trigger-action"><p className="eyebrow">Recommended action</p><b>{t.action.label}</b><p>{t.action.detail}</p></div>
      </section>
    )}</div>}
  </>;
}

function AppsPage({apps,role,requestExport,message}:{apps:AppInventory[];role:Role;requestExport:()=>void;message:string}){
  const approvalMix=countBy(apps.map(a=>a.approval));
  const approvalLabels=Object.keys(approvalMix);
  return <>
    <div className="title"><div><p className="eyebrow">Application discovery</p><h1>Inventory for review</h1><p>Approval status reflects the tenant’s inventory, not a safety judgment.</p></div><div>{role==='analyst'?<button className="primary" onClick={requestExport}>Download CSV export</button>:<button className="primary" disabled>Download CSV export</button>}<small className="block">{role==='viewer'?'Viewer role: export requests are unavailable.':'Downloads a CSV of all current alerts.'}</small></div></div>
    {message&&<div className="success" role="status">{message}</div>}
    {approvalLabels.length>0&&<div className="panel chart-panel"><h3>Approval mix</h3><DonutChart labels={approvalLabels} values={approvalLabels.map(k=>approvalMix[k])} colors={approvalLabels.map(k=>APPROVAL_COLOR[k]??ACCENT)} height={180} ariaLabel="Application approval status mix"/></div>}
    <section className="panel apps"><div className="appheader"><span>Application</span><span>Category</span><span>Approval</span><span>Active users</span><span>Review</span></div>{apps.length?apps.map(a=><div className="approw" key={a.id}><b className="mono">{a.name}</b><span className="mono">{a.category}</span><Badge kind={a.approval}>{a.approval}</Badge><span className="mono">{a.activeUsers}</span><Badge kind={a.review}>{a.review}</Badge></div>):<p className="loading">Loading inventory…</p>}</section>
  </>;
}

createRoot(document.getElementById('root')!).render(<App/>);
