"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

type Probe = { label?: string; source: string; destination: string; protocol: string; port?: number | null };
type Rule = { id: string; source: string; destination: string; protocol: string; port: number | string; action: string; priority?: number };
type Config = { default_policy: "allow" | "deny"; rules: Rule[] };
type Finding = { id: string; severity: string; title: string; rule_ids: string[]; evidence: Record<string, unknown>; explanation: string; mitigation: string };
type Analysis = { changes: { added: Rule[]; removed: Rule[]; changed: { id: string; before: Rule; after: Rule }[]; unchanged: string[]; default_policy: { before: string; after: string } | null }; findings: Finding[]; simulation: { before: Decision[]; after: Decision[] }; recommendations: string[]; rules_version: string; assumptions: string[]; limitations: string[] };
type Decision = { probe: Probe; decision: string; matched_rule_id: string | null; reason: string };
type Example = { before: Config; after: Config; probes: Probe[] };

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
const NAV_ITEMS = ["overview", "configuration", "findings", "simulation"] as const;
type View = "overview" | "findings" | "simulation";

function jumpTo(id: string) {
  document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" });
}

export default function Home() {
  const [before, setBefore] = useState("");
  const [after, setAfter] = useState("");
  const [probes, setProbes] = useState("");
  const [result, setResult] = useState<Analysis | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [active, setActive] = useState<View>("overview");

  const getExample = useCallback(async (): Promise<Example> => {
    const response = await fetch(`${API}/api/examples/demo`);
    if (!response.ok) throw new Error("Could not load the demo configuration from the API.");
    return response.json() as Promise<Example>;
  }, []);

  const loadExample = useCallback(async () => {
    setLoading(true); setError("");
    try {
      const data = await getExample();
      setBefore(JSON.stringify(data.before, null, 2)); setAfter(JSON.stringify(data.after, null, 2)); setProbes(JSON.stringify(data.probes, null, 2));
    } catch (e) { setError(e instanceof Error ? e.message : "API is unavailable."); }
    finally { setLoading(false); }
  }, [getExample]);

  useEffect(() => {
    let active = true;
    void getExample().then((data) => {
      if (active) { setBefore(JSON.stringify(data.before, null, 2)); setAfter(JSON.stringify(data.after, null, 2)); setProbes(JSON.stringify(data.probes, null, 2)); }
    }).catch((e: unknown) => {
      if (active) setError(e instanceof Error ? e.message : "API is unavailable.");
    }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [getExample]);

  const runAnalysis = async () => {
    setBusy(true); setError("");
    try {
      const parsedProbes = probes.trim() ? JSON.parse(probes) as Probe[] : [];
      if (!Array.isArray(parsedProbes)) throw new Error("Connectivity probes must be a JSON array.");
      const payload = { before: JSON.parse(before) as Config, after: JSON.parse(after) as Config, probes: parsedProbes };
      const response = await fetch(`${API}/api/analyze`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
      const data = await response.json().catch(() => null);
      if (!response.ok) {
        const message = data?.error?.message || "Permintaan analisis gagal.";
        const details = Array.isArray(data?.error?.details) ? data.error.details.map((item: { loc?: unknown[]; msg?: string }) => `${item.loc?.slice(1).join(" → ") || "Input"}: ${item.msg || "Nilai tidak valid"}`).join("; ") : "";
        throw new Error(details ? `${message} ${details}` : message);
      }
      setResult(data as Analysis); setActive("overview");
      window.setTimeout(() => jumpTo("results"), 0);
    } catch (e) { setError(e instanceof SyntaxError ? "JSON tidak valid. Periksa koma, tanda kutip, dan kurung pada konfigurasi atau probe." : e instanceof Error ? e.message : "Analisis gagal."); }
    finally { setBusy(false); }
  };

  const download = () => {
    if (!result) return;
    const report = { generated_at: new Date().toISOString(), changes: result.changes, findings: result.findings, simulation: result.simulation, recommendations: result.recommendations, rules_version: result.rules_version, assumptions: result.assumptions, limitations: result.limitations };
    const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }));
    const link = document.createElement("a"); link.href = url; link.download = "conduitguard-report.json"; document.body.appendChild(link); link.click(); link.remove(); window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  const criticalCount = useMemo(() => result?.findings.filter((f) => f.severity === "critical" || f.severity === "high").length ?? 0, [result]);

  return <main className="shell">
    <a className="skip-link" href="#configuration">Langsung ke konfigurasi</a>
    <aside className="sidebar">
      <a className="brand" href="#top" aria-label="ConduitGuard home"><span className="brand-mark"><ShieldIcon /></span><span>conduit<span className="brand-light">guard</span><small>NETWORK CHANGE CONTROL</small></span></a>
      <div className="nav-label">RUANG KERJA</div>
      <nav aria-label="Navigasi utama">
        {NAV_ITEMS.map((tab) => <button key={tab} type="button" className={`nav-item ${active === tab ? "selected" : ""}`} aria-current={active === tab ? "page" : undefined} onClick={() => {
          if (tab === "configuration") { setActive("overview"); jumpTo("configuration"); }
          else if (result) { setActive(tab); jumpTo("results"); }
          else { setError("Jalankan analisis terlebih dahulu untuk melihat hasil."); jumpTo("configuration"); }
        }}><NavIcon name={tab} /><span>{tab === "overview" ? "Ringkasan" : tab === "configuration" ? "Konfigurasi" : tab === "findings" ? "Temuan" : "Simulasi"}</span>{tab === "findings" && result && <b className="nav-count" aria-label={`${result.findings.length} temuan`}>{result.findings.length}</b>}</button>)}
      </nav>
      <div className="sidebar-bottom"><div className="offline-card"><span className="green-dot"/><div><strong>Offline analysis</strong><small>No network changes applied</small></div></div><div className="user-card"><div className="avatar">CG</div><div><strong>Local workspace</strong><small>Policy engine v1.0.0</small></div><span className="dots">···</span></div></div>
    </aside>

    <section className="main-panel" id="top">
      <header className="topbar"><div className="crumb">Ruang kerja <span>/</span> <strong>Validasi perubahan</strong></div><div className="top-right"><span className="env-tag"><i/> ANALISIS LOKAL</span><button className="icon-button" type="button" aria-label="Lompat ke cara kerja evaluasi" title="Cara kerja evaluasi" onClick={() => jumpTo("semantics")}>?</button><div className="avatar small-avatar" aria-hidden="true">CG</div></div></header>
      <div className="content" id="main-content">
        <div className="page-heading"><div><div className="eyebrow"><span className="eyebrow-line"/> KONTROL PERUBAHAN</div><h1>Validasi perubahan jaringan</h1><p>Tinjau dampak kebijakan dan uji konektivitas sebelum perubahan diterapkan.</p></div><button className="secondary-button" type="button" onClick={loadExample} disabled={loading} aria-busy={loading}><RefreshIcon /> {loading ? "Memuat…" : "Muat contoh"}</button></div>
        <span className="sr-only" role="status" aria-live="polite">{loading ? "Memuat konfigurasi contoh." : ""}</span>
        <div className="safety-banner"><span className="shield-small"><ShieldIcon /></span><div><strong>Safe by design</strong><span>All analysis runs locally against a documented generic model. No firewall is contacted or modified.</span></div><span className="banner-badge">SIMULATION ONLY</span></div>

        <div className="section-heading" id="configuration" tabIndex={-1}><div className="step">01</div><div><h2>Bandingkan konfigurasi</h2><p>Masukkan kebijakan firewall saat ini dan usulan dalam format JSON.</p></div><span className="schema-link">SKEMA <code>firewall-config/v1</code></span></div>
        <div className="config-grid">
          <ConfigEditor title="Current configuration" subtitle="BEFORE" value={before} setValue={setBefore} color="blue" />
          <ConfigEditor title="Proposed configuration" subtitle="AFTER" value={after} setValue={setAfter} color="violet" />
        </div>

        <div className="probe-panel"><div className="probe-header"><div><div className="probe-title"><span className="probe-icon"><PulseIcon /></span><div><h3 id="probes-label">Uji konektivitas</h3><p>Opsional. Uji keputusan koneksi pada kebijakan sebelum dan sesudah.</p></div></div></div><span className="optional">OPSIONAL</span></div><textarea id="probes" className="probe-input" aria-labelledby="probes-label" aria-describedby="probes-help" value={probes} onChange={(e) => setProbes(e.target.value)} spellCheck={false} placeholder={'[\n  { "source": "10.20.1.8", "destination": "192.0.2.10", "protocol": "tcp", "port": 443 }\n]'} /><span id="probes-help" className="sr-only">Masukkan array JSON probe koneksi. Kosongkan untuk melewati uji konektivitas.</span></div>
        {error && <div className="error-box" role="alert"><span aria-hidden="true">!</span><div><strong>Analisis belum dapat dijalankan</strong><p>{error}</p><small>Pastikan API aktif di {API} dan input mengikuti skema yang didokumentasikan.</small></div></div>}
        <div className="run-row"><div className="run-note"><span className="lock-icon" aria-hidden="true">⌑</span> Validasi dan simulasi berjalan tanpa mengubah jaringan.</div><button className="primary-button" type="button" onClick={runAnalysis} disabled={busy || loading} aria-busy={busy}>{busy ? <><span className="spinner" aria-hidden="true"/> Menganalisis…</> : <>Analisis perubahan <ArrowIcon /></>}</button></div>

        {result && <div className="results" id="results">
          <div className="section-heading result-heading"><div className="step">02</div><div><h2>Analysis results</h2><p>Generated by the API · rules v{result.rules_version}</p></div><button className="secondary-button export-button" onClick={download}><DownloadIcon /> Export JSON</button></div>
          <div className={`status-card ${criticalCount ? "status-review" : "status-clear"}`} role="status" aria-live="polite"><span className="status-icon" aria-hidden="true">{criticalCount ? "!" : "✓"}</span><div><strong>{criticalCount ? "Perlu ditinjau" : "Tidak ada temuan berkeparahan tinggi"}</strong><span>{result.findings.length ? `${result.findings.length} temuan kebijakan ditemukan. Tinjau bukti dan mitigasi di bawah.` : "Pemeriksaan kebijakan yang tersedia tidak menemukan pelanggaran."}</span></div><span className="status-count">{result.findings.length} TEMUAN</span></div>
          <div className="tabs" role="tablist" aria-label="Tampilan hasil analisis" onKeyDown={(event) => {
            if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
            event.preventDefault();
            const views: View[] = ["overview", "findings", "simulation"];
            const current = views.indexOf(active);
            const next = event.key === "Home" ? 0 : event.key === "End" ? views.length - 1 : (current + (event.key === "ArrowRight" ? 1 : views.length - 1)) % views.length;
            setActive(views[next]);
            document.getElementById(`tab-${views[next]}`)?.focus();
          }}>{(["overview", "findings", "simulation"] as View[]).map((tab) => <button id={`tab-${tab}`} role="tab" aria-controls="panel-${tab}" aria-selected={active === tab} tabIndex={active === tab ? 0 : -1} type="button" key={tab} onClick={() => setActive(tab)} className={active === tab ? "tab-active" : ""}>{tab === "overview" ? "Ringkasan" : tab === "findings" ? "Temuan" : "Simulasi"} {tab === "findings" && <span>{result.findings.length}</span>}</button>)}</div>
          <div id={`panel-${active}`} role="tabpanel" aria-labelledby={`tab-${active}`} tabIndex={0} className="tab-panel">{active === "overview" ? <Overview result={result} /> : active === "findings" ? <Findings items={result.findings} /> : <Simulation before={result.simulation.before} after={result.simulation.after} />}</div>
          <div className="model-notes"><h3>Model assumptions &amp; limits</h3><ul>{[...result.assumptions, ...result.limitations].map((item, i) => <li key={`${i}-${item}`}>{item}</li>)}</ul></div>
        </div>}

        <div className="below-fold" id="semantics"><div className="section-heading compact-heading"><div className="step muted-step">03</div><div><h2>Cara kerja evaluasi</h2><p>Semantik kebijakan deterministik dan transparan.</p></div></div><div className="semantics-grid"><SemanticCard number="01" title="Urutan aturan" text="Prioritas angka lebih kecil dievaluasi lebih dahulu. ID aturan memecah nilai seri secara alfabetis."/><SemanticCard number="02" title="Pencocokan" text="Sumber dan tujuan menerima IP, jaringan CIDR, atau *. Protokol: TCP, UDP, ICMP, atau any. Port menerima angka atau *."/><SemanticCard number="03" title="Kebijakan bawaan" text="Aturan pertama yang cocok menentukan keputusan. Jika tidak ada yang cocok, default_policy berlaku."/></div></div>
        <footer><span>ConduitGuard <span className="footer-sep">·</span> Open source network change validation</span><span>Offline by design <i className="green-dot"/></span></footer>
      </div>
    </section>
  </main>;
}

function ConfigEditor({ title, subtitle, value, setValue, color }: { title: string; subtitle: string; value: string; setValue: (v: string) => void; color: string }) {
  const id = color === "blue" ? "before-config" : "after-config";
  let valid = true;
  try { if (value.trim()) JSON.parse(value); } catch { valid = false; }
  const stateLabel = !value.trim() ? "Belum diisi" : valid ? "JSON valid" : "JSON belum valid";
  return <section className="editor-card"><div className="editor-head"><div className={`editor-dot ${color}`} aria-hidden="true"/><div className="editor-labels"><strong id={`${id}-label`}>{title}</strong><span>{subtitle}</span></div><span className="json-tag">JSON</span></div><textarea id={id} aria-labelledby={`${id}-label`} aria-describedby={`${id}-status`} aria-invalid={!valid} value={value} onChange={(e) => setValue(e.target.value)} spellCheck={false} placeholder={'{\n  "default_policy": "deny",\n  "rules": []\n}'}/><div className="editor-foot"><span id={`${id}-status`}><span className={`valid-dot ${valid && value.trim() ? "is-valid" : "is-invalid"}`} aria-hidden="true"/> {stateLabel}</span><span>Batas isi 256 KB</span></div></section>;
}

function Overview({ result }: { result: Analysis }) {
  const counts = [{ label: "Added", value: result.changes.added.length, cls: "added" }, { label: "Changed", value: result.changes.changed.length, cls: "changed" }, { label: "Removed", value: result.changes.removed.length, cls: "removed" }, { label: "Unchanged", value: result.changes.unchanged.length, cls: "unchanged" }];
  return <><div className="metrics">{counts.map((c) => <div className="metric" key={c.label}><span>{c.label}</span><strong className={c.cls}>{c.value}</strong></div>)}<div className="metric"><span>Probes tested</span><strong>{result.simulation.after.length}</strong></div></div><div className="overview-grid"><div className="result-card"><div className="card-title"><h3>Policy changes</h3><span className="quiet">BY RULE ID</span></div>{result.changes.default_policy && <div className="change-row"><span className="change-icon changed">↔</span><div><strong>Default policy</strong><small>{result.changes.default_policy.before} → {result.changes.default_policy.after}</small></div><span className="change-type">UPDATED</span></div>}{result.changes.added.map((r) => <ChangeRow key={r.id} name={r.id} detail={`${r.action} ${r.protocol}/${r.port}`} type="ADDED" kind="added"/>)}{result.changes.changed.map((r) => <ChangeRow key={r.id} name={r.id} detail={`${r.before.action} → ${r.after.action} · ${r.before.protocol}/${r.before.port} → ${r.after.protocol}/${r.after.port}`} type="UPDATED" kind="changed"/>)}{result.changes.removed.map((r) => <ChangeRow key={r.id} name={r.id} detail={`${r.action} ${r.protocol}/${r.port}`} type="REMOVED" kind="removed"/>)}{!result.changes.added.length && !result.changes.changed.length && !result.changes.removed.length && !result.changes.default_policy && <div className="empty-state">No policy changes detected. Reordering rules does not change the configuration result.</div>}</div><div className="result-card"><div className="card-title"><h3>Recommended actions</h3><span className="quiet">{result.recommendations.length} ITEMS</span></div>{result.recommendations.length ? result.recommendations.map((r, i) => <div className="recommendation" key={`${i}-${r}`}><span>{String(i + 1).padStart(2, "0")}</span><p>{r}</p></div>) : <div className="empty-state">No recommendations from the configured checks.</div>}<div className="mini-sim"><PulseIcon/><span>Offline simulation</span><strong>{result.simulation.after.length} probes</strong></div></div></div></>;
}

function Findings({ items }: { items: Finding[] }) { return items.length ? <div className="finding-list">{items.map((f, i) => <article className="finding-card" key={`${f.id}-${i}`}><div className={`severity-badge ${f.severity}`}>{f.severity}</div><div className="finding-body"><div className="finding-title"><h3>{f.title}</h3><code>{f.id}</code></div><p>{f.explanation}</p><div className="finding-evidence"><strong>Evidence</strong><pre>{JSON.stringify(f.evidence, null, 2)}</pre></div><div className="mitigation"><strong>Suggested mitigation</strong><span>{f.mitigation}</span></div>{f.rule_ids.length > 0 && <div className="related">Related rule IDs: {f.rule_ids.map((id) => <code key={id}>{id}</code>)}</div>}</div></article>)}</div> : <div className="empty-state large-empty"><span className="check-circle">✓</span><strong>No findings</strong><span>The active policy checks did not identify a violation.</span></div>; }

function Simulation({ before, after }: { before: Decision[]; after: Decision[] }) { if (!after.length) return <div className="empty-state large-empty"><PulseIcon/><strong>No probes supplied</strong><span>Add connection probes above to evaluate decisions on both configurations.</span></div>; return <div className="result-card simulation-card"><div className="card-title"><div><h3>Connection decisions</h3><p>Each probe runs against both rule sets independently.</p></div><span className="quiet">{after.length} PROBES</span></div><div className="sim-table-head"><span>CONNECTION</span><span>BEFORE</span><span>AFTER</span><span>CHANGE</span></div>{after.map((a, i) => { const b = before[i]; return <div className="sim-row" key={`${a.probe.label || a.probe.source}-${i}`}><div className="connection"><strong>{a.probe.label || `${a.probe.source} → ${a.probe.destination}`}</strong><small>{a.probe.protocol.toUpperCase()}{a.probe.port ? ` / ${a.probe.port}` : ""} · matched {a.matched_rule_id || "default policy"}</small><small className="reason">{a.reason}</small></div><DecisionBadge decision={b?.decision || "unknown"}/><DecisionBadge decision={a.decision}/><span className={`delta ${b?.decision === a.decision ? "same" : "different"}`}>{b?.decision === a.decision ? "No change" : `${b?.decision} → ${a.decision}`}</span></div>; })}</div>; }

function DecisionBadge({ decision }: { decision: string }) { return <span className={`decision ${decision}`}>{decision === "allow" ? "✓" : "⊘"} {decision}</span>; }
function ChangeRow({ name, detail, type, kind }: { name: string; detail: string; type: string; kind: string }) { return <div className="change-row"><span className={`change-icon ${kind}`}>{kind === "added" ? "+" : kind === "removed" ? "−" : "↔"}</span><div><strong>{name}</strong><small>{detail}</small></div><span className="change-type">{type}</span></div>; }
function SemanticCard({ number, title, text }: { number: string; title: string; text: string }) { return <article className="semantic-card"><span>{number}</span><h3>{title}</h3><p>{text}</p></article>; }
function ShieldIcon() { return <svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 3 20 6v5.5c0 5.2-3.4 8.6-8 10.5-4.6-1.9-8-5.3-8-10.5V6l8-3Z" stroke="currentColor" strokeWidth="1.6"/><path d="m8.5 12 2.2 2.2 4.8-5" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"/></svg>; }
function PulseIcon() { return <svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M3 12h4l3-8 4 16 3-8h4" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/></svg>; }
function ArrowIcon() { return <svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><path d="M4 10h12m-5-5 5 5-5 5" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"/></svg>; }
function RefreshIcon() { return <svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><path d="M16.5 8A6.5 6.5 0 0 0 5 5.5L3.5 7M3.5 4.5V7H6m-2.5 5A6.5 6.5 0 0 0 15 14.5l1.5-1.5m0 2.5V13H14" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></svg>; }
function DownloadIcon() { return <svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><path d="M10 3v9m0 0 3.5-3.5M10 12 6.5 8.5M4 14v2h12v-2" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></svg>; }
function NavIcon({ name }: { name: string }) { const common = { width: 18, height: 18, viewBox: "0 0 20 20", fill: "none", "aria-hidden": true as const }; if (name === "overview") return <svg {...common}><rect x="3" y="3" width="5" height="5" rx="1" stroke="currentColor"/><rect x="12" y="3" width="5" height="5" rx="1" stroke="currentColor"/><rect x="3" y="12" width="5" height="5" rx="1" stroke="currentColor"/><rect x="12" y="12" width="5" height="5" rx="1" stroke="currentColor"/></svg>; if (name === "configuration") return <svg {...common}><path d="M4 5h12M4 10h12M4 15h8" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/><circle cx="7" cy="5" r="1.5" fill="var(--sidebar)" stroke="currentColor"/><circle cx="13" cy="10" r="1.5" fill="var(--sidebar)" stroke="currentColor"/></svg>; if (name === "findings") return <svg {...common}><path d="M10 3 18 17H2L10 3Z" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round"/><path d="M10 8v4m0 2v.2" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round"/></svg>; return <PulseIcon/>; }
