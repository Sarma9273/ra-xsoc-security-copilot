import { useState } from "react";
import "./App.css";
import Header from "./components/Header";
import IncidentInput from "./components/IncidentInput";
import AnalysisSummary from "./components/AnalysisSummary";
import EvidencePanel from "./components/EvidencePanel";
import ResponsePlaybook from "./components/ResponsePlaybook";
import IntelligenceTelemetry from "./components/IntelligenceTelemetry";
import type { AnalyzeResponse } from "./types/api";
import { analyzeIncident, ApiRequestError } from "./services/api";

const defaultIncident = "An employee received a suspicious phishing email containing a malicious login link requesting credentials.";

function App() {
  const [incident, setIncident] = useState(defaultIncident);
  const [analysis, setAnalysis] = useState<AnalyzeResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleAnalyze() {
    const description = incident.trim();
    if (!description) { setError("Please enter a security activity or incident."); setAnalysis(null); return; }
    setLoading(true); setError(null);
    try { setAnalysis(await analyzeIncident({ description })); }
    catch (e) {
      setError(e instanceof ApiRequestError ? `${e.message} (${e.status})` : "Unable to analyze activity.");
      setAnalysis(null);
    } finally { setLoading(false); }
  }

  return (
    <main className="app-shell">
      <Header modelVersion={analysis?.model_version ?? "ra-xsoc-x-investigation-engine-1.0"} />
      <section className="hero">
        <div>
          <p className="eyebrow">SOC INVESTIGATION / MULTI-HYPOTHESIS / EVIDENCE VERIFICATION</p>
          <h1>Investigate the activity.<br />Verify the threat.</h1>
          <p className="hero-copy">Evaluates competing attack and benign hypotheses, independently verifies ATT&CK mappings, and gives a beginner-safe investigation path.</p>
        </div>
        <div className="version-badge"><span>ENGINE</span><strong>RA-XSOC-X</strong></div>
      </section>

      <IncidentInput incident={incident} loading={loading} error={error} onChange={setIncident} onAnalyze={handleAnalyze} />

      {analysis ? (
        <>
          <section className="content-section">
            <div className="section-heading"><div><span className="section-number">01</span><h2>Investigation Verdict</h2></div><span className="input-limit">Evidence-based assessment</span></div>
            <div className="analysis-grid">
              <article className="classification-card">
                <div className="card-label">CURRENT VERDICT</div>
                <div className="attack-icon">⚑</div>
                <h2>{analysis.incident.name}</h2>
                <p className="attack-id">{analysis.incident.attack_family} · {analysis.incident.stage}</p>
                <h3>{analysis.assessment.verdict}</h3>
                <p>{analysis.assessment.rationale}</p>
                <p className="attack-id">SECURITY STATE / {analysis.assessment.securityState.toUpperCase()} · DETECTION / {analysis.assessment.detectionState.toUpperCase()}</p>
              </article>
              <article className="metrics-card">
                <div className="card-label">LEADING HYPOTHESIS</div>
                <div className="metrics">
                  <div><span>INCIDENT</span><strong>{analysis.incident.name}</strong></div>
                  <div><span>CONFIDENCE</span><strong>{(analysis.confidence * 100).toFixed(0)}%</strong></div>
                  <div><span>SEVERITY</span><strong>{analysis.severity.toUpperCase()}</strong></div>
                  <div><span>NOVELTY</span><strong className="review">{analysis.novelty.status.replaceAll("_"," ")}</strong></div><div><span>REVIEW</span><strong className="review">REQUIRED</strong></div>
                </div>
              </article>
            </div>
          </section>

          <section className="content-section">
            <div className="section-heading"><div><span className="section-number">02</span><h2>Novelty Assessment</h2></div><span className="input-limit">Research signal</span></div>
            <div className="analysis-grid">
              <article className="classification-card">
                <div className="card-label">NOVELTY STATUS</div>
                <h2>{analysis.novelty.status.replaceAll("_"," ")}</h2>
                <p>{analysis.novelty.reasons.join(" ")}</p>
              </article>
              <article className="metrics-card">
                <div className="card-label">NOVELTY FEATURES</div>
                <div className="metrics">
                  <div><span>NOVELTY SCORE</span><strong>{(analysis.novelty.score*100).toFixed(0)}%</strong></div>
                  <div><span>KNOWN SIMILARITY</span><strong>{(analysis.novelty.known_similarity*100).toFixed(0)}%</strong></div>
                  <div><span>BEHAVIOR COVERAGE</span><strong>{(analysis.novelty.behavior_coverage*100).toFixed(0)}%</strong></div>
                  <div><span>COMBINATION NOVELTY</span><strong>{(analysis.novelty.combination_novelty*100).toFixed(0)}%</strong></div>
                </div>
              </article>
            </div>
          </section>

          <AnalysisSummary analysis={analysis} />
          <EvidencePanel analysis={analysis} />

          <section className="content-section">
            <div className="section-heading"><div><span className="section-number">04</span><h2>Competing Hypotheses</h2></div><span className="input-limit">No forced single attack type</span></div>
            <div className="alternatives">
              {analysis.hypotheses.map((h) => (
                <div className="alternative" key={h.id}>
                  <span className="rank">{h.status === "supported" ? "✓" : h.status === "contradicted" ? "×" : "?"}</span>
                  <div className="candidate-details"><span className="candidate-name">{h.name}</span><span className="candidate-id">{h.category} · {h.status.toUpperCase()}</span></div>
                  <span className="candidate-score">{(h.score * 100).toFixed(0)}%</span>
                  <div className="candidate-bar"><span style={{width:`${Math.max(4,h.score*100)}%`}} /></div>
                </div>
              ))}
            </div>
          </section>

          <section className="content-section">
            <div className="section-heading"><div><span className="section-number">05</span><h2>Independent Verification</h2></div><span className="input-limit">Authoritative security knowledge</span></div>
            <div className="telemetry-grid">
              {analysis.verification.map((v) => (
                <article className="telemetry-card" key={v.source}>
                  <div className="telemetry-label">{v.source}</div>
                  <div className="telemetry-value">{v.status.toUpperCase()}</div>
                  <p>{v.details}</p>
                  <a href={v.url} target="_blank" rel="noreferrer">Open source →</a>
                </article>
              ))}
            </div>
          </section>

          <section className="content-section">
            <div className="section-heading"><div><span className="section-number">06</span><h2>SOC Beginner Investigation</h2></div><span className="input-limit">Follow in order</span></div>
            <div className="playbook-grid">
              {analysis.investigation.map((s) => (
                <article className="playbook-card" key={s.order}>
                  <div className="playbook-title"><span />STEP {s.order} · {s.title}</div>
                  <p><strong>DO:</strong> {s.action}</p>
                  <p><strong>LOOK FOR:</strong> {s.whatToLookFor}</p>
                  <p><strong>SUPPORTS:</strong> {s.supports.join(" ")}</p>
                  <p><strong>CONTRADICTS:</strong> {s.contradicts.join(" ")}</p>
                </article>
              ))}
            </div>
            <div className="detection-rules">
              <div className="playbook-title"><span />NEXT EVIDENCE TO COLLECT</div>
              <ul>{analysis.next_evidence.map(x => <li key={x}>{x}</li>)}</ul>
            </div>
          </section>

          <section className="content-section">
            <div className="section-heading"><div><span className="section-number">07</span><h2>Beginner Interpretation</h2></div></div>
            <div className="reason-list">{analysis.beginner_summary.map((x,i)=><p key={i}>{x}</p>)}</div>
          </section>

          <IntelligenceTelemetry analysis={analysis} />
          <ResponsePlaybook analysis={analysis} />
        </>
      ) : (
        <section className="empty-state">
          <span>{loading ? "INVESTIGATING" : "READY"}</span>
          <p>{loading ? "Evaluating competing hypotheses and verifying security mappings." : "Enter any security activity, alert, log, email or observation to begin."}</p>
        </section>
      )}

      <footer><span>RA-XSOC-X</span><span>HUMAN-IN-THE-LOOP · MULTI-HYPOTHESIS INVESTIGATION</span><span>1.0</span></footer>
    </main>
  );
}
export default App;
