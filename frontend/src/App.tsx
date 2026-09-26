import { useState } from "react";
import "./App.css";
import Header from "./components/Header";
import IncidentInput from "./components/IncidentInput";
import AnalysisSummary from "./components/AnalysisSummary";
import EvidencePanel from "./components/EvidencePanel";
import Alternatives from "./components/Alternatives";
import ResponsePlaybook from "./components/ResponsePlaybook";
import IntelligenceTelemetry from "./components/IntelligenceTelemetry";
import { analyzeIncident, ApiRequestError } from "./services/api";
import type { AnalyzeResponse } from "./types/api";

const defaultIncident = "An employee received a suspicious phishing email containing a malicious login link requesting credentials.";

function App() {
  const [incident, setIncident] = useState(defaultIncident);
  const [analysis, setAnalysis] = useState<AnalyzeResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleAnalyze() {
    const description = incident.trim();
    if (!description) { setError("Please enter a security incident description."); setAnalysis(null); return; }
    setLoading(true); setError(null);
    try { setAnalysis(await analyzeIncident({ description })); }
    catch (error) {
      setError(error instanceof ApiRequestError ? `${error.message} (${error.status})` : "Unable to analyze incident.");
      setAnalysis(null);
    } finally { setLoading(false); }
  }

  return (
    <main className="app-shell">
      <Header modelVersion={analysis?.model_version ?? "ra-xsoc-x-browser-demo-1.0"} />
      <section className="hero">
        <div>
          <p className="eyebrow">SECURITY OPERATIONS / EVIDENCE-DRIVEN INVESTIGATION</p>
          <h1>Investigate the incident.<br />Understand the threat.</h1>
          <p className="hero-copy">Evidence-driven investigation with competing hypotheses, ATT&CK mapping and human-in-the-loop response guidance.</p>
        </div>
        <div className="version-badge"><span>ENGINE</span><strong>RA-XSOC-X</strong></div>
      </section>
      <IncidentInput incident={incident} loading={loading} error={error} onChange={setIncident} onAnalyze={handleAnalyze} />
      {analysis ? (
        <>
          <AnalysisSummary analysis={analysis} />
          <EvidencePanel analysis={analysis} />
          <IntelligenceTelemetry analysis={analysis} />
          <Alternatives analysis={analysis} />
          <ResponsePlaybook analysis={analysis} />
        </>
      ) : (
        <section className="empty-state">
          <span>{loading ? "ANALYZING" : "READY"}</span>
          <p>{loading ? "RA-XSOC-X is processing the incident." : "Submit an incident to begin the public RA-XSOC-X demonstration."}</p>
        </section>
      )}
      <footer><span>RA-XSOC-X</span><span>HUMAN-IN-THE-LOOP · PUBLIC DEMO</span><span>1.0</span></footer>
    </main>
  );
}
export default App;
