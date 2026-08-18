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

const defaultIncident =
  "An employee received a suspicious phishing email containing a malicious login link requesting credentials.";

function App() {
  const [incident, setIncident] = useState(defaultIncident);
  const [analysis, setAnalysis] = useState<AnalyzeResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleAnalyze() {
    const description = incident.trim();

    if (!description) {
      setError("Please enter a security incident description.");
      setAnalysis(null);
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const result = await analyzeIncident({
        description,
      });

      setAnalysis(result);
    } catch (error) {
      if (error instanceof ApiRequestError) {
        setError(`${error.message} (${error.status})`);
      } else {
        setError("Unable to connect to the RA-XSOC API.");
      }

      setAnalysis(null);
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="app-shell">
      <Header modelVersion={analysis?.model_version ?? "ra-xsoc-v2"} />

      <section className="hero">
        <div>
          <p className="eyebrow">SECURITY OPERATIONS / INCIDENT ANALYSIS</p>

          <h1>
            Analyze the incident.
            <br />
            Understand the threat.
          </h1>

          <p className="hero-copy">
            AI-assisted incident analysis powered by semantic retrieval,
            cybersecurity knowledge and structured response playbooks.
          </p>
        </div>

        <div className="version-badge">
          <span>ENGINE</span>
          <strong>RA-XSOC V2</strong>
        </div>
      </section>

      <IncidentInput
        incident={incident}
        loading={loading}
        error={error}
        onChange={setIncident}
        onAnalyze={handleAnalyze}
      />

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

          <p>
            {loading
              ? "RA-XSOC is processing the incident."
              : "Submit an incident to begin RA-XSOC analysis."}
          </p>
        </section>
      )}

      <footer>
        <span>RA-XSOC SECURITY COPILOT</span>
        <span>AI-ASSISTED · HUMAN-IN-THE-LOOP</span>
        <span>V2</span>
      </footer>
    </main>
  );
}

export default App;
