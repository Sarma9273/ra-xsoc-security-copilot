import { useState } from "react";
import "./App.css";
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
      <header className="topbar">
        <div>
          <div className="brand">
            <span className="brand-mark">RA</span>
            <span>RA-XSOC</span>
          </div>

          <p className="brand-subtitle">Security Copilot</p>
        </div>

        <div className="system-status">
          <span className="status-dot" />
          ENGINE ONLINE
        </div>
      </header>

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
          <span>MODEL</span>
          <strong>{analysis?.model_version ?? "ra-xsoc-v2"}</strong>
        </div>
      </section>

      <section className="incident-panel">
        <div className="section-heading">
          <div>
            <span className="section-number">01</span>
            <h2>Incident Input</h2>
          </div>

          <span className="input-limit">Natural language incident</span>
        </div>

        <textarea
          value={incident}
          onChange={(event) => setIncident(event.target.value)}
          aria-label="Security incident description"
          placeholder="Describe the security incident..."
          maxLength={20_000}
          disabled={loading}
        />

        <div className="action-row">
          <span className="input-note">
            Evidence will be analyzed against the security knowledge base.
          </span>

          <button type="button" onClick={handleAnalyze} disabled={loading}>
            {loading ? "ANALYZING..." : "ANALYZE INCIDENT"}
            <span>→</span>
          </button>
        </div>

        {error && (
          <div className="error-message" role="alert">
            {error}
          </div>
        )}
      </section>

      {analysis ? (
        <>
          <section className="analysis-grid">
            <article className="classification-card">
              <div className="card-label">PRIMARY CLASSIFICATION</div>

              <div className="attack-icon">⚠</div>

              <h2>{analysis.primary_match.name.toUpperCase()}</h2>

              <p className="attack-id">
                ATTACK ID / {analysis.primary_match.attack_id}
              </p>

              {analysis.primary_match.mitre_techniques.map((technique) => (
                <div className="mitre-chip" key={technique.technique_id}>
                  MITRE ATT&CK <strong>{technique.technique_id}</strong> ·{" "}
                  {technique.name}
                </div>
              ))}
            </article>

            <article className="metrics-card">
              <div className="card-label">ANALYSIS STATUS</div>

              <div className="metrics">
                <div>
                  <span>CONFIDENCE</span>
                  <strong>{(analysis.confidence * 100).toFixed(2)}%</strong>
                </div>

                <div>
                  <span>SEVERITY</span>
                  <strong className="medium">
                    {analysis.severity.toUpperCase()}
                  </strong>
                </div>

                <div>
                  <span>NOVELTY</span>
                  <strong>
                    {analysis.novelty_status.replace(/_/g, " ").toUpperCase()}
                  </strong>
                </div>

                <div>
                  <span>REVIEW</span>
                  <strong className={analysis.requires_review ? "review" : ""}>
                    {analysis.requires_review ? "REQUIRED" : "NOT REQUIRED"}
                  </strong>
                </div>
              </div>
            </article>
          </section>

          <section className="content-section">
            <div className="section-heading">
              <div>
                <span className="section-number">02</span>
                <h2>Why RA-XSOC Thinks This</h2>
              </div>
            </div>

            <div className="explanation">
              <div className="evidence-line">
                <span className="evidence-value">
                  {analysis.primary_match.semantic_score.toFixed(3)}
                </span>

                <span>semantic retrieval score</span>
              </div>

              {analysis.explanation.map((reason) => (
                <p key={reason}>{reason}</p>
              ))}
            </div>
          </section>

          <section className="content-section">
            <div className="section-heading">
              <div>
                <span className="section-number">03</span>
                <h2>Alternative Candidates</h2>
              </div>
            </div>

            <div className="alternatives">
              {analysis.alternatives.map((candidate, index) => (
                <div className="alternative" key={candidate.attack_id}>
                  <span className="rank">
                    {String(index + 2).padStart(2, "0")}
                  </span>

                  <span className="candidate-name">{candidate.name}</span>

                  <span className="candidate-score">
                    {(candidate.hybrid_score * 100).toFixed(2)}%
                  </span>

                  <span className="candidate-bar">
                    <span
                      style={{
                        width: `${Math.min(
                          candidate.hybrid_score * 100,
                          100,
                        )}%`,
                      }}
                    />
                  </span>
                </div>
              ))}
            </div>
          </section>

          <section className="content-section">
            <div className="section-heading">
              <div>
                <span className="section-number">04</span>
                <h2>Response Playbook</h2>
              </div>

              {analysis.requires_review && (
                <span className="review-badge">ANALYST REVIEW REQUIRED</span>
              )}
            </div>

            <div className="playbook-grid">
              <PlaybookCard
                title="Containment"
                items={analysis.playbook.containment}
              />

              <PlaybookCard
                title="Investigation"
                items={analysis.playbook.investigation}
              />

              <PlaybookCard
                title="Recovery"
                items={analysis.playbook.recovery}
              />

              <PlaybookCard
                title="Prevention"
                items={analysis.playbook.prevention}
              />
            </div>
          </section>
        </>
      ) : (
        <section className="empty-state">
          <span>READY</span>
          <p>Submit an incident to begin RA-XSOC analysis.</p>
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

function PlaybookCard({ title, items }: { title: string; items: string[] }) {
  return (
    <article className="playbook-card">
      <div className="playbook-title">
        <span />
        {title}
      </div>

      <ul>
        {items.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
    </article>
  );
}

export default App;
