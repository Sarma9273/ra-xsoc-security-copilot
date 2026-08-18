import type { AnalyzeResponse } from "../types/api";

interface IntelligenceTelemetryProps {
  analysis: AnalyzeResponse;
}

function formatScore(score: number): string {
  return score.toFixed(3);
}

function scorePercentage(score: number): string {
  return `${Math.min(Math.max(score * 100, 0), 100)}%`;
}

function IntelligenceTelemetry({ analysis }: IntelligenceTelemetryProps) {
  const primaryMatch = analysis.primary_match;

  return (
    <section className="content-section telemetry-section">
      <div className="section-heading">
        <div>
          <span className="section-number">05</span>
          <h2>Intelligence Telemetry</h2>
        </div>

        <span className="input-limit">Retrieval evidence</span>
      </div>

      <div className="telemetry-grid">
        <article className="telemetry-card">
          <div className="telemetry-label">SEMANTIC RETRIEVAL</div>

          <div className="telemetry-value">
            {formatScore(primaryMatch.semantic_score)}
          </div>

          <div className="telemetry-track">
            <span
              style={{
                width: scorePercentage(primaryMatch.semantic_score),
              }}
            />
          </div>

          <p>
            Similarity between the incident and retrieved security knowledge.
          </p>
        </article>

        <article className="telemetry-card">
          <div className="telemetry-label">KEYWORD / LEXICAL</div>

          <div className="telemetry-value">
            {formatScore(primaryMatch.keyword_score)}
          </div>

          <div className="telemetry-track">
            <span
              style={{
                width: scorePercentage(primaryMatch.keyword_score),
              }}
            />
          </div>

          <p>Lexical evidence contributing to the classification.</p>
        </article>

        <article className="telemetry-card">
          <div className="telemetry-label">HYBRID SCORE</div>

          <div className="telemetry-value">
            {formatScore(primaryMatch.hybrid_score)}
          </div>

          <div className="telemetry-track">
            <span
              style={{
                width: scorePercentage(primaryMatch.hybrid_score),
              }}
            />
          </div>

          <p>Combined retrieval signal used for the primary match.</p>
        </article>
      </div>

      <div className="telemetry-meta">
        <div>
          <span>PRIMARY MATCH</span>
          <strong>{primaryMatch.name.toUpperCase()}</strong>
        </div>

        <div>
          <span>CANDIDATES RETRIEVED</span>
          <strong>{analysis.alternatives.length + 1}</strong>
        </div>

        <div>
          <span>MODEL VERSION</span>
          <strong>{analysis.model_version}</strong>
        </div>

        <div>
          <span>ANALYSIS ID</span>
          <strong>{analysis.analysis_id}</strong>
        </div>
      </div>
    </section>
  );
}

export default IntelligenceTelemetry;
