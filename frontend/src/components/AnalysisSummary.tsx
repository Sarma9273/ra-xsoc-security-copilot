import type { AnalyzeResponse } from "../types/api";

interface AnalysisSummaryProps {
  analysis: AnalyzeResponse;
}

function AnalysisSummary({ analysis }: AnalysisSummaryProps) {
  const primary = analysis.primary_match;

  return (
    <section className="analysis-grid">
      <article className="classification-card">
        <div className="card-label">PRIMARY CLASSIFICATION</div>

        <div className="attack-icon">⚠</div>

        <h2>{primary.name.toUpperCase()}</h2>

        <p className="attack-id">
          ATTACK ID / {primary.attack_id}
        </p>

        <div className="mitre-list">
          {primary.mitre_techniques.map((technique) => (
            <div className="mitre-chip" key={technique.technique_id}>
              MITRE ATT&CK{" "}
              <strong>{technique.technique_id}</strong>
              {" · "}
              {technique.name}
            </div>
          ))}
        </div>
      </article>

      <article className="metrics-card">
        <div className="card-label">ANALYSIS STATUS</div>

        <div className="metrics">
          <div>
            <span>CONFIDENCE</span>
            <strong>
              {(analysis.confidence * 100).toFixed(2)}%
            </strong>
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
              {analysis.novelty_status
                .replace(/_/g, " ")
                .toUpperCase()}
            </strong>
          </div>

          <div>
            <span>REVIEW</span>
            <strong className={analysis.requires_review ? "review" : ""}>
              {analysis.requires_review
                ? "REQUIRED"
                : "NOT REQUIRED"}
            </strong>
          </div>
        </div>
      </article>
    </section>
  );
}

export default AnalysisSummary;