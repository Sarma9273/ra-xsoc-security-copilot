import type { AnalyzeResponse } from "../types/api";

interface EvidencePanelProps {
  analysis: AnalyzeResponse;
}

function EvidencePanel({ analysis }: EvidencePanelProps) {
  const primary = analysis.primary_match;

  return (
    <section className="content-section">
      <div className="section-heading">
        <div>
          <span className="section-number">02</span>
          <h2>Why RA-XSOC Thinks This</h2>
        </div>

        <span className="input-limit">
          Retrieval + hybrid evidence
        </span>
      </div>

      <div className="evidence-grid">
        <div className="explanation">
          <div className="evidence-line">
            <span className="evidence-value">
              {primary.semantic_score.toFixed(3)}
            </span>

            <span>semantic retrieval score</span>
          </div>

          <div className="score-breakdown">
            <div>
              <span>SEMANTIC</span>
              <strong>{primary.semantic_score.toFixed(3)}</strong>
            </div>

            <div>
              <span>KEYWORD</span>
              <strong>{primary.keyword_score.toFixed(3)}</strong>
            </div>

            <div>
              <span>HYBRID</span>
              <strong>{primary.hybrid_score.toFixed(3)}</strong>
            </div>
          </div>

          <div className="reason-list">
            {analysis.explanation.map((reason, index) => (
              <p key={`${index}-${reason}`}>{reason}</p>
            ))}
          </div>
        </div>

        <div className="evidence-meta">
          <div>
            <span>MODEL VERSION</span>
            <strong>{analysis.model_version}</strong>
          </div>

          <div>
            <span>ANALYSIS ID</span>
            <strong>{analysis.analysis_id}</strong>
          </div>

          <div>
            <span>REVIEW STATUS</span>
            <strong>
              {analysis.review_status.replace(/_/g, " ").toUpperCase()}
            </strong>
          </div>
        </div>
      </div>
    </section>
  );
}

export default EvidencePanel;