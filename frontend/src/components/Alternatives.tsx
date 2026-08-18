import type { AnalyzeResponse } from "../types/api";

interface AlternativesProps {
  analysis: AnalyzeResponse;
}

function Alternatives({ analysis }: AlternativesProps) {
  return (
    <section className="content-section">
      <div className="section-heading">
        <div>
          <span className="section-number">03</span>
          <h2>Alternative Candidates</h2>
        </div>

        <span className="input-limit">
          Ranked hybrid similarity
        </span>
      </div>

      {analysis.alternatives.length > 0 ? (
        <div className="alternatives">
          {analysis.alternatives.map((candidate, index) => {
            const score = Math.max(
              0,
              Math.min(candidate.hybrid_score * 100, 100),
            );

            return (
              <div
                className="alternative"
                key={candidate.attack_id}
              >
                <span className="rank">
                  {String(index + 2).padStart(2, "0")}
                </span>

                <div className="candidate-details">
                  <span className="candidate-name">
                    {candidate.name}
                  </span>

                  <span className="candidate-id">
                    ATTACK ID / {candidate.attack_id}
                  </span>
                </div>

                <span className="candidate-score">
                  {score.toFixed(2)}%
                </span>

                <div
                  className="candidate-bar"
                  aria-label={`${candidate.name} score ${score.toFixed(2)} percent`}
                >
                  <span
                    style={{
                      width: `${score}%`,
                    }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        <div className="empty-state">
          <span>NO ALTERNATIVES</span>
          <p>
            No competing attack candidates were returned by the
            analysis engine.
          </p>
        </div>
      )}
    </section>
  );
}

export default Alternatives;