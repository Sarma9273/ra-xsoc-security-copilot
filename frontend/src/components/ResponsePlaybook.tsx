import type { AnalyzeResponse } from "../types/api";

interface ResponsePlaybookProps {
  analysis: AnalyzeResponse;
}

interface PlaybookCardProps {
  title: string;
  items: string[];
}

function PlaybookCard({ title, items }: PlaybookCardProps) {
  return (
    <article className="playbook-card">
      <div className="playbook-title">
        <span />
        {title}
      </div>

      {items.length > 0 ? (
        <ul>
          {items.map((item, index) => (
            <li key={`${index}-${item}`}>{item}</li>
          ))}
        </ul>
      ) : (
        <p className="playbook-empty">
          No guidance returned.
        </p>
      )}
    </article>
  );
}

function ResponsePlaybook({
  analysis,
}: ResponsePlaybookProps) {
  const { playbook } = analysis;

  return (
    <section className="content-section">
      <div className="section-heading">
        <div>
          <span className="section-number">04</span>
          <h2>Response Playbook</h2>
        </div>

        {analysis.requires_review && (
          <span className="review-badge">
            ANALYST REVIEW REQUIRED
          </span>
        )}
      </div>

      <div className="playbook-grid">
        <PlaybookCard
          title="Containment"
          items={playbook.containment}
        />

        <PlaybookCard
          title="Investigation"
          items={playbook.investigation}
        />

        <PlaybookCard
          title="Recovery"
          items={playbook.recovery}
        />

        <PlaybookCard
          title="Prevention"
          items={playbook.prevention}
        />
      </div>

      <div className="detection-rules">
        <div className="playbook-title">
          <span />
          Detection Rules
        </div>

        {playbook.detection_rules.length > 0 ? (
          <ul>
            {playbook.detection_rules.map((rule, index) => (
              <li key={`${index}-${rule}`}>{rule}</li>
            ))}
          </ul>
        ) : (
          <p className="playbook-empty">
            No detection rules returned.
          </p>
        )}
      </div>
    </section>
  );
}

export default ResponsePlaybook;