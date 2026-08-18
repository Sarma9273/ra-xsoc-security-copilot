interface IncidentInputProps {
  incident: string;
  loading: boolean;
  error: string | null;
  onChange: (value: string) => void;
  onAnalyze: () => void;
}

function IncidentInput({
  incident,
  loading,
  error,
  onChange,
  onAnalyze,
}: IncidentInputProps) {
  return (
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
        onChange={(event) => onChange(event.target.value)}
        aria-label="Security incident description"
        placeholder="Describe the security incident..."
        maxLength={20_000}
        disabled={loading}
      />

      <div className="action-row">
        <span className="input-note">
          Evidence will be analyzed against the security knowledge base.
        </span>

        <button type="button" onClick={onAnalyze} disabled={loading}>
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
  );
}

export default IncidentInput;