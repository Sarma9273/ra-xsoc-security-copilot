interface HeaderProps {
  modelVersion: string;
}

function Header({ modelVersion }: HeaderProps) {
  return (
    <header className="topbar">
      <div>
        <div className="brand">
          <span className="brand-mark">RA</span>
          <span>RA-XSOC</span>
        </div>

        <p className="brand-subtitle">Security Copilot</p>
      </div>

      <div className="header-meta">
        <div className="model-indicator">
          <span>MODEL</span>
          <strong>{modelVersion}</strong>
        </div>

        <div className="system-status">
          <span className="status-dot" />
          ENGINE ONLINE
        </div>
      </div>
    </header>
  );
}

export default Header;