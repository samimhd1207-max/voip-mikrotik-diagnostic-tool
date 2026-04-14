import { useEffect, useMemo, useState } from 'react';
import { Link, useLocation } from 'react-router-dom';

const emptyFeedback = { type: '', message: '' };

function MikrotikAuditPage() {
  const location = useLocation();

  const storedCredentials = useMemo(() => {
    try {
      return JSON.parse(sessionStorage.getItem('mikrotikCredentials') || 'null');
    } catch (_error) {
      return null;
    }
  }, []);

  const credentials = location.state?.credentials || storedCredentials;
  const [issues, setIssues] = useState(Array.isArray(location.state?.issues) ? location.state.issues : []);
  const [loading, setLoading] = useState(!Array.isArray(location.state?.issues));
  const [applyLoading, setApplyLoading] = useState('');
  const [feedback, setFeedback] = useState(emptyFeedback);

  useEffect(() => {
    let active = true;

    const fetchAudit = async () => {
      if (!credentials?.host || !credentials?.username || !credentials?.password) {
        setLoading(false);
        setFeedback({ type: 'error', message: 'Missing MikroTik credentials. Please reconnect first.' });
        return;
      }

      try {
        const response = await fetch('/api/v1/mikrotik/audit', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ mikrotik: credentials }),
        });

        const payload = await response.json();
        if (!response.ok) {
          throw new Error(payload.message || 'Audit failed.');
        }

        if (!active) return;
        const normalized = Array.isArray(payload) ? payload : [];
        setIssues(normalized);
        setFeedback({
          type: 'success',
          message: normalized.length ? 'Audit completed successfully.' : 'Audit completed: no issues found.',
        });
      } catch (error) {
        if (!active) return;
        setFeedback({ type: 'error', message: error.message || 'Unable to load audit results.' });
      } finally {
        if (active) setLoading(false);
      }
    };

    if (!Array.isArray(location.state?.issues)) {
      fetchAudit();
    }

    return () => {
      active = false;
    };
  }, [credentials, location.state]);

  const applyFix = async (command) => {
    if (!window.confirm('Are you sure you want to apply this fix?')) return;

    setApplyLoading(command);
    setFeedback(emptyFeedback);

    try {
      const response = await fetch('/api/v1/mikrotik/apply-fix', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command, mikrotik: credentials }),
      });

      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.message || 'Failed to apply fix.');
      }

      setFeedback({ type: 'success', message: 'Fix applied successfully.' });
    } catch (error) {
      setFeedback({ type: 'error', message: error.message || 'Failed to apply fix.' });
    } finally {
      setApplyLoading('');
    }
  };

  return (
    <main className="page">
      <section className="card">
        <div className="dashboard-header">
          <div>
            <h1>MikroTik Audit Results</h1>
            <p className="help-text">Review detected problems, proposed solutions, and apply safe fixes.</p>
          </div>
          <Link className="dashboard-link-btn" to="/mikrotik-dashboard">Back to Dashboard</Link>
        </div>

        {loading && <p className="audit-loading">⏳ Running audit...</p>}

        {!loading && feedback.message && (
          <p className={`audit-feedback audit-feedback-${feedback.type || 'info'}`}>
            {feedback.message}
          </p>
        )}
      </section>

     {!loading && !!issues.length && (
  <section className="card">
    <div className="audit-issues">
      {issues.map((issue, index) => (
        <article key={`${issue.command}-${index}`} className="audit-issue-card">
          <p className={`severity-badge severity-${issue.severity || 'info'}`}>
            {(issue.severity || 'info').toUpperCase()}
          </p>
          <p className="audit-problem"><strong>❌ Problem</strong></p>
          <p>{issue.problem || 'N/A'}</p>

          <p className="audit-impact"><strong>⚠️ Impact</strong></p>
          <p>{issue.impact || 'N/A'}</p>

          <p className="audit-solution"><strong>✅ Solution</strong></p>
          <p>{issue.solution || 'N/A'}</p>

          <p className="audit-command"><strong>💻 Command</strong></p>
          <pre>{issue.command || 'N/A'}</pre>

          <button
            type="button"
            disabled={!issue.command || applyLoading === issue.command}
            onClick={() => applyFix(issue.command)}
          >
            {applyLoading === issue.command ? 'Applying...' : 'Apply Fix'}
          </button>
        </article>
      ))}
    </div>
  </section>
)}
    </main>
  );
}

export default MikrotikAuditPage;