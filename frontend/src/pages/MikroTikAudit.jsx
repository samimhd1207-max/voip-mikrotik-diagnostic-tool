import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';

const defaultCredentials = {
  host: '',
  username: '',
  password: '',
  port: 22,
};

function MikroTikAudit() {
  const sessionCredentials = useMemo(() => {
    try {
      const parsed = JSON.parse(sessionStorage.getItem('mikrotikCredentials') || 'null');
      if (!parsed?.host || !parsed?.username) return null;
      return { ...defaultCredentials, ...parsed };
    } catch (_error) {
      return null;
    }
  }, []);

  const [credentials, setCredentials] = useState(sessionCredentials || defaultCredentials);
  const [issues, setIssues] = useState([]);
  const [loadingAudit, setLoadingAudit] = useState(false);
  const [applyLoading, setApplyLoading] = useState('');
  const [feedback, setFeedback] = useState({ type: '', message: '' });

  const onCredentialsChange = (event) => {
    const { name, value } = event.target;
    setCredentials((prev) => ({
      ...prev,
      [name]: name === 'port' ? Number(value || 22) : value,
    }));
  };

  const runAudit = async () => {
    setLoadingAudit(true);
    setFeedback({ type: '', message: '' });

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

      setIssues(payload.issues || []);
      setFeedback({
        type: 'success',
        message: payload.issues?.length ? 'Audit completed successfully.' : 'Audit completed: no alert detected.',
      });
    } catch (error) {
      setFeedback({ type: 'error', message: error.message || 'Unable to run audit.' });
    } finally {
      setLoadingAudit(false);
    }
  };

  const applyFix = async (command) => {
    if (!window.confirm('Apply this configuration on MikroTik?')) return;

    setApplyLoading(command);
    setFeedback({ type: '', message: '' });

    try {
      const response = await fetch('/api/v1/mikrotik/apply-fix', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mikrotik: credentials, command }),
      });

      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.message || 'Failed to apply fix.');
      }

      setFeedback({ type: 'success', message: 'Fix applied successfully.' });
    } catch (error) {
      setFeedback({ type: 'error', message: error.message || 'Fix failed.' });
    } finally {
      setApplyLoading('');
    }
  };

  return (
    <main className="page">
      <section className="card">
        <div className="dashboard-header">
          <div>
            <h1>MikroTik Audit</h1>
            <p className="help-text">Run RouterOS scripts and apply safe fixes directly.</p>
          </div>
          <Link to="/mikrotik-dashboard">Back to Dashboard</Link>
        </div>

        <div className="audit-credentials-grid">
          <label>
            MikroTik host
            <input name="host" value={credentials.host} onChange={onCredentialsChange} required />
          </label>
          <label>
            SSH port
            <input name="port" type="number" min="1" max="65535" value={credentials.port} onChange={onCredentialsChange} required />
          </label>
          <label>
            Username
            <input name="username" value={credentials.username} onChange={onCredentialsChange} required />
          </label>
          <label>
            Password
            <input name="password" type="password" value={credentials.password} onChange={onCredentialsChange} required />
          </label>
        </div>

        <button type="button" onClick={runAudit} disabled={loadingAudit}>
          {loadingAudit ? 'Running audit...' : 'Run Audit'}
        </button>

        {feedback.message && (
          <p className={`audit-feedback audit-feedback-${feedback.type || 'info'}`}>
            {feedback.message}
          </p>
        )}
      </section>

      {!!issues.length && (
        <section className="card">
          <h2>Detected Issues</h2>
          <div className="audit-issues">
            {issues.map((issue, index) => (
              <article key={`${issue.command}-${index}`} className="audit-issue-card">
                <p><strong>❌ Problem</strong></p>
                <p>{issue.problem || 'N/A'}</p>

                <p><strong>✅ Solution</strong></p>
                <p>{issue.solution || 'N/A'}</p>

                <p><strong>💻 Command</strong></p>
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

export default MikroTikAudit;
