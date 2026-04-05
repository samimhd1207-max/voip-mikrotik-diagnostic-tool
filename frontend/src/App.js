import { useState } from 'react';
import './App.css';

function App() {
  const [target, setTarget] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);

  const runDiagnostic = async () => {
    const trimmedTarget = target.trim();
    if (!trimmedTarget) {
      setError('Please enter a target IP address or hostname.');
      setResult(null);
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const startResponse = await fetch('/api/v1/diagnostics', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ target: trimmedTarget }),
      });

      if (!startResponse.ok) {
        const failedBody = await startResponse.json().catch(() => ({}));
        throw new Error(failedBody.error?.message || 'Unable to start diagnostic run.');
      }

      const { id } = await startResponse.json();
      const detailResponse = await fetch(`/api/v1/diagnostics/${id}`);

      if (!detailResponse.ok) {
        throw new Error('Diagnostic started but failed to retrieve details.');
      }

      setResult(await detailResponse.json());
    } catch (requestError) {
      setError(requestError.message || 'Unexpected error while running diagnostics.');
    } finally {
      setLoading(false);
    }
  };

  const analysis = result?.analysis;

  return (
    <main className="page">
      <section className="card">
        <h1>MikroTik / VoIP Remote Diagnostic (V1)</h1>
        <p className="help-text">
          Enter the client WAN IP or remote Winbox hostname, then run diagnostics.
        </p>

        <div className="form-row">
          <label htmlFor="target">Target IP or hostname</label>
          <input
            id="target"
            type="text"
            placeholder="203.0.113.10 or client.example.net"
            value={target}
            onChange={(event) => setTarget(event.target.value)}
          />
          <button type="button" onClick={runDiagnostic} disabled={loading}>
            {loading ? 'Running diagnostic…' : 'Run diagnostic'}
          </button>
        </div>

        {error && (
          <div className="alert" role="alert">
            {error}
          </div>
        )}
      </section>

      <section className="card result-card">
        <h2>Result</h2>

        {!result && !loading && !error && <p className="empty">No result yet. Run a diagnostic to see analysis.</p>}

        {result && (
          <div className="result-content">
            <div className="summary-grid">
              <div>
                <span className="label">Target</span>
                <strong>{result.target}</strong>
              </div>
              <div>
                <span className="label">Overall status</span>
                <strong>{analysis?.overallStatus || result.status}</strong>
              </div>
              <div>
                <span className="label">Ping</span>
                <strong>{result.results?.ping?.ok ? 'Reachable' : 'Unreachable'}</strong>
              </div>
              <div>
                <span className="label">DNS</span>
                <strong>
                  {result.results?.dns?.skipped
                    ? 'Skipped (IP target)'
                    : result.results?.dns?.ok
                    ? 'Resolved'
                    : 'Failed'}
                </strong>
              </div>
            </div>

            <h3>Tested ports</h3>
            <table>
              <thead>
                <tr>
                  <th>Port</th>
                  <th>State</th>
                  <th>Response</th>
                </tr>
              </thead>
              <tbody>
                {(result.results?.ports?.ports || []).map((port) => (
                  <tr key={port.port}>
                    <td>{port.port}</td>
                    <td>{port.open ? 'Open' : 'Closed'}</td>
                    <td>{port.responseTimeMs} ms</td>
                  </tr>
                ))}
              </tbody>
            </table>

            <h3>Probable cause</h3>
            <p>{analysis?.primaryFinding?.probableCause || 'No probable cause identified.'}</p>

            <h3>Recommended next action</h3>
            <p>{analysis?.primaryFinding?.recommendedAction || 'No recommendation available.'}</p>

            <h3>Suggested MikroTik-side checks</h3>
            <ul>
              {(analysis?.primaryFinding?.mikrotikChecks || []).map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>

            <h3>RouterOS command suggestion</h3>
            <code>{analysis?.primaryFinding?.routerOsCommand || 'N/A'}</code>
          </div>
        )}
      </section>
    </main>
  );
}

export default App;