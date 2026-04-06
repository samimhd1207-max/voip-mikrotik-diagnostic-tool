import { useState } from 'react';
import './App.css';

const deriveFallbackAnalysisFromResults = (result) => {
  const pingOk = result?.results?.ping?.ok;
  const dns = result?.results?.dns;
  const ports = result?.results?.ports?.ports || [];

  const portState = new Map(ports.map((item) => [item.port, item.open]));
  const port5060Closed = portState.get(5060) === false;

  if (pingOk === false) {
    return {
      probableCause: 'Device unreachable from WAN checks (host down, link issue, or ICMP blocked).',
      recommendedAction: 'Check WAN connectivity, CPE power, and ICMP policy on firewall/router.',
      mikrotikChecks: [
        'Inspect WAN interface status in /interface print',
        'Check default route in /ip route print where dst-address=0.0.0.0/0',
      ],
      routerOsCommand: '/interface print; /ip route print where dst-address=0.0.0.0/0',
    };
  }

  if (dns && dns.skipped !== true && dns.ok === false) {
    return {
      probableCause: 'DNS resolution failed for this hostname.',
      recommendedAction: 'Check DNS server settings and resolver reachability.',
      mikrotikChecks: ['Review /ip dns print and verify upstream DNS reachability'],
      routerOsCommand: '/ip dns print; /ping 8.8.8.8 count=4',
    };
  }

  if (pingOk === true && port5060Closed) {
    return {
      probableCause: 'SIP signaling port 5060 appears blocked.',
      recommendedAction: 'Allow/open port 5060 and verify NAT + firewall filter rules.',
      mikrotikChecks: [
        'Check firewall filter rules for dst-port=5060',
        'Check NAT rules for SIP service',
      ],
      routerOsCommand: '/ip firewall filter print; /ip firewall nat print',
    };
  }

  return {
    probableCause: 'Network checks completed but no single dominant root cause was isolated from this probe point.',
    recommendedAction: 'Collect more data (traceroute, ISP path, PBX logs) and re-run diagnostics.',
    mikrotikChecks: [],
    routerOsCommand: 'N/A',
  };
};

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
  const fallbackAnalysis = deriveFallbackAnalysisFromResults(result);

  // Backward/forward compatibility across analysis payload versions.
  const probableCause =
    analysis?.primaryFinding?.probableCause || analysis?.cause || analysis?.explanation || analysis?.issue || fallbackAnalysis.probableCause;
  const recommendedAction =
    analysis?.primaryFinding?.recommendedAction || analysis?.solution || fallbackAnalysis.recommendedAction;
  const mikrotikChecks =
    analysis?.primaryFinding?.mikrotikChecks || analysis?.suggestedChecks || analysis?.mikrotikChecks || fallbackAnalysis.mikrotikChecks;
  const routerOsCommand =
    analysis?.primaryFinding?.routerOsCommand || analysis?.routerOsCommand || fallbackAnalysis.routerOsCommand;

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
            <p>{probableCause}</p>

            <h3>Recommended next action</h3>
            <p>{recommendedAction}</p>

            {analysis?.context && (
              <>
                <h3>Realistic context</h3>
                <p>{analysis.context}</p>
              </>
            )}

            <h3>Suggested MikroTik-side checks</h3>
            <ul>
              {mikrotikChecks.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>

            <h3>RouterOS command suggestion</h3>
            <code>{routerOsCommand}</code>
          </div>
        )}
      </section>
    </main>
  );
}

export default App;