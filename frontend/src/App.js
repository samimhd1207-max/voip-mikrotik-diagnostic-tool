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
  const [useMikrotikAccess, setUseMikrotikAccess] = useState(false);
  const [mikrotikHost, setMikrotikHost] = useState('');
  const [mikrotikPort, setMikrotikPort] = useState('22');
  const [mikrotikUsername, setMikrotikUsername] = useState('');
  const [mikrotikPassword, setMikrotikPassword] = useState('');
  const [safeRangeScan, setSafeRangeScan] = useState(false);
  const [showOnlyOpen, setShowOnlyOpen] = useState(false);
  const [portSearch, setPortSearch] = useState('');
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

    let payload = { target: trimmedTarget, safeRangeScan };
    if (useMikrotikAccess) {
      if (!mikrotikHost.trim() || !mikrotikUsername.trim() || !mikrotikPassword) {
        setError('Please enter MikroTik host, username, and password.');
        setResult(null);
        return;
      }

      payload = {
        ...payload,
        mikrotik: {
          host: mikrotikHost.trim(),
          username: mikrotikUsername.trim(),
          password: mikrotikPassword,
          port: Number(mikrotikPort) || 22,
        },
      };
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
        body: JSON.stringify(payload),
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

  const probableCause =
    analysis?.primaryFinding?.probableCause || analysis?.cause || analysis?.explanation || analysis?.issue || fallbackAnalysis.probableCause;
  const recommendedAction =
    analysis?.primaryFinding?.recommendedAction || analysis?.solution || fallbackAnalysis.recommendedAction;
  const mikrotikChecks =
    analysis?.primaryFinding?.mikrotikChecks || analysis?.suggestedChecks || analysis?.mikrotikChecks || fallbackAnalysis.mikrotikChecks;
  const routerOsCommand =
    analysis?.primaryFinding?.routerOsCommand || analysis?.routerOsCommand || fallbackAnalysis.routerOsCommand;
  const confidence =
    Number.isFinite(analysis?.confidence) ? analysis.confidence : Number.isFinite(analysis?.confidenceScore) ? analysis.confidenceScore : 35;
  const confidenceClass = confidence > 80 ? 'confidence-high' : confidence >= 50 ? 'confidence-medium' : 'confidence-low';
  const allPortRows = result?.results?.ports?.ports || [];
  const filteredPortRows = allPortRows.filter((row) => {
    const matchOpen = showOnlyOpen ? row.open : true;
    const matchSearch = portSearch.trim() ? String(row.port).includes(portSearch.trim()) : true;
    return matchOpen && matchSearch;
  });
  const openRows = filteredPortRows.filter((row) => row.open);
  const closedRows = filteredPortRows.filter((row) => !row.open);
  const visibleRows = [...openRows, ...closedRows].slice(0, 50);

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
          <label className="checkbox-row" htmlFor="use-mikrotik-access">
            <input
              id="use-mikrotik-access"
              type="checkbox"
              checked={useMikrotikAccess}
              onChange={(event) => setUseMikrotikAccess(event.target.checked)}
            />
            <span>Connect to MikroTik via SSH (username + password)</span>
          </label>

          {useMikrotikAccess && (
            <div className="mikrotik-credentials">
              <label htmlFor="mikrotik-host">MikroTik host</label>
              <input
                id="mikrotik-host"
                type="text"
                placeholder="203.0.113.10"
                value={mikrotikHost}
                onChange={(event) => setMikrotikHost(event.target.value)}
              />

              <label htmlFor="mikrotik-port">MikroTik SSH port</label>
              <input
                id="mikrotik-port"
                type="number"
                min="1"
                max="65535"
                value={mikrotikPort}
                onChange={(event) => setMikrotikPort(event.target.value)}
              />

              <label htmlFor="mikrotik-username">MikroTik username</label>
              <input
                id="mikrotik-username"
                type="text"
                placeholder="admin"
                value={mikrotikUsername}
                onChange={(event) => setMikrotikUsername(event.target.value)}
              />

              <label htmlFor="mikrotik-password">MikroTik password</label>
              <input
                id="mikrotik-password"
                type="password"
                value={mikrotikPassword}
                onChange={(event) => setMikrotikPassword(event.target.value)}
              />
            </div>
          )}
          <label className="checkbox-row" htmlFor="safe-range-scan">
            <input
              id="safe-range-scan"
              type="checkbox"
              checked={safeRangeScan}
              onChange={(event) => setSafeRangeScan(event.target.checked)}
            />
            <span>Safe scan mode (ports 1-1024)</span>
          </label>

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
              <div>
                <span className="label">Confidence</span>
                <strong className={confidenceClass}>{confidence}%</strong>
              </div>
            </div>

            <h3>Tested ports</h3>
            <div className="port-tools">
              <label className="checkbox-row" htmlFor="show-open-only">
                <input
                  id="show-open-only"
                  type="checkbox"
                  checked={showOnlyOpen}
                  onChange={(event) => setShowOnlyOpen(event.target.checked)}
                />
                <span>Show only open ports</span>
              </label>
              <input
                type="text"
                placeholder="Search port (e.g. 5060)"
                value={portSearch}
                onChange={(event) => setPortSearch(event.target.value)}
              />
            </div>
            <p className="port-group-label">Open Ports: {openRows.length} | Closed Ports: {closedRows.length}</p>
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Port</th>
                    <th>State</th>
                    <th>Service</th>
                    <th>Response Time</th>
                  </tr>
                </thead>
                <tbody>
                  {visibleRows.map((port) => (
                    <tr key={port.port}>
                      <td>{port.port}</td>
                      <td>
                        <span className={port.open ? 'state-open' : 'state-closed'}>{port.open ? 'Open' : 'Closed'}</span>
                      </td>
                      <td>{port.service || 'unknown'}</td>
                      <td>{port.responseTime ?? port.responseTimeMs} ms</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

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