import { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';

const ipv4Regex = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

function MainPage() {
  const navigate = useNavigate();
  const [target, setTarget] = useState('');
  const [safeRangeScan, setSafeRangeScan] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);

  const [mikrotikHost, setMikrotikHost] = useState('');
  const [mikrotikPort, setMikrotikPort] = useState('22');
  const [mikrotikUsername, setMikrotikUsername] = useState('');
  const [mikrotikPassword, setMikrotikPassword] = useState('');
  const [connecting, setConnecting] = useState(false);

  const credentialsError = useMemo(() => {
    if (!mikrotikHost.trim()) return 'MikroTik host is required.';
    if (!mikrotikUsername.trim()) return 'MikroTik username is required.';
    if (!mikrotikPassword) return 'MikroTik password is required.';
    if (!ipv4Regex.test(mikrotikHost.trim()) && !/^[a-zA-Z0-9.-]+$/.test(mikrotikHost.trim())) {
      return 'MikroTik host must be a valid IP or hostname.';
    }
    return '';
  }, [mikrotikHost, mikrotikUsername, mikrotikPassword]);

  const runDiagnostic = async () => {
    if (!target.trim()) {
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
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target.trim(), safeRangeScan }),
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

  const connectMikrotik = async () => {
    if (credentialsError) {
      setError(credentialsError);
      return;
    }

    setConnecting(true);
    setError('');

    try {
      const payload = {
        target: target.trim() || mikrotikHost.trim(),
        mikrotik: {
          host: mikrotikHost.trim(),
          username: mikrotikUsername.trim(),
          password: mikrotikPassword,
          port: Number(mikrotikPort) || 22,
        },
        safeRangeScan: true,
      };

      const startResponse = await fetch('/api/v1/diagnostics', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (!startResponse.ok) {
        const failedBody = await startResponse.json().catch(() => ({}));
        throw new Error(failedBody.error?.message || 'Unable to validate MikroTik credentials.');
      }

      const { id } = await startResponse.json();
      const detailResponse = await fetch(`/api/v1/diagnostics/${id}`);
      const details = await detailResponse.json();

      if (!details?.results?.mikrotik?.enabled || details?.results?.mikrotik?.authFailed) {
        throw new Error('MikroTik login failed. Please verify host/username/password.');
      }

      const credentials = {
        host: mikrotikHost.trim(),
        port: Number(mikrotikPort) || 22,
        username: mikrotikUsername.trim(),
        password: mikrotikPassword,
      };

      sessionStorage.setItem('mikrotikCredentials', JSON.stringify(credentials));
      navigate('/mikrotik-dashboard', { state: { credentials } });
    } catch (requestError) {
      setError(requestError.message || 'Unable to connect to MikroTik.');
    } finally {
      setConnecting(false);
    }
  };

  return (
    <main className="page">
      <section className="card">
        <h1>VoIP / MikroTik Diagnostic</h1>
        <p className="help-text">Run diagnostics or connect to MikroTik dashboard.</p>

        <div className="form-row">
          <label htmlFor="target">Target IP or hostname</label>
          <input id="target" type="text" value={target} onChange={(event) => setTarget(event.target.value)} placeholder="203.0.113.10" />

          <label className="checkbox-row" htmlFor="safe-range-scan">
            <input id="safe-range-scan" type="checkbox" checked={safeRangeScan} onChange={(event) => setSafeRangeScan(event.target.checked)} />
            <span>Safe scan mode (ports 1-1024)</span>
          </label>

          <button type="button" onClick={runDiagnostic} disabled={loading}>{loading ? 'Running...' : 'Run diagnostic'}</button>
        </div>
      </section>

      <section className="card">
        <h2>Connect to MikroTik</h2>
        <div className="mikrotik-credentials">
          <label htmlFor="mikrotik-host">MikroTik host</label>
          <input id="mikrotik-host" type="text" value={mikrotikHost} onChange={(event) => setMikrotikHost(event.target.value)} />

          <label htmlFor="mikrotik-port">MikroTik SSH port</label>
          <input id="mikrotik-port" type="number" value={mikrotikPort} onChange={(event) => setMikrotikPort(event.target.value)} />

          <label htmlFor="mikrotik-username">MikroTik username</label>
          <input id="mikrotik-username" type="text" value={mikrotikUsername} onChange={(event) => setMikrotikUsername(event.target.value)} />

          <label htmlFor="mikrotik-password">MikroTik password</label>
          <input id="mikrotik-password" type="password" value={mikrotikPassword} onChange={(event) => setMikrotikPassword(event.target.value)} />
        </div>

        <button type="button" onClick={connectMikrotik} disabled={connecting}>
          {connecting ? 'Connecting...' : 'Open MikroTik Dashboard'}
        </button>
      </section>

      {error && <div className="card alert" role="alert">{error}</div>}

     {result && (
  <section className="card">
    <h2>Diagnostic Result</h2>
    <p><strong>Target:</strong> {result.target}</p>
    <p><strong>Status:</strong> {result.status}</p>
    <p><strong>Cause:</strong> {result.analysis?.primaryFinding?.probableCause || result.analysis?.cause || 'N/A'}</p>
    <p><strong>Action:</strong> {result.analysis?.primaryFinding?.recommendedAction || result.analysis?.solution || 'N/A'}</p>

    <h3>Tested ports</h3>
    {Array.isArray(result?.results?.ports?.ports) && result.results.ports.ports.length > 0 ? (
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
            {result.results.ports.ports.map((port) => (
              <tr key={`${port.port}-${port.service || 'unknown'}`}>
                <td>{port.port}</td>
                <td>
                  <span className={port.open ? 'state-open' : 'state-closed'}>
                    {port.open ? 'Open' : 'Closed'}
                  </span>
                </td>
                <td>{port.service || 'unknown'}</td>
                <td>{port.responseTimeMs ?? port.responseTime ?? 0} ms</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    ) : (
      <p className="help-text">No port scan data returned for this run.</p>
    )}
  </section>
)}
    </main>
  );
}

export default MainPage;