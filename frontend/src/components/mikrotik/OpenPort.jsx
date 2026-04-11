import { useMemo, useState } from 'react';

const isValidIpv4 = (value) => /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(value.trim());
const isValidPort = (value) => Number.isInteger(Number(value)) && Number(value) >= 1 && Number(value) <= 65535;

function OpenPort({ credentials }) {
  const [publicIp, setPublicIp] = useState('');
  const [externalPort, setExternalPort] = useState('5060');
  const [protocol, setProtocol] = useState('udp');
  const [internalIp, setInternalIp] = useState('');
  const [internalPort, setInternalPort] = useState('5060');
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const validationError = useMemo(() => {
    if (publicIp.trim() && !isValidIpv4(publicIp)) return 'Public IP invalid.';
    if (!isValidIpv4(internalIp)) return 'Internal IP invalid.';
    if (!isValidPort(externalPort) || !isValidPort(internalPort)) return 'Port must be 1-65535.';
    return '';
  }, [publicIp, internalIp, externalPort, internalPort]);

  const apply = async () => {
    if (validationError) {
      setError(validationError);
      return;
    }

    setError('');
    const response = await fetch('/api/v1/mikrotik/port-forward', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        mikrotik: credentials,
        config: {
          publicIp: publicIp.trim(),
          externalPort: Number(externalPort),
          protocol,
          internalIp: internalIp.trim(),
          internalPort: Number(internalPort),
        },
      }),
    });

    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      setError(body.error?.message || 'Failed to apply port forwarding.');
      return;
    }

    setResult(body);
  };

  return (
    <div className="card action-panel">
      <h3>🌐 Open Port</h3>
      <div className="port-forward-grid">
        <div><label>Public IP (optional)</label><input value={publicIp} onChange={(e) => setPublicIp(e.target.value)} /></div>
        <div><label>External Port</label><input value={externalPort} onChange={(e) => setExternalPort(e.target.value)} /></div>
        <div><label>Protocol</label><select value={protocol} onChange={(e) => setProtocol(e.target.value)}><option value="udp">UDP</option><option value="tcp">TCP</option></select></div>
        <div><label>Internal IP</label><input value={internalIp} onChange={(e) => setInternalIp(e.target.value)} /></div>
        <div><label>Internal Port</label><input value={internalPort} onChange={(e) => setInternalPort(e.target.value)} /></div>
      </div>
      <button type="button" onClick={apply}>Apply</button>
      {error && <div className="alert">{error}</div>}
      {result?.commands && <code>{`${result.commands.nat}\n${result.commands.filter}`}</code>}
    </div>
  );
}

export default OpenPort;