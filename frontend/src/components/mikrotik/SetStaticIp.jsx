import { useMemo, useState } from 'react';

const isValidIpv4 = (value) => /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(value.trim());

function SetStaticIp({ credentials }) {
  const [publicIp, setPublicIp] = useState('');
  const [outInterface, setOutInterface] = useState('');
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const validationError = useMemo(() => {
    if (!isValidIpv4(publicIp)) return 'Public IP invalid.';
    if (!outInterface.trim()) return 'Out interface required.';
    return '';
  }, [publicIp, outInterface]);

  const apply = async () => {
    if (validationError) {
      setError(validationError);
      return;
    }

    setError('');
    const response = await fetch('/api/v1/mikrotik/set-static-ip', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mikrotik: credentials, config: { publicIp: publicIp.trim(), outInterface: outInterface.trim() } }),
    });

    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      setError(body.error?.message || 'Failed to set static IP.');
      return;
    }

    setResult(body);
  };

  return (
    <div className="card action-panel">
      <h3>📌 Set Static IP</h3>
      <div className="port-forward-grid">
        <div><label>Public IP</label><input value={publicIp} onChange={(e) => setPublicIp(e.target.value)} /></div>
        <div><label>Out Interface</label><input value={outInterface} onChange={(e) => setOutInterface(e.target.value)} /></div>
      </div>
      <button type="button" onClick={apply}>Apply</button>
      {error && <div className="alert">{error}</div>}
      {result?.commands && <code>{`${result.commands.addressList}\n${result.commands.srcNat}`}</code>}
    </div>
  );
}

export default SetStaticIp;