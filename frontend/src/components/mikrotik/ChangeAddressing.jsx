import { useState } from 'react';

function ChangeAddressing({ credentials }) {
  const [form, setForm] = useState({
    oldNetwork: '192.168.1.0/24',
    oldGateway: '192.168.1.1/24',
    newNetwork: '192.168.178.0/24',
    newGateway: '192.168.178.1/24',
    interface: 'bridge1',
    dhcpPoolStart: '192.168.178.10',
    dhcpPoolEnd: '192.168.178.200',
    dnsServer: '8.8.8.8',
    dhcpName: 'LAN_DATA',
  });
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const update = (key, value) => setForm((prev) => ({ ...prev, [key]: value }));

  const apply = async () => {
    setError('');
    const response = await fetch('/api/v1/mikrotik/change-lan-network', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mikrotik: credentials, config: form }),
    });

    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      setError(body.error?.message || 'Failed to change network addressing.');
      return;
    }

    setResult(body);
  };

  return (
    <div className="card action-panel">
      <h3>🧭 Change Network Addressing</h3>
      <div className="port-forward-grid">
        {Object.entries(form).map(([key, value]) => (
          <div key={key}>
            <label>{key}</label>
            <input value={value} onChange={(e) => update(key, e.target.value)} />
          </div>
        ))}
      </div>
      <button type="button" onClick={apply}>Apply</button>
      {error && <div className="alert">{error}</div>}
      {result?.commands && <code>{Object.values(result.commands).join('\n')}</code>}
    </div>
  );
}

export default ChangeAddressing;