import { useMemo, useState } from 'react';

const isValidIpv4 = (value) => /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(value.trim());

function ChangeGateway() {
  const [oldGateway, setOldGateway] = useState('192.168.1.1');
  const [newGateway, setNewGateway] = useState('192.168.178.1');

  const command = useMemo(() => {
    if (!isValidIpv4(oldGateway) || !isValidIpv4(newGateway)) return 'N/A';
    return `/ip route set [find where gateway=${oldGateway.trim()}] gateway=${newGateway.trim()}`;
  }, [oldGateway, newGateway]);

  return (
    <div className="card action-panel">
      <h3>🚪 Change Gateway</h3>
      <div className="port-forward-grid">
        <div><label>Old Gateway</label><input value={oldGateway} onChange={(e) => setOldGateway(e.target.value)} /></div>
        <div><label>New Gateway</label><input value={newGateway} onChange={(e) => setNewGateway(e.target.value)} /></div>
      </div>
      <p className="help-text">Preview command before running it directly on RouterOS.</p>
      <code>{command}</code>
    </div>
  );
}

export default ChangeGateway;