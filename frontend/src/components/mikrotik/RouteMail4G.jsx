import { useMemo, useState } from 'react';

const isValidIpv4 = (value) => /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(value.trim());

const buildMail4gCommands = ({ deviceType, lanInterface, wan4gInterface, gateway4g }) => {
  if (deviceType === 'mr100') {
    return [
      '/routing table add name=mail_via_4g fib',
      `/ip route add dst-address=0.0.0.0/0 gateway=${gateway4g}@main routing-table=mail_via_4g comment="Route mail via MR100 4G"`,
      `/ip firewall mangle add chain=prerouting in-interface=${lanInterface} protocol=tcp dst-port=25,110,143,465,587,993,995 dst-address-type=!local connection-state=new action=mark-connection new-connection-mark=mail_4g_conn passthrough=yes comment="Mark mail connections to 4G"`,
      `/ip firewall mangle add chain=prerouting in-interface=${lanInterface} connection-mark=mail_4g_conn action=mark-routing new-routing-mark=mail_via_4g passthrough=no comment="Route marked mail via 4G"`,
      '/ip firewall filter add chain=forward connection-mark=mail_4g_conn action=accept place-before=[find where action=fasttrack-connection] comment="Bypass FastTrack for mail via 4G"',
      `/ip firewall nat add chain=srcnat out-interface=${wan4gInterface} action=masquerade comment="NAT mail via 4G"`,
    ];
  }

  return [
    '/routing table add name=mail_via_lte fib',
    '/ip route add dst-address=0.0.0.0/0 gateway=lte1 routing-table=mail_via_lte comment="Mail via LTE Chateau"',
    `/ip firewall mangle add chain=prerouting in-interface=${lanInterface} protocol=tcp dst-port=25,110,143,465,587,993,995 dst-address-type=!local connection-state=new action=mark-connection new-connection-mark=mail_lte_conn passthrough=yes comment="Mark mail connections to LTE"`,
    `/ip firewall mangle add chain=prerouting in-interface=${lanInterface} connection-mark=mail_lte_conn action=mark-routing new-routing-mark=mail_via_lte passthrough=no comment="Route marked mail via LTE"`,
    '/ip firewall filter add chain=forward connection-mark=mail_lte_conn action=accept place-before=[find where action=fasttrack-connection] comment="Bypass FastTrack for mail via LTE"',
    '/ip firewall nat add chain=srcnat out-interface=lte1 action=masquerade comment="NAT via LTE"',
  ];
};

function RouteMail4G({ credentials }) {
  const [deviceType, setDeviceType] = useState('mr100');
  const [lanInterface, setLanInterface] = useState('bridge1');
  const [wan4gInterface, setWan4gInterface] = useState('ether5');
  const [gateway4g, setGateway4g] = useState('192.168.8.1');
  const [preview, setPreview] = useState([]);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const validationError = useMemo(() => {
    if (!lanInterface.trim()) return 'LAN interface is required.';
    if (!wan4gInterface.trim()) return '4G interface is required.';
    if (deviceType === 'mr100' && !isValidIpv4(gateway4g)) return '4G gateway must be a valid IPv4 address.';
    return '';
  }, [deviceType, lanInterface, wan4gInterface, gateway4g]);

  const onChangeDevice = (value) => {
    setDeviceType(value);
    setWan4gInterface(value === 'mr100' ? 'ether5' : 'lte1');
  };

  const previewConfiguration = () => {
    if (validationError) {
      setError(validationError);
      setPreview([]);
      return;
    }

    setError('');
    setResult(null);
    setPreview(
      buildMail4gCommands({
        deviceType,
        lanInterface: lanInterface.trim(),
        wan4gInterface: wan4gInterface.trim(),
        gateway4g: gateway4g.trim(),
      })
    );
  };

  const applyConfiguration = async () => {
    if (validationError) {
      setError(validationError);
      return;
    }

    if (!window.confirm('Mail traffic will be routed via 4G backup. Continue?')) {
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const response = await fetch('/api/v1/mikrotik/route-mail-4g', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mikrotik: credentials,
          config: {
            deviceType,
            lanInterface: lanInterface.trim(),
            wan4gInterface: wan4gInterface.trim(),
            gateway4g: gateway4g.trim(),
          },
        }),
      });

      const body = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(body.error?.message || 'Failed to route mail traffic via 4G.');
      }

      setResult(body);
      setPreview([]);
    } catch (requestError) {
      setError(requestError.message || 'Failed to route mail traffic via 4G.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="card action-panel">
      <h3>📧📶 Route Mail via 4G</h3>
      <div className="port-forward-grid">
        <div>
          <label htmlFor="device-type">Device Type</label>
          <select id="device-type" value={deviceType} onChange={(event) => onChangeDevice(event.target.value)}>
            <option value="mr100">MR100 (external 4G modem)</option>
            <option value="chateau">Chateau (LTE built-in)</option>
          </select>
        </div>
        <div>
          <label htmlFor="lan-interface">LAN Interface</label>
          <input id="lan-interface" value={lanInterface} onChange={(event) => setLanInterface(event.target.value)} />
        </div>
        <div>
          <label htmlFor="wan4g-interface">4G Interface</label>
          <input id="wan4g-interface" value={wan4gInterface} onChange={(event) => setWan4gInterface(event.target.value)} />
        </div>
        {deviceType === 'mr100' && (
          <div>
            <label htmlFor="gateway4g">4G Gateway</label>
            <input id="gateway4g" value={gateway4g} onChange={(event) => setGateway4g(event.target.value)} placeholder="192.168.8.1" />
          </div>
        )}
      </div>

      <div className="button-row">
        <button type="button" onClick={previewConfiguration}>Preview Configuration</button>
        <button type="button" onClick={applyConfiguration} disabled={loading}>
          {loading ? 'Applying...' : 'Apply Configuration'}
        </button>
      </div>

      {error && <div className="alert">{error}</div>}
      {preview.length > 0 && <code>{preview.join('\n')}</code>}
      {result?.success && <p className="help-text">Mail traffic routing via 4G configured successfully.</p>}
      {Array.isArray(result?.commands) && result.commands.length > 0 && <code>{result.commands.join('\n')}</code>}
    </div>
  );
}

export default RouteMail4G;