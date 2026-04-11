import { useMemo, useState } from 'react';

const buildWifiCommands = ({ ssid, wifiPassword }) => ({
  wlan1: `/interface wireless set [find default-name=wlan1] ssid="${ssid}" security-profile=default wps-mode=disabled`,
  wlan2: `/interface wireless set [find default-name=wlan2] ssid="${ssid}" security-profile=default wps-mode=disabled`,
  security:
    `/interface wireless security-profiles set [find name="default"] mode=dynamic-keys authentication-types=wpa2-psk ` +
    `unicast-ciphers=aes-ccm group-ciphers=aes-ccm wpa2-pre-shared-key="${wifiPassword}"`,
});

const maskWifiPasswordInCommand = (value = '') =>
  value.replace(/wpa2-pre-shared-key="[^"]*"/g, 'wpa2-pre-shared-key="********"');

function UpdateWifi({ credentials }) {
  const [ssid, setSsid] = useState('');
  const [wifiPassword, setWifiPassword] = useState('');
  const [preview, setPreview] = useState(null);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const validationError = useMemo(() => {
    if (!ssid.trim()) return 'SSID is required.';
    if (wifiPassword.length < 8) return 'WiFi password must be at least 8 characters.';
    return '';
  }, [ssid, wifiPassword]);

  const previewConfiguration = () => {
    if (validationError) {
      setError(validationError);
      setPreview(null);
      return;
    }

    const commands = buildWifiCommands({ ssid: ssid.trim(), wifiPassword });
    setError('');
    setResult(null);
    setPreview({
      wlan1: commands.wlan1,
      wlan2: commands.wlan2,
      security: maskWifiPasswordInCommand(commands.security),
    });
  };

  const applyConfiguration = async () => {
    if (validationError) {
      setError(validationError);
      return;
    }

    if (!window.confirm('Changing WiFi will disconnect clients. Continue?')) {
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const response = await fetch('/api/v1/mikrotik/update-wifi', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mikrotik: credentials,
          config: {
            ssid: ssid.trim(),
            wifiPassword,
          },
        }),
      });

      const body = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(body.error?.message || 'Failed to update WiFi configuration.');
      }

      setResult({
        ...body,
        commands: {
          ...body.commands,
          security: maskWifiPasswordInCommand(body.commands?.security || ''),
        },
      });
      setPreview(null);
    } catch (requestError) {
      setError(requestError.message || 'Failed to update WiFi configuration.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="card action-panel">
      <h3>📶 Change WiFi Settings</h3>
      <div className="port-forward-grid">
        <div>
          <label htmlFor="wifi-ssid">SSID</label>
          <input id="wifi-ssid" value={ssid} onChange={(event) => setSsid(event.target.value)} />
        </div>
        <div>
          <label htmlFor="wifi-password">WiFi Password</label>
          <input
            id="wifi-password"
            type="password"
            value={wifiPassword}
            onChange={(event) => setWifiPassword(event.target.value)}
          />
        </div>
      </div>

      <div className="button-row">
        <button type="button" onClick={previewConfiguration}>Preview Configuration</button>
        <button type="button" onClick={applyConfiguration} disabled={loading}>
          {loading ? 'Applying...' : 'Apply Configuration'}
        </button>
      </div>

      {error && <div className="alert">{error}</div>}
      {preview && <code>{`${preview.wlan1}\n${preview.wlan2}\n${preview.security}`}</code>}
      {result?.success && <p className="help-text">WiFi configuration updated successfully</p>}
      {result?.commands && <code>{`${result.commands.wlan1}\n${result.commands.wlan2}\n${result.commands.security}`}</code>}
    </div>
  );
}

export default UpdateWifi;