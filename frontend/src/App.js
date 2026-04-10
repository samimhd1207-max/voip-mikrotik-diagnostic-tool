import { useMemo, useState } from 'react';
import './App.css';

const ipv4Regex = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

const isValidIpv4 = (value) => ipv4Regex.test(value.trim());
const isValidPort = (value) => Number.isInteger(Number(value)) && Number(value) >= 1 && Number(value) <= 65535;

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

const buildPortForwardCommands = ({ publicIp, externalPort, protocol, internalIp, internalPort }) => ({
  nat: [
    '/ip firewall nat add',
    'chain=dstnat',
    `protocol=${protocol}`,
    `dst-port=${externalPort}`,
    ...(publicIp ? [`dst-address=${publicIp}`] : []),
    'action=dst-nat',
    `to-addresses=${internalIp}`,
    `to-ports=${internalPort}`,
  ].join(' '),
  filter: [
    '/ip firewall filter add',
    'chain=forward',
    `protocol=${protocol}`,
    `dst-port=${externalPort}`,
    `dst-address=${internalIp}`,
    'action=accept',
  ].join(' '),
});

const buildStaticIpCommands = ({ publicIp, outInterface }) => ({
  addressList: `/ip firewall address-list add list=public-add address=${publicIp} comment=\"Static public IP\"`,
  srcNat: `/ip firewall nat add chain=srcnat out-interface=${outInterface} action=src-nat to-addresses=${publicIp} comment=\"Static public IP\"`,
});

const buildLanNetworkCommands = ({
  oldNetwork,
  oldGateway,
  newNetwork,
  newGateway,
  interfaceName,
  dhcpPoolStart,
  dhcpPoolEnd,
  dnsServer,
  dhcpName,
}) => {
  const newNetworkWithoutMask = newNetwork.split('/')[0];
  const newGatewayWithoutMask = newGateway.split('/')[0];

  return {
    ip: `/ip address set [find where address=\"${oldGateway}\"] address=${newGateway} network=${newNetworkWithoutMask} interface=${interfaceName} comment=\"LAN DATA\"`,
    pool: `/ip pool set [find where name=\"default-dhcp\"] name=${dhcpName} ranges=${dhcpPoolStart}-${dhcpPoolEnd} next-pool=none`,
    firewall: `/ip firewall address-list set [find where list=\"LAN\" and address=\"${oldNetwork}\"] address=${newNetwork}`,
    dhcp: `/ip dhcp-server set [find where name=\"defconf\"] name=${dhcpName} interface=${interfaceName} address-pool=${dhcpName} disabled=no`,
    dhcpNetwork: `/ip dhcp-server network set [find where address=\"${oldNetwork}\"] address=${newNetwork} gateway=${newGatewayWithoutMask} dns-server=${dnsServer}`,
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

  const [publicIp, setPublicIp] = useState('');
  const [externalPort, setExternalPort] = useState('5060');
  const [protocol, setProtocol] = useState('udp');
  const [internalIp, setInternalIp] = useState('');
  const [internalPort, setInternalPort] = useState('5060');
  const [portForwardError, setPortForwardError] = useState('');
  const [portForwardSuccess, setPortForwardSuccess] = useState('');
  const [portForwardCommands, setPortForwardCommands] = useState(null);
  const [portForwardLoading, setPortForwardLoading] = useState(false);

  const [staticPublicIp, setStaticPublicIp] = useState('');
  const [outInterface, setOutInterface] = useState('');
  const [staticIpError, setStaticIpError] = useState('');
  const [staticIpSuccess, setStaticIpSuccess] = useState('');
  const [staticIpCommands, setStaticIpCommands] = useState(null);
  const [staticIpLoading, setStaticIpLoading] = useState(false);

  const [oldNetwork, setOldNetwork] = useState('192.168.1.0/24');
  const [oldGateway, setOldGateway] = useState('192.168.1.1/24');
  const [newNetwork, setNewNetwork] = useState('192.168.178.0/24');
  const [newGateway, setNewGateway] = useState('192.168.178.1/24');
  const [lanInterface, setLanInterface] = useState('bridge1');
  const [dhcpPoolStart, setDhcpPoolStart] = useState('192.168.178.12');
  const [dhcpPoolEnd, setDhcpPoolEnd] = useState('192.168.178.249');
  const [dnsServer, setDnsServer] = useState('100.100.15.30');
  const [dhcpName, setDhcpName] = useState('LAN_DATA');
  const [lanError, setLanError] = useState('');
  const [lanSuccess, setLanSuccess] = useState('');
  const [lanCommands, setLanCommands] = useState(null);
  const [lanLoading, setLanLoading] = useState(false);

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
        headers: { 'Content-Type': 'application/json' },
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

  const portForwardValidationError = useMemo(() => {
    if (!mikrotikHost.trim() || !mikrotikUsername.trim() || !mikrotikPassword) {
      return 'MikroTik host, username, and password are required for port forwarding.';
    }
    if (publicIp.trim() && !isValidIpv4(publicIp)) {
      return 'Public IP must be a valid IPv4 address when provided.';
    }
    if (!isValidIpv4(internalIp)) {
      return 'Internal IP must be a valid IPv4 address.';
    }
    if (!isValidPort(externalPort)) {
      return 'External Port must be a valid number between 1 and 65535.';
    }
    if (!isValidPort(internalPort)) {
      return 'Internal Port must be a valid number between 1 and 65535.';
    }
    return '';
  }, [mikrotikHost, mikrotikUsername, mikrotikPassword, publicIp, internalIp, externalPort, internalPort]);

  const staticIpValidationError = useMemo(() => {
    if (!mikrotikHost.trim() || !mikrotikUsername.trim() || !mikrotikPassword) {
      return 'MikroTik host, username, and password are required for static IP configuration.';
    }
    if (!isValidIpv4(staticPublicIp)) {
      return 'Public IP must be a valid IPv4 address.';
    }
    if (!outInterface.trim()) {
      return 'Out Interface is required.';
    }
    return '';
  }, [mikrotikHost, mikrotikUsername, mikrotikPassword, staticPublicIp, outInterface]);

  const lanValidationError = useMemo(() => {
    const cidrRegex = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}\/(3[0-2]|[12]?\d)$/;
    const toInt = (ip) => ip.split('.').map(Number).reduce((acc, octet) => (acc << 8) + octet, 0) >>> 0;

    if (!mikrotikHost.trim() || !mikrotikUsername.trim() || !mikrotikPassword) {
      return 'MikroTik host, username, and password are required for LAN configuration.';
    }

    const cidrFields = [oldNetwork, oldGateway, newNetwork, newGateway];
    if (cidrFields.some((value) => !cidrRegex.test(value.trim()))) {
      return 'Old/New network and gateway must be valid CIDR values (e.g. 192.168.1.1/24).';
    }

    const ipFields = [dhcpPoolStart, dhcpPoolEnd, dnsServer];
    if (ipFields.some((value) => !isValidIpv4(value))) {
      return 'DHCP pool start/end and DNS server must be valid IPv4 addresses.';
    }

    if (toInt(dhcpPoolStart.trim()) > toInt(dhcpPoolEnd.trim())) {
      return 'DHCP Pool Start must be lower than or equal to DHCP Pool End.';
    }

    if (!lanInterface.trim() || !dhcpName.trim()) {
      return 'Interface and DHCP Name are required.';
    }

    return '';
  }, [
    mikrotikHost,
    mikrotikUsername,
    mikrotikPassword,
    oldNetwork,
    oldGateway,
    newNetwork,
    newGateway,
    dhcpPoolStart,
    dhcpPoolEnd,
    dnsServer,
    lanInterface,
    dhcpName,
  ]);

  const previewPortForwardCommand = () => {
    setPortForwardError('');
    setPortForwardSuccess('');
    if (portForwardValidationError) {
      setPortForwardCommands(null);
      setPortForwardError(portForwardValidationError);
      return;
    }

    setPortForwardCommands(
      buildPortForwardCommands({
        publicIp: publicIp.trim(),
        externalPort: Number(externalPort),
        protocol,
        internalIp: internalIp.trim(),
        internalPort: Number(internalPort),
      })
    );
  };

  const applyPortForwarding = async () => {
    setPortForwardError('');
    setPortForwardSuccess('');
    if (portForwardValidationError) {
      setPortForwardCommands(null);
      setPortForwardError(portForwardValidationError);
      return;
    }

    const confirmed = window.confirm('Are you sure you want to apply this configuration?');
    if (!confirmed) return;

    const payload = {
      mikrotik: {
        host: mikrotikHost.trim(),
        username: mikrotikUsername.trim(),
        password: mikrotikPassword,
        port: Number(mikrotikPort) || 22,
      },
      config: {
        publicIp: publicIp.trim(),
        externalPort: Number(externalPort),
        internalIp: internalIp.trim(),
        internalPort: Number(internalPort),
        protocol,
      },
    };

    setPortForwardLoading(true);
    try {
      const response = await fetch('/api/v1/mikrotik/port-forward', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      const body = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(body.error?.message || 'Failed to apply port forwarding configuration.');
      }

      setPortForwardCommands(body.commands);
      setPortForwardSuccess('Port forwarding configuration applied successfully.');
    } catch (requestError) {
      setPortForwardError(requestError.message || 'Unexpected error applying port forwarding configuration.');
    } finally {
      setPortForwardLoading(false);
    }
  };

  const previewStaticIpConfiguration = () => {
    setStaticIpError('');
    setStaticIpSuccess('');
    if (staticIpValidationError) {
      setStaticIpCommands(null);
      setStaticIpError(staticIpValidationError);
      return;
    }

    setStaticIpCommands(
      buildStaticIpCommands({
        publicIp: staticPublicIp.trim(),
        outInterface: outInterface.trim(),
      })
    );
  };

  const applyStaticIpConfiguration = async () => {
    setStaticIpError('');
    setStaticIpSuccess('');
    if (staticIpValidationError) {
      setStaticIpCommands(null);
      setStaticIpError(staticIpValidationError);
      return;
    }

    const confirmed = window.confirm('Are you sure you want to assign this public IP?');
    if (!confirmed) return;

    const payload = {
      mikrotik: {
        host: mikrotikHost.trim(),
        username: mikrotikUsername.trim(),
        password: mikrotikPassword,
        port: Number(mikrotikPort) || 22,
      },
      config: {
        publicIp: staticPublicIp.trim(),
        outInterface: outInterface.trim(),
      },
    };

    setStaticIpLoading(true);
    try {
      const response = await fetch('/api/v1/mikrotik/set-static-ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      const body = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(body.error?.message || 'Failed to apply static public IP configuration.');
      }

      setStaticIpCommands(body.commands);
      setStaticIpSuccess('Static public IP configuration applied successfully.');
    } catch (requestError) {
      setStaticIpError(requestError.message || 'Unexpected error applying static public IP configuration.');
    } finally {
      setStaticIpLoading(false);
    }
  };

  const previewLanConfiguration = () => {
    setLanError('');
    setLanSuccess('');
    if (lanValidationError) {
      setLanCommands(null);
      setLanError(lanValidationError);
      return;
    }

    setLanCommands(
      buildLanNetworkCommands({
        oldNetwork: oldNetwork.trim(),
        oldGateway: oldGateway.trim(),
        newNetwork: newNetwork.trim(),
        newGateway: newGateway.trim(),
        interfaceName: lanInterface.trim(),
        dhcpPoolStart: dhcpPoolStart.trim(),
        dhcpPoolEnd: dhcpPoolEnd.trim(),
        dnsServer: dnsServer.trim(),
        dhcpName: dhcpName.trim(),
      })
    );
  };

  const applyLanConfiguration = async () => {
    setLanError('');
    setLanSuccess('');
    if (lanValidationError) {
      setLanCommands(null);
      setLanError(lanValidationError);
      return;
    }

    const confirmed = window.confirm('WARNING: This will change LAN network and may disconnect you. Continue?');
    if (!confirmed) return;

    const payload = {
      mikrotik: {
        host: mikrotikHost.trim(),
        username: mikrotikUsername.trim(),
        password: mikrotikPassword,
        port: Number(mikrotikPort) || 22,
      },
      config: {
        oldNetwork: oldNetwork.trim(),
        oldGateway: oldGateway.trim(),
        newNetwork: newNetwork.trim(),
        newGateway: newGateway.trim(),
        interface: lanInterface.trim(),
        dhcpPoolStart: dhcpPoolStart.trim(),
        dhcpPoolEnd: dhcpPoolEnd.trim(),
        dnsServer: dnsServer.trim(),
        dhcpName: dhcpName.trim(),
      },
    };

    setLanLoading(true);
    try {
      const response = await fetch('/api/v1/mikrotik/change-lan-network', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      const body = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(body.error?.message || 'Failed to apply LAN network configuration.');
      }

      setLanCommands(body.commands);
      setLanSuccess('LAN network configuration applied successfully.');
    } catch (requestError) {
      setLanError(requestError.message || 'Unexpected error applying LAN network configuration.');
    } finally {
      setLanLoading(false);
    }
  };

  const analysis = result?.analysis;
  const fallbackAnalysis = deriveFallbackAnalysisFromResults(result);
  const probableCause =
    analysis?.primaryFinding?.probableCause || analysis?.cause || analysis?.explanation || analysis?.issue || fallbackAnalysis.probableCause;
  const recommendedAction = analysis?.primaryFinding?.recommendedAction || analysis?.solution || fallbackAnalysis.recommendedAction;
  const mikrotikChecks =
    analysis?.primaryFinding?.mikrotikChecks || analysis?.suggestedChecks || analysis?.mikrotikChecks || fallbackAnalysis.mikrotikChecks;
  const routerOsCommand = analysis?.primaryFinding?.routerOsCommand || analysis?.routerOsCommand || fallbackAnalysis.routerOsCommand;
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
        <p className="help-text">Enter the client WAN IP or remote Winbox hostname, then run diagnostics.</p>

        <div className="form-row">
          <label htmlFor="target">Target IP or hostname</label>
          <input id="target" type="text" placeholder="203.0.113.10 or client.example.net" value={target} onChange={(event) => setTarget(event.target.value)} />

          <label className="checkbox-row" htmlFor="use-mikrotik-access">
            <input id="use-mikrotik-access" type="checkbox" checked={useMikrotikAccess} onChange={(event) => setUseMikrotikAccess(event.target.checked)} />
            <span>Connect to MikroTik via SSH (username + password)</span>
          </label>

          <div className="mikrotik-credentials">
            <label htmlFor="mikrotik-host">MikroTik host</label>
            <input id="mikrotik-host" type="text" placeholder="203.0.113.10" value={mikrotikHost} onChange={(event) => setMikrotikHost(event.target.value)} />

            <label htmlFor="mikrotik-port">MikroTik SSH port</label>
            <input id="mikrotik-port" type="number" min="1" max="65535" value={mikrotikPort} onChange={(event) => setMikrotikPort(event.target.value)} />

            <label htmlFor="mikrotik-username">MikroTik username</label>
            <input id="mikrotik-username" type="text" placeholder="admin" value={mikrotikUsername} onChange={(event) => setMikrotikUsername(event.target.value)} />

            <label htmlFor="mikrotik-password">MikroTik password</label>
            <input id="mikrotik-password" type="password" value={mikrotikPassword} onChange={(event) => setMikrotikPassword(event.target.value)} />
          </div>

          <label className="checkbox-row" htmlFor="safe-range-scan">
            <input id="safe-range-scan" type="checkbox" checked={safeRangeScan} onChange={(event) => setSafeRangeScan(event.target.checked)} />
            <span>Safe scan mode (ports 1-1024)</span>
          </label>

          <button type="button" onClick={runDiagnostic} disabled={loading}>
            {loading ? 'Running diagnostic…' : 'Run diagnostic'}
          </button>
        </div>

        {error && <div className="alert" role="alert">{error}</div>}
      </section>

      <section className="card">
        <h2>Port Forwarding Configuration</h2>
        <p className="help-text">Create RouterOS dst-nat + forward filter rules from validated input.</p>
        <div className="port-forward-grid">
          <div>
            <label htmlFor="public-ip">Public IP (optional)</label>
            <input id="public-ip" type="text" placeholder="198.51.100.10" value={publicIp} onChange={(event) => setPublicIp(event.target.value)} />
          </div>
          <div>
            <label htmlFor="external-port">External Port</label>
            <input id="external-port" type="number" min="1" max="65535" value={externalPort} onChange={(event) => setExternalPort(event.target.value)} />
          </div>
          <div>
            <label htmlFor="protocol">Protocol</label>
            <select id="protocol" value={protocol} onChange={(event) => setProtocol(event.target.value)}>
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
            </select>
          </div>
          <div>
            <label htmlFor="internal-ip">Internal IP</label>
            <input id="internal-ip" type="text" placeholder="192.168.1.50" value={internalIp} onChange={(event) => setInternalIp(event.target.value)} />
          </div>
          <div>
            <label htmlFor="internal-port">Internal Port</label>
            <input id="internal-port" type="number" min="1" max="65535" value={internalPort} onChange={(event) => setInternalPort(event.target.value)} />
          </div>
        </div>

        <div className="button-row">
          <button type="button" onClick={previewPortForwardCommand}>Preview Command</button>
          <button type="button" onClick={applyPortForwarding} disabled={portForwardLoading}>
            {portForwardLoading ? 'Applying configuration…' : 'Apply Configuration'}
          </button>
        </div>

        {portForwardError && <div className="alert" role="alert">{portForwardError}</div>}
        {portForwardSuccess && <div className="alert success-alert">{portForwardSuccess}</div>}

        {portForwardCommands && (
          <div className="preview-box">
            <h3>Generated commands</h3>
            <p><strong>NAT</strong></p>
            <code>{portForwardCommands.nat}</code>
            <p><strong>FILTER</strong></p>
            <code>{portForwardCommands.filter}</code>
          </div>
        )}
      </section>

      <section className="card">
        <h2>Static Public IP Configuration</h2>
        <p className="help-text">Assign a static public IP for outbound traffic using src-nat.</p>
        <div className="port-forward-grid">
          <div>
            <label htmlFor="static-public-ip">Public IP</label>
            <input id="static-public-ip" type="text" placeholder="46.183.37.46" value={staticPublicIp} onChange={(event) => setStaticPublicIp(event.target.value)} />
          </div>
          <div>
            <label htmlFor="out-interface">Out Interface</label>
            <input id="out-interface" type="text" placeholder="pppoe-out1" value={outInterface} onChange={(event) => setOutInterface(event.target.value)} />
          </div>
        </div>

        <div className="button-row">
          <button type="button" onClick={previewStaticIpConfiguration}>Preview Configuration</button>
          <button type="button" onClick={applyStaticIpConfiguration} disabled={staticIpLoading}>
            {staticIpLoading ? 'Applying configuration…' : 'Apply Configuration'}
          </button>
        </div>

        {staticIpError && <div className="alert" role="alert">{staticIpError}</div>}
        {staticIpSuccess && <div className="alert success-alert">{staticIpSuccess}</div>}

        {staticIpCommands && (
          <div className="preview-box">
            <h3>Generated commands</h3>
            <p><strong>Address List</strong></p>
            <code>{staticIpCommands.addressList}</code>
            <p><strong>SRC-NAT</strong></p>
            <code>{staticIpCommands.srcNat}</code>
          </div>
        )}
      </section>

      <section className="card">
        <h2>LAN Network Configuration</h2>
        <p className="help-text">Safely update LAN addressing, DHCP pool, and DHCP network settings.</p>
        <div className="port-forward-grid">
          <div><label htmlFor="old-network">Old Network</label><input id="old-network" type="text" value={oldNetwork} onChange={(event) => setOldNetwork(event.target.value)} /></div>
          <div><label htmlFor="old-gateway">Old Gateway</label><input id="old-gateway" type="text" value={oldGateway} onChange={(event) => setOldGateway(event.target.value)} /></div>
          <div><label htmlFor="new-network">New Network</label><input id="new-network" type="text" value={newNetwork} onChange={(event) => setNewNetwork(event.target.value)} /></div>
          <div><label htmlFor="new-gateway">New Gateway</label><input id="new-gateway" type="text" value={newGateway} onChange={(event) => setNewGateway(event.target.value)} /></div>
          <div><label htmlFor="lan-interface">Interface</label><input id="lan-interface" type="text" value={lanInterface} onChange={(event) => setLanInterface(event.target.value)} /></div>
          <div><label htmlFor="dhcp-start">DHCP Pool Start</label><input id="dhcp-start" type="text" value={dhcpPoolStart} onChange={(event) => setDhcpPoolStart(event.target.value)} /></div>
          <div><label htmlFor="dhcp-end">DHCP Pool End</label><input id="dhcp-end" type="text" value={dhcpPoolEnd} onChange={(event) => setDhcpPoolEnd(event.target.value)} /></div>
          <div><label htmlFor="dns-server">DNS Server</label><input id="dns-server" type="text" value={dnsServer} onChange={(event) => setDnsServer(event.target.value)} /></div>
          <div><label htmlFor="dhcp-name">DHCP Name</label><input id="dhcp-name" type="text" value={dhcpName} onChange={(event) => setDhcpName(event.target.value)} /></div>
        </div>

        <div className="button-row">
          <button type="button" onClick={previewLanConfiguration}>Preview Changes</button>
          <button type="button" onClick={applyLanConfiguration} disabled={lanLoading}>
            {lanLoading ? 'Applying configuration…' : 'Apply Configuration'}
          </button>
        </div>

        {lanError && <div className="alert" role="alert">{lanError}</div>}
        {lanSuccess && <div className="alert success-alert">{lanSuccess}</div>}

        {lanCommands && (
          <div className="preview-box">
            <h3>Generated commands</h3>
            <p><strong>IP</strong></p><code>{lanCommands.ip}</code>
            <p><strong>Pool</strong></p><code>{lanCommands.pool}</code>
            <p><strong>Firewall</strong></p><code>{lanCommands.firewall}</code>
            <p><strong>DHCP Server</strong></p><code>{lanCommands.dhcp}</code>
            <p><strong>DHCP Network</strong></p><code>{lanCommands.dhcpNetwork}</code>
          </div>
        )}
      </section>

      <section className="card result-card">
        <h2>Result</h2>
        {!result && !loading && !error && <p className="empty">No result yet. Run a diagnostic to see analysis.</p>}

        {result && (
          <div className="result-content">
            <div className="summary-grid">
              <div><span className="label">Target</span><strong>{result.target}</strong></div>
              <div><span className="label">Overall status</span><strong>{analysis?.overallStatus || result.status}</strong></div>
              <div><span className="label">Ping</span><strong>{result.results?.ping?.ok ? 'Reachable' : 'Unreachable'}</strong></div>
              <div><span className="label">DNS</span><strong>{result.results?.dns?.skipped ? 'Skipped (IP target)' : result.results?.dns?.ok ? 'Resolved' : 'Failed'}</strong></div>
              <div><span className="label">Confidence</span><strong className={confidenceClass}>{confidence}%</strong></div>
            </div>

            <h3>Tested ports</h3>
            <div className="port-tools">
              <label className="checkbox-row" htmlFor="show-open-only">
                <input id="show-open-only" type="checkbox" checked={showOnlyOpen} onChange={(event) => setShowOnlyOpen(event.target.checked)} />
                <span>Show only open ports</span>
              </label>
              <input type="text" placeholder="Search port (e.g. 5060)" value={portSearch} onChange={(event) => setPortSearch(event.target.value)} />
            </div>
            <p className="port-group-label">Open Ports: {openRows.length} | Closed Ports: {closedRows.length}</p>
            <div className="table-scroll">
              <table>
                <thead><tr><th>Port</th><th>State</th><th>Service</th><th>Response Time</th></tr></thead>
                <tbody>
                  {visibleRows.map((port) => (
                    <tr key={port.port}>
                      <td>{port.port}</td>
                      <td><span className={port.open ? 'state-open' : 'state-closed'}>{port.open ? 'Open' : 'Closed'}</span></td>
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
            {analysis?.context && <><h3>Realistic context</h3><p>{analysis.context}</p></>}

            <h3>Suggested MikroTik-side checks</h3>
            <ul>{mikrotikChecks.map((item) => <li key={item}>{item}</li>)}</ul>
            <h3>RouterOS command suggestion</h3>
            <code>{routerOsCommand}</code>
          </div>
        )}
      </section>
    </main>
  );
}

export default App;