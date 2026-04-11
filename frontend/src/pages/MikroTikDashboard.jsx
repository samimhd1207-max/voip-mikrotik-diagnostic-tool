import { useMemo, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import OpenPort from '../components/mikrotik/OpenPort';
import SetStaticIp from '../components/mikrotik/SetStaticIp';
import ChangeAddressing from '../components/mikrotik/ChangeAddressing';
import ChangeGateway from '../components/mikrotik/ChangeGateway';
import UpdateWifi from '../components/mikrotik/UpdateWifi';
import RouteMail4G from '../components/mikrotik/RouteMail4G';

const actions = [
  { id: 'open-port', title: 'Open Port', description: 'Create dst-nat + filter allow for service publishing.', icon: '🌐' },
  { id: 'set-static-ip', title: 'Set Static IP', description: 'Configure fixed public source NAT policy.', icon: '📌' },
  { id: 'change-addressing', title: 'Change Network Addressing', description: 'Update LAN network, DHCP pool, and related settings.', icon: '🧭' },
  { id: 'change-gateway', title: 'Change Gateway', description: 'Preview gateway route update command.', icon: '🚪' },
  { id: 'change-wifi', title: 'Change WiFi Settings', description: 'Update SSID and WPA2 passphrase on wlan interfaces.', icon: '📶' },
  { id: 'route-mail-4g', title: 'Route Mail via 4G', description: 'Policy-route SMTP/IMAP/POP traffic over backup 4G/LTE.', icon: '📧' },
];

function MikroTikDashboard() {
  const location = useLocation();
  const navigate = useNavigate();
  const [activeAction, setActiveAction] = useState('open-port');

  const credentials = useMemo(() => {
    if (location.state?.credentials) return location.state.credentials;
    try {
      return JSON.parse(sessionStorage.getItem('mikrotikCredentials') || 'null');
    } catch (error) {
      return null;
    }
  }, [location.state]);

  if (!credentials?.host || !credentials?.username) {
    return (
      <main className="page">
        <section className="card">
          <h2>MikroTik Dashboard</h2>
          <p className="help-text">No active MikroTik session found. Connect first from home page.</p>
          <Link to="/">Go to Home</Link>
        </section>
      </main>
    );
  }

  return (
    <main className="page">
      <section className="card">
        <div className="dashboard-header">
          <div>
            <h1>MikroTik Dashboard</h1>
            <p className="help-text">Connected to {credentials.host}:{credentials.port || 22} as {credentials.username}</p>
          </div>
          <button
            type="button"
            onClick={() => {
              sessionStorage.removeItem('mikrotikCredentials');
              navigate('/');
            }}
          >
            Disconnect
          </button>
        </div>

        <div className="dashboard-grid">
          {actions.map((action) => (
            <button
              key={action.id}
              type="button"
              className={`action-tile ${activeAction === action.id ? 'action-tile-active' : ''}`}
              onClick={() => setActiveAction(action.id)}
            >
              <span className="action-icon" aria-hidden="true">{action.icon}</span>
              <strong>{action.title}</strong>
              <span>{action.description}</span>
            </button>
          ))}
        </div>
      </section>

      {activeAction === 'open-port' && <OpenPort credentials={credentials} />}
      {activeAction === 'set-static-ip' && <SetStaticIp credentials={credentials} />}
      {activeAction === 'change-addressing' && <ChangeAddressing credentials={credentials} />}
      {activeAction === 'change-gateway' && <ChangeGateway credentials={credentials} />}
      {activeAction === 'change-wifi' && <UpdateWifi credentials={credentials} />}
      {activeAction === 'route-mail-4g' && <RouteMail4G credentials={credentials} />}
    </main>
  );
}

export default MikroTikDashboard;