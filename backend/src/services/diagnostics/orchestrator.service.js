const { pingTarget } = require('../network/ping.service');
const { resolveDns } = require('../network/dns.service');
const { checkPorts, DEFAULT_PORTS } = require('../network/port.service');

const runDiagnostics = async ({ target, ports }) => {
  const [ping, dns, portCheck] = await Promise.all([
    pingTarget(target),
    resolveDns(target),
    checkPorts(target, ports || DEFAULT_PORTS),
  ]);

  const checks = [
    { key: 'ping', ok: ping.ok },
    { key: 'dns', ok: dns.ok },
    { key: 'ports', ok: portCheck.ok },
  ];

  const healthy = checks.every((check) => check.ok);

  return {
    target,
    status: healthy ? 'healthy' : 'degraded',
    checks,
    results: {
      ping,
      dns,
      ports: portCheck,
    },
  };
};

module.exports = {
  runDiagnostics,
};
