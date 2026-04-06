const { pingTarget } = require('../network/ping.service');
const { resolveDns } = require('../network/dns.service');
const { checkPorts, DEFAULT_PORTS } = require('../network/port.service');
const { buildAnalysis } = require('./analysis.service');

const runSafely = async (runner, fallback) => {
  try {
    return await runner();
  } catch (error) {
    return {
      ...fallback,
      error: error.message,
      finishedAt: new Date().toISOString(),
    };
  }
};

const runDiagnostics = async ({ target, ports }) => {
  const effectivePorts = ports || DEFAULT_PORTS;
  const startedAt = new Date().toISOString();

  const [ping, portCheck, dns] = await Promise.all([
    runSafely(
      () => pingTarget(target),
      {
        ok: false,
        target,
        latencyMs: null,
        startedAt,
        rawOutput: 'Ping execution failed unexpectedly.',
      }
    ),
    runSafely(
      () => checkPorts(target, effectivePorts),
      {
        ok: false,
        target,
        startedAt,
        ports: effectivePorts.map((port) => ({
          port,
          open: false,
          responseTimeMs: 0,
          error: 'port-check-execution-failed',
        })),
      }
    ),
    runSafely(
      () => resolveDns(target),
      {
        ok: false,
        skipped: false,
        target,
        records: { ipv4: [], ipv6: [] },
        errors: { global: 'dns-execution-failed' },
        startedAt,
      }
    ),
  ]);

  const dnsWasRequired = dns.skipped !== true;

  const analysis = buildAnalysis({
    target,
    ping,
    dns,
    portCheck,
    dnsWasRequired,
  });

  return {
    target,
    status: analysis.overallStatus,
    checks: [
      { key: 'reachable', ok: ping.ok },
      { key: 'ping', ok: ping.ok },
      { key: 'dns', ok: dns.ok },
      { key: 'ports', ok: portCheck.ok },
    ],
    analysis,
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