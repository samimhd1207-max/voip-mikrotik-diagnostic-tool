const logger = require('../../config/logger');
const { pingTarget } = require('../network/ping.service');
const { resolveDns } = require('../network/dns.service');
const { checkPorts, DEFAULT_PORTS } = require('../network/port.service');
const { buildAnalysis } = require('./analysis.service');
const { fetchMikrotikSnapshot } = require('../mikrotik/mikrotik.service');

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

const runDiagnostics = async ({ target, ports, expectsSipService = false, mikrotik = null }) => {
  const effectivePorts = ports || DEFAULT_PORTS;
  const startedAt = new Date().toISOString();

  const [ping, dns, portCheck, mikrotikSnapshot] = await Promise.all([
    runSafely(
      () => pingTarget(target),
      {
        success: false,
        latency: null,
        rawOutput: 'Ping execution failed unexpectedly.',
        ok: false,
        latencyMs: null,
        target,
        startedAt,
      }
    ),
    runSafely(
      () => resolveDns(target),
      {
        success: false,
        applicable: true,
        status: 'failed',
        records: { ipv4: [], ipv6: [] },
        rawOutput: 'DNS execution failed unexpectedly.',
        ok: false,
        skipped: false,
        target,
        startedAt,
      }
    ),
    runSafely(
      () => checkPorts(target, effectivePorts),
      {
        success: false,
        ports: effectivePorts.map((port) => ({
          port,
          success: false,
          open: false,
          responseTimeMs: 0,
          error: 'port-check-execution-failed',
        })),
        rawOutput: 'Port check execution failed unexpectedly.',
        ok: false,
        target,
        startedAt,
      }
    ),
    runSafely(
      () => fetchMikrotikSnapshot(mikrotik),
      {
        enabled: false,
        reason: 'MikroTik snapshot failed unexpectedly.',
      }
    ),
  ]);

  const dnsHealthy = dns.applicable === false || dns.success;
  const status = ping.success && dnsHealthy && portCheck.success ? 'healthy' : 'degraded';

  // Keep analysis engine integration without blocking primary response format.
  const analysis = buildAnalysis({
    target,
    ping,
    dns,
    portCheck,
    dnsWasRequired: dns.applicable !== false,
    expectsSipService,
    mikrotikSnapshot,
  });

  const payload = {
    target,
    results: {
      ping,
      dns,
      ports: portCheck,
      mikrotik: mikrotikSnapshot,
    },
    status,
    checks: [
      { key: 'ping', ok: ping.success },
      { key: 'dns', ok: dnsHealthy },
      { key: 'ports', ok: portCheck.success },
    ],
    analysis,
  };

  logger.info({ target, payload }, 'Diagnostics orchestration result');
  return payload;
};

module.exports = {
  runDiagnostics,
};