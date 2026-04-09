const logger = require('../../config/logger');
const { pingTarget } = require('../network/ping.service');
const { resolveDns } = require('../network/dns.service');
const { checkPorts, DEFAULT_PORTS } = require('../network/port.service');
const { buildAnalysis } = require('./analysis.service');
const { fetchMikrotikSnapshot } = require('../mikrotik/mikrotik.service');
const NAT_PORT_PATTERN = /dst-port=([\d,-]+)/ig;

const expandPortToken = (token) => {
  if (/^\d+$/.test(token)) return [Number(token)];
  const rangeMatch = token.match(/^(\d+)-(\d+)$/);
  if (!rangeMatch) return [];
  const from = Number(rangeMatch[1]);
  const to = Number(rangeMatch[2]);
  if (to < from) return [];
  const size = to - from + 1;
  if (size > 30) return [from, to];
  return Array.from({ length: size }, (_, index) => from + index);
};

const extractPortsFromNatRaw = (natRaw = '') => {
  const collected = new Set();
  let match = NAT_PORT_PATTERN.exec(natRaw);
  while (match) {
    const expression = match[1];
    expression.split(',').forEach((token) => {
      expandPortToken(token.trim()).forEach((port) => {
        if (port >= 1 && port <= 65535) {
          collected.add(port);
        }
      });
    });
    match = NAT_PORT_PATTERN.exec(natRaw);
  }
  NAT_PORT_PATTERN.lastIndex = 0;
  return [...collected];
};

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

const runDiagnostics = async ({ target, ports, expectsSipService = false, mikrotik = null, safeRangeScan = false }) => {
  const requestedPorts = ports || DEFAULT_PORTS;
  const startedAt = new Date().toISOString();

  const [ping, dns, mikrotikSnapshot] = await Promise.all([
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
      () => fetchMikrotikSnapshot(mikrotik),
      {
        enabled: false,
        reason: 'MikroTik snapshot failed unexpectedly.',
      }
    ),
  ]);

  const dynamicNatPorts = extractPortsFromNatRaw(mikrotikSnapshot?.natRaw || '');
  const effectivePorts = [...new Set([...requestedPorts, ...dynamicNatPorts])];

  const portCheck = await runSafely(
    () => checkPorts(target, effectivePorts, { safeRangeScan, timeoutMs: 2500, concurrency: 50 }),
    {
      success: false,
      ports: effectivePorts.map((port) => ({
        port,
        state: 'closed',
        service: 'unknown',
        responseTime: 0,
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
  );

  const dnsHealthy = dns.applicable === false || dns.success;
  const status = ping.success && dnsHealthy && portCheck.success ? 'healthy' : 'degraded';

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