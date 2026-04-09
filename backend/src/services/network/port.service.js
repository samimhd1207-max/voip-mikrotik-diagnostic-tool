const net = require('net');
const logger = require('../../config/logger');

const DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 5060, 5061, 8291];
const SAFE_RANGE_PORTS = Array.from({ length: 1024 }, (_, index) => index + 1);

const SERVICE_BY_PORT = {
  21: 'ftp',
  22: 'ssh',
  23: 'telnet',
  25: 'smtp',
  53: 'dns',
  80: 'http',
  110: 'pop3',
  143: 'imap',
  443: 'https',
  445: 'smb',
  3389: 'rdp',
  5060: 'sip',
  5061: 'sips',
  8291: 'mikrotik',
};

const withConcurrency = async (items, limit, worker) => {
  const results = [];
  const executing = new Set();

  for (const item of items) {
    const promise = Promise.resolve().then(() => worker(item));
    results.push(promise);
    executing.add(promise);
    promise.finally(() => executing.delete(promise));

    if (executing.size >= limit) {
      await Promise.race(executing);
    }
  }

  return Promise.all(results);
};

const resolveServiceName = (port) => SERVICE_BY_PORT[port] || 'unknown';

const checkSinglePort = (target, port, timeoutMs = 2500) =>
  new Promise((resolve) => {
    const socket = new net.Socket();
    const startedMs = Date.now();
    let settled = false;

    const finalize = (isOpen, error = null) => {
      if (settled) return;
      settled = true;
      socket.removeAllListeners();
      socket.destroy();

      resolve({
        port,
        state: isOpen ? 'open' : 'closed',
        service: resolveServiceName(port),
        responseTime: Date.now() - startedMs,
        success: isOpen,
        open: isOpen,
        responseTimeMs: Date.now() - startedMs,
        error,
      });
    };

    socket.setTimeout(timeoutMs);
    socket.setNoDelay(true);
    socket.once('connect', () => finalize(true));
    socket.once('timeout', () => finalize(false, 'timeout'));
    socket.once('error', (err) => finalize(false, err.code || err.message));

    try {
      socket.connect(port, target);
    } catch (error) {
      finalize(false, error.code || error.message);
    }
  });

const checkPorts = async (target, ports = DEFAULT_PORTS, options = {}) => {
  const { safeRangeScan = false, timeoutMs = 2500, concurrency = 50 } = options;
  const basePorts = safeRangeScan ? [...ports, ...SAFE_RANGE_PORTS] : ports;
  const uniquePorts = [...new Set(basePorts)].filter((port) => Number.isInteger(port) && port >= 1 && port <= 65535).sort((a, b) => a - b);

  const startedAt = new Date().toISOString();
  const results = await withConcurrency(uniquePorts, concurrency, (port) => checkSinglePort(target, port, timeoutMs));

  const payload = {
    success: results.some((result) => result.success),
    target,
    ports: results,
    rawOutput: results.map((result) => `${result.port}:${result.state}`).join(', '),
    ok: results.every((result) => result.success),
    startedAt,
    finishedAt: new Date().toISOString(),
    scannedCount: results.length,
  };

  logger.info({ target, scanned: results.length, safeRangeScan }, 'Port diagnostic result');
  return payload;
};

module.exports = {
  checkPorts,
  DEFAULT_PORTS,
};