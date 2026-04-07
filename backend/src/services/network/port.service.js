const net = require('net');
const logger = require('../../config/logger');

const DEFAULT_PORTS = [80, 443, 8291, 5060, 5061];

const checkSinglePort = (target, port, timeoutMs = 3000) =>
  new Promise((resolve) => {
    const socket = new net.Socket();
    const startedMs = Date.now();
    let settled = false;

    const finalize = (success, error = null) => {
      if (settled) return;
      settled = true;
      socket.removeAllListeners();
      socket.destroy();

      resolve({
        port,
        success,
        open: success,
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

const checkPorts = async (target, ports = DEFAULT_PORTS) => {
  const uniquePorts = [...new Set(ports)];
  const startedAt = new Date().toISOString();
  const results = await Promise.all(uniquePorts.map((port) => checkSinglePort(target, port)));

  const payload = {
    success: results.some((result) => result.success),
    target,
    ports: results,
    rawOutput: results.map((result) => `${result.port}:${result.success ? 'open' : result.error || 'closed'}`).join(', '),
    // Backward compatibility
    ok: results.every((result) => result.success),
    startedAt,
    finishedAt: new Date().toISOString(),
  };

  logger.info({ target, payload }, 'Port diagnostic result');
  return payload;
};

module.exports = {
  checkPorts,
  DEFAULT_PORTS,
};