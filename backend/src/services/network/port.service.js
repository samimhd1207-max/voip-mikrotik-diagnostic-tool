const net = require('net');

const DEFAULT_PORTS = [80, 443, 8291, 5060, 5061];

const checkSinglePort = (target, port, timeoutMs = 3000) =>
  new Promise((resolve) => {
    const socket = new net.Socket();
    const startedAt = Date.now();
    let settled = false;

    const finalize = (open, error = null) => {
      if (settled) return;
      settled = true;
      socket.removeAllListeners();
      socket.destroy();
      resolve({
        port,
        open,
        responseTimeMs: Date.now() - startedAt,
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

  return {
    ok: results.every((result) => result.open),
    target,
    ports: results,
    startedAt,
    finishedAt: new Date().toISOString(),
  };
};

module.exports = {
  checkPorts,
  DEFAULT_PORTS,
};