const { exec } = require('child_process');
const logger = require('../../config/logger');

const extractLatency = (output) => {
  const unixMatch = output.match(/time[=<]([\d.]+)\s*ms/i);
  if (unixMatch) return Number(unixMatch[1]);

  const windowsEn = output.match(/Average\s*=\s*(\d+)ms/i);
  if (windowsEn) return Number(windowsEn[1]);

  const windowsFr = output.match(/Moyenne\s*=\s*(\d+)ms/i);
  if (windowsFr) return Number(windowsFr[1]);

  return null;
};

const parsePingSuccess = (output) => {
  // Explicit success indicators across OS/locales.
  return (
    /ttl[=:\s]/i.test(output) ||
    /bytes\s+from/i.test(output) ||
    /Reply\s+from/i.test(output) ||
    /R[ée]ponse\s+de/i.test(output) ||
    /Received\s*=\s*[1-9]\d*/i.test(output) ||
    /Re[cç]us\s*=\s*[1-9]\d*/i.test(output) ||
    /\b1\s+(packets\s+)?received\b/i.test(output)
  );
};

const buildPingCommand = (target) => {
  if (process.platform === 'win32') {
    return `ping -n 1 ${target}`;
  }

  return `ping -c 1 ${target}`;
};

const pingTarget = async (target) => {
  const startedAt = new Date().toISOString();
  const command = buildPingCommand(target);

  return new Promise((resolve) => {
    exec(command, { timeout: 7000, windowsHide: true }, (error, stdout = '', stderr = '') => {
      const rawOutput = `${stdout}${stderr}${error?.message || ''}`.trim();
      const successFromOutput = parsePingSuccess(rawOutput);
      const success = successFromOutput || (!error && rawOutput.length > 0);
      const latency = extractLatency(rawOutput);

      logger.info(
        {
          target,
          command,
          success,
          latency,
          rawOutput,
        },
        'Ping diagnostic result'
      );

      resolve({
        success,
        latency,
        rawOutput,
        // Backward compatibility
        ok: success,
        latencyMs: latency,
        target,
        startedAt,
        finishedAt: new Date().toISOString(),
      });
    });
  });
};

module.exports = {
  pingTarget,
};