const { execFile } = require('child_process');
const { promisify } = require('util');

const execFileAsync = promisify(execFile);

const extractLatency = (stdout) => {
  // Linux/macOS format: time=12.3 ms
  const unixMatch = stdout.match(/time[=<]([\d.]+)\s*ms/i);
  if (unixMatch) {
    return Number(unixMatch[1]);
  }

  // Windows format (EN): Average = 12ms
  const windowsEnMatch = stdout.match(/Average\s*=\s*(\d+)ms/i);
  if (windowsEnMatch) {
    return Number(windowsEnMatch[1]);
  }

  // Windows format (FR): Moyenne = 12ms
  const windowsFrMatch = stdout.match(/Moyenne\s*=\s*(\d+)ms/i);
  if (windowsFrMatch) {
    return Number(windowsFrMatch[1]);
  }

  return null;
};

const parsePingSuccess = (output) => {
  // Linux/macOS indicators
  if (/\b1\s+(packets\s+)?received\b/i.test(output) || /bytes\s+from/i.test(output)) {
    return true;
  }

  // Windows EN indicators
  if (/Reply\s+from/i.test(output) || /Received\s*=\s*[1-9]\d*/i.test(output)) {
    return true;
  }

  // Windows FR indicators
  if (/R[ée]ponse\s+de/i.test(output) || /Re[cç]us\s*=\s*[1-9]\d*/i.test(output)) {
    return true;
  }

  return false;
};

const parsePingFailure = (output) => {
  return (
    /100%\s*(packet\s*)?loss/i.test(output) ||
    /Lost\s*=\s*\d+\s*\(100%\s*loss\)/i.test(output) ||
    /Perdus\s*=\s*\d+\s*\(perte\s*100%\)/i.test(output) ||
    /could not find host/i.test(output) ||
    /impossible de trouver l'h[ôo]te/i.test(output)
  );
};

const buildPingCommand = (target) => {
  if (process.platform === 'win32') {
    return {
      command: 'ping',
      args: ['-n', '1', '-w', '3000', target],
    };
  }

  return {
    command: 'ping',
    args: ['-c', '1', target],
  };
};

const pingTarget = async (target) => {
  const startedAt = new Date().toISOString();
  const { command, args } = buildPingCommand(target);

  try {
    const { stdout, stderr } = await execFileAsync(command, args, {
      timeout: 7000,
      windowsHide: true,
    });

    const rawOutput = `${stdout || ''}${stderr || ''}`.trim();

    // In successful exec path, trust success unless output explicitly indicates failure.
    const parsedSuccess = parsePingSuccess(rawOutput);
    const explicitFailure = parsePingFailure(rawOutput);

    return {
      ok: explicitFailure ? false : parsedSuccess || true,
      target,
      latencyMs: extractLatency(rawOutput),
      startedAt,
      finishedAt: new Date().toISOString(),
      rawOutput,
    };
  } catch (error) {
    const rawOutput = `${error.stdout || ''}${error.stderr || ''}${error.message || ''}`.trim();

    return {
      ok: parsePingSuccess(rawOutput),
      target,
      latencyMs: extractLatency(rawOutput),
      startedAt,
      finishedAt: new Date().toISOString(),
      rawOutput,
    };
  }
};

module.exports = {
  pingTarget,
};