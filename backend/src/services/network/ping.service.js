const { execFile } = require('child_process');
const { promisify } = require('util');

const execFileAsync = promisify(execFile);

const pingTarget = async (target) => {
  const startedAt = new Date().toISOString();
  try {
    const { stdout } = await execFileAsync('ping', ['-c', '1', '-W', '2', target], {
      timeout: 4000,
    });

    const latencyMatch = stdout.match(/time=([\d.]+)\s*ms/i);
    return {
      ok: true,
      target,
      latencyMs: latencyMatch ? Number(latencyMatch[1]) : null,
      startedAt,
      finishedAt: new Date().toISOString(),
      rawOutput: stdout.trim(),
    };
  } catch (error) {
    return {
      ok: false,
      target,
      latencyMs: null,
      startedAt,
      finishedAt: new Date().toISOString(),
      rawOutput: (error.stdout || error.stderr || error.message || '').toString().trim(),
    };
  }
};

module.exports = {
  pingTarget,
};
