const { execFile } = require('child_process');
const { promisify } = require('util');
const logger = require('../../config/logger');

const execFileAsync = promisify(execFile);

const looksLikeAuthFailure = (message = '') =>
  /(permission denied|authentication failed|access denied|invalid password|incorrect password)/i.test(message);

const buildSshArgs = ({ host, username, port = 22, privateKeyPath }, command) => {
  const sshArgs = [
    '-p',
    String(port),
    '-o',
    'StrictHostKeyChecking=accept-new',
  ];

  if (privateKeyPath) {
    sshArgs.push('-o', 'BatchMode=yes', '-i', privateKeyPath);
  }

  sshArgs.push(`${username}@${host}`, command);
  return sshArgs;
};

const runSshCommand = async (connection, command) => {
  const { password } = connection;
  const sshArgs = buildSshArgs(connection, command);

  const executable = password ? 'sshpass' : 'ssh';
  const args = password ? ['-p', password, 'ssh', ...sshArgs] : sshArgs;

  const { stdout, stderr } = await execFileAsync(executable, args, {
    timeout: 10000,
    windowsHide: true,
  });

  return `${stdout || ''}${stderr || ''}`.trim();
};

const analyzeFirewallForSipBlock = (firewallRaw) => {
  const lines = firewallRaw.split('\n').map((line) => line.trim()).filter(Boolean);
  const blockedRule = lines.find(
    (line) =>
      /(?:drop|reject)/i.test(line) &&
      /dst-port=5060/.test(line) &&
      /(protocol=(tcp|udp)|udp|tcp)/i.test(line)
  );

  return {
    blocked: Boolean(blockedRule),
    matchingRule: blockedRule || null,
  };
};

const analyzeNatForSip = (natRaw) => {
  const lines = natRaw.split('\n').map((line) => line.trim()).filter(Boolean);
  const sipDstNatRule = lines.find((line) => /chain=dstnat/i.test(line) && /dst-port=(5060|5061)\b/.test(line));
  const srcNatRule = lines.find((line) => /chain=srcnat/i.test(line) && /(action=masquerade|action=src-nat)/i.test(line));
  const rtpDstNatRule = lines.find((line) => {
    if (!/chain=dstnat/i.test(line)) return false;
    const rangeMatch = line.match(/dst-port=(\d+)-(\d+)/i);
    if (!rangeMatch) return false;
    const from = Number(rangeMatch[1]);
    const to = Number(rangeMatch[2]);
    const overlapsTypicalRtpRange = (from <= 20000 && to >= 10000) || (from <= 32768 && to >= 16384);
    return overlapsTypicalRtpRange;
  });

  return {
    hasSipDstNat: Boolean(sipDstNatRule),
    hasRtpDstNat: Boolean(rtpDstNatRule),
    hasSrcNat: Boolean(srcNatRule),
    matchingSipDstNatRule: sipDstNatRule || null,
    matchingRtpDstNatRule: rtpDstNatRule || null,
  };
};

const fetchMikrotikSnapshot = async (connection) => {
  if (!connection || !connection.host || !connection.username) {
    return {
      enabled: false,
      reason: 'MikroTik connection not configured.',
    };
  }

  try {
    const firewallRaw = await runSshCommand(
      connection,
      '/ip firewall filter print terse without-paging'
    );

    const natRaw = await runSshCommand(
      connection,
      '/ip firewall nat print terse without-paging'
    );

    const interfacesRaw = await runSshCommand(
      connection,
      '/interface print terse without-paging'
    );

    const firewallAnalysis = analyzeFirewallForSipBlock(firewallRaw);
    const natAnalysis = analyzeNatForSip(natRaw);

    const payload = {
      enabled: true,
      firewallRaw,
      natRaw,
      interfacesRaw,
      analysis: {
        firewall: firewallAnalysis,
        nat: natAnalysis,
      },
    };

    logger.info({ host: connection.host, analysis: payload.analysis }, 'MikroTik snapshot collected');
    return payload;
  } catch (error) {
    const authFailed = looksLikeAuthFailure(error.message);
    const payload = {
      enabled: true,
      error: error.message,
      authFailed,
      analysis: {
        firewall: { blocked: false, matchingRule: null },
        nat: {
          hasSipDstNat: false,
          hasRtpDstNat: false,
          hasSrcNat: false,
          matchingSipDstNatRule: null,
          matchingRtpDstNatRule: null,
        },
      },
    };

    logger.warn({ host: connection.host, error: error.message }, 'MikroTik snapshot failed');
    return payload;
  }
};

module.exports = {
  fetchMikrotikSnapshot,
};