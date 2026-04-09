const fs = require('fs');
const { Client } = require('ssh2');
const logger = require('../../config/logger');

const looksLikeAuthFailure = (message = '') =>
  /(permission denied|authentication failed|access denied|invalid password|incorrect password|all configured authentication methods failed)/i.test(message);

const runSshCommand = async ({ host, username, password, port = 22, privateKeyPath }, command) =>
  new Promise((resolve, reject) => {
    const client = new Client();
    let timeoutRef;

    const onDone = (error, output) => {
      if (timeoutRef) clearTimeout(timeoutRef);
      client.end();
      if (error) {
        reject(error);
        return;
      }
      resolve((output || '').trim());
    };

    const connectionConfig = {
      host,
      port,
      username,
      readyTimeout: 10000,
      tryKeyboard: false,
      ...(privateKeyPath ? { privateKey: fs.readFileSync(privateKeyPath, 'utf8') } : {}),
      ...(password ? { password } : {}),
    };

    timeoutRef = setTimeout(() => {
      onDone(new Error('MikroTik SSH timeout exceeded (10s).'));
    }, 10000);

    client
      .on('ready', () => {
        client.exec(command, (execError, stream) => {
          if (execError) {
            onDone(execError);
            return;
          }

          let stdout = '';
          let stderr = '';
          stream.on('data', (data) => {
            stdout += data.toString();
          });
          stream.stderr.on('data', (data) => {
            stderr += data.toString();
          });
          stream.on('close', () => {
            onDone(null, `${stdout}${stderr}`);
          });
        });
      })
      .on('error', (error) => onDone(error))
      .connect(connectionConfig);
  });

const analyzeFirewallForSipBlock = (firewallRaw) => {
  const lines = firewallRaw.split('\n').map((line) => line.trim()).filter(Boolean);
  const sipBlockedRule = lines.find(
    (line) =>
      /(?:drop|reject)/i.test(line) &&
      /dst-port=5060/.test(line) &&
      /(protocol=(tcp|udp)|udp|tcp)/i.test(line)
  );
  const rtpAllowRule = lines.find(
    (line) =>
      /action=accept/i.test(line) &&
      /protocol=udp/i.test(line) &&
      /dst-port=10000-20000/i.test(line)
  );
  const rtpBlockedRule = lines.find(
    (line) =>
      /(?:drop|reject)/i.test(line) &&
      /protocol=udp/i.test(line) &&
      /dst-port=10000-20000/i.test(line)
  );

  return {
    blocked: Boolean(sipBlockedRule),
    matchingRule: sipBlockedRule || null,
    hasRtpAllowRule: Boolean(rtpAllowRule),
    hasRtpBlockRule: Boolean(rtpBlockedRule),
    matchingRtpAllowRule: rtpAllowRule || null,
    matchingRtpBlockRule: rtpBlockedRule || null,
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
        firewall: {
          blocked: false,
          matchingRule: null,
          hasRtpAllowRule: false,
          hasRtpBlockRule: false,
          matchingRtpAllowRule: null,
          matchingRtpBlockRule: null,
        },
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