const dns = require('dns').promises;
const net = require('net');
const logger = require('../../config/logger');

const resolveDns = async (target) => {
  const startedAt = new Date().toISOString();

  if (net.isIP(target)) {
    const payload = {
      success: true,
      applicable: false,
      status: 'not_applicable',
      reason: 'DNS check not applicable for direct IP target.',
      records: { ipv4: [], ipv6: [] },
      rawOutput: 'IP target provided, DNS resolution skipped.',
      // Backward compatibility
      ok: true,
      skipped: true,
      target,
      startedAt,
      finishedAt: new Date().toISOString(),
    };

    logger.info({ target, payload }, 'DNS diagnostic result');
    return payload;
  }

  try {
    const [a, aaaa] = await Promise.allSettled([dns.resolve4(target), dns.resolve6(target)]);
    const ipv4 = a.status === 'fulfilled' ? a.value : [];
    const ipv6 = aaaa.status === 'fulfilled' ? aaaa.value : [];

    const success = ipv4.length > 0 || ipv6.length > 0;
    const payload = {
      success,
      applicable: true,
      status: success ? 'resolved' : 'failed',
      records: { ipv4, ipv6 },
      errors: {
        ipv4: a.status === 'rejected' ? a.reason.message : null,
        ipv6: aaaa.status === 'rejected' ? aaaa.reason.message : null,
      },
      rawOutput: success ? `A=${ipv4.join(',')} AAAA=${ipv6.join(',')}` : 'No DNS records resolved.',
      // Backward compatibility
      ok: success,
      skipped: false,
      target,
      startedAt,
      finishedAt: new Date().toISOString(),
    };

    logger.info({ target, payload }, 'DNS diagnostic result');
    return payload;
  } catch (error) {
    const payload = {
      success: false,
      applicable: true,
      status: 'failed',
      records: { ipv4: [], ipv6: [] },
      errors: { global: error.message },
      rawOutput: error.message,
      // Backward compatibility
      ok: false,
      skipped: false,
      target,
      startedAt,
      finishedAt: new Date().toISOString(),
    };

    logger.info({ target, payload }, 'DNS diagnostic result');
    return payload;
  }
};

module.exports = {
  resolveDns,
};