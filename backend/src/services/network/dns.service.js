const dns = require('dns').promises;
const net = require('net');

const resolveDns = async (target) => {
  const startedAt = new Date().toISOString();

  if (net.isIP(target)) {
    return {
      ok: true,
      skipped: true,
      reason: 'DNS not applicable for direct IP target.',
      target,
      records: {
        ipv4: [],
        ipv6: [],
      },
      errors: null,
      startedAt,
      finishedAt: new Date().toISOString(),
    };
  }

  const [ipv4Result, ipv6Result] = await Promise.allSettled([dns.resolve4(target), dns.resolve6(target)]);

  const ipv4Records = ipv4Result.status === 'fulfilled' ? ipv4Result.value : [];
  const ipv6Records = ipv6Result.status === 'fulfilled' ? ipv6Result.value : [];

  // Fallback for environments where resolve4/resolve6 may fail but lookup still works.
  let lookupRecords = [];
  if (!ipv4Records.length && !ipv6Records.length) {
    try {
      lookupRecords = await dns.lookup(target, { all: true, verbatim: true });
    } catch {
      lookupRecords = [];
    }
  }

  const lookupIpv4 = lookupRecords.filter((entry) => entry.family === 4).map((entry) => entry.address);
  const lookupIpv6 = lookupRecords.filter((entry) => entry.family === 6).map((entry) => entry.address);

  const finalIpv4 = [...new Set([...ipv4Records, ...lookupIpv4])];
  const finalIpv6 = [...new Set([...ipv6Records, ...lookupIpv6])];

  return {
    ok: finalIpv4.length > 0 || finalIpv6.length > 0,
    skipped: false,
    target,
    records: {
      ipv4: finalIpv4,
      ipv6: finalIpv6,
    },
    errors: {
      ipv4: ipv4Result.status === 'rejected' ? ipv4Result.reason.message : null,
      ipv6: ipv6Result.status === 'rejected' ? ipv6Result.reason.message : null,
    },
    startedAt,
    finishedAt: new Date().toISOString(),
  };
};

module.exports = {
  resolveDns,
};