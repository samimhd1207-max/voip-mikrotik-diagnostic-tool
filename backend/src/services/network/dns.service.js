const dns = require('dns').promises;

const resolveDns = async (target) => {
  const startedAt = new Date().toISOString();

  try {
    const [ipv4, ipv6] = await Promise.allSettled([dns.resolve4(target), dns.resolve6(target)]);

    const ipv4Records = ipv4.status === 'fulfilled' ? ipv4.value : [];
    const ipv6Records = ipv6.status === 'fulfilled' ? ipv6.value : [];

    return {
      ok: ipv4Records.length > 0 || ipv6Records.length > 0,
      target,
      records: {
        ipv4: ipv4Records,
        ipv6: ipv6Records,
      },
      errors: {
        ipv4: ipv4.status === 'rejected' ? ipv4.reason.message : null,
        ipv6: ipv6.status === 'rejected' ? ipv6.reason.message : null,
      },
      startedAt,
      finishedAt: new Date().toISOString(),
    };
  } catch (error) {
    return {
      ok: false,
      target,
      records: {
        ipv4: [],
        ipv6: [],
      },
      errors: {
        global: error.message,
      },
      startedAt,
      finishedAt: new Date().toISOString(),
    };
  }
};

module.exports = {
  resolveDns,
};
