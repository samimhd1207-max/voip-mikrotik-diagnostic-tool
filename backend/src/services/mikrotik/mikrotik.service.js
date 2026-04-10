const withoutMask = (cidr) => cidr.split('/')[0];

const buildLanNetworkCommands = (config) => {
  const newNetworkWithoutMask = withoutMask(config.newNetwork);
  const newGatewayWithoutMask = withoutMask(config.newGateway);

  return {
    ip: `/ip address set [find where address=\"${config.oldGateway}\"] address=${config.newGateway} network=${newNetworkWithoutMask} interface=${config.interface} comment=\"LAN DATA\"`,
    pool: `/ip pool set [find where name=\"default-dhcp\"] name=${config.dhcpName} ranges=${config.dhcpPoolStart}-${config.dhcpPoolEnd} next-pool=none`,
    firewall: `/ip firewall address-list set [find where list=\"LAN\" and address=\"${config.oldNetwork}\"] address=${config.newNetwork}`,
    dhcp: `/ip dhcp-server set [find where name=\"defconf\"] name=${config.dhcpName} interface=${config.interface} address-pool=${config.dhcpName} disabled=no`,
    dhcpNetwork: `/ip dhcp-server network set [find where address=\"${config.oldNetwork}\"] address=${config.newNetwork} gateway=${newGatewayWithoutMask} dns-server=${config.dnsServer}`,
  };
};

const applyLanNetworkChange = async ({ mikrotik, config }) => {
  const commands = buildLanNetworkCommands(config);
  const context = {
    host: mikrotik.host,
    username: mikrotik.username,
    oldNetwork: config.oldNetwork,
    newNetwork: config.newNetwork,
    interface: config.interface,
  };

  try {
    logger.info(context, 'Validating current MikroTik LAN network state before applying changes');

    const addressRaw = await runSshCommand(mikrotik, '/ip address print terse without-paging');
    const interfaceRaw = await runSshCommand(mikrotik, '/interface print terse without-paging');
    const dhcpNetworkRaw = await runSshCommand(mikrotik, '/ip dhcp-server network print terse without-paging');

    if (!new RegExp(`address=${config.oldGateway.replace('/', '\\/')}\\b`, 'i').test(addressRaw)) {
      throw new HttpError(400, `Old gateway ${config.oldGateway} was not found on MikroTik.`, { field: 'config.oldGateway' });
    }

    if (
      !new RegExp(`\\bname=${config.interface}\\b`, 'i').test(interfaceRaw) &&
      !new RegExp(`\\b${config.interface}\\b`, 'i').test(interfaceRaw)
    ) {
      throw new HttpError(400, `Interface ${config.interface} does not exist on MikroTik.`, { field: 'config.interface' });
    }

    if (!new RegExp(`address=${config.oldNetwork.replace('/', '\\/')}\\b`, 'i').test(dhcpNetworkRaw)) {
      throw new HttpError(400, `Old network ${config.oldNetwork} was not found in DHCP server networks.`, { field: 'config.oldNetwork' });
    }

    logger.info(context, 'Applying MikroTik LAN network re-addressing commands');

    await runSshCommand(mikrotik, commands.ip);
    await runSshCommand(mikrotik, commands.pool);
    await runSshCommand(mikrotik, commands.firewall);
    await runSshCommand(mikrotik, commands.dhcp);
    await runSshCommand(mikrotik, commands.dhcpNetwork);

    logger.info(context, 'MikroTik LAN network change completed successfully');
    return { success: true, commands };
  } catch (error) {
    logger.error({ ...context, error: error.message }, 'Failed to change MikroTik LAN network');

    if (error instanceof HttpError) throw error;

    if (looksLikeAuthFailure(error.message)) {
      throw new HttpError(401, 'MikroTik authentication failed. Please check username/password and retry.', {
        field: 'mikrotik.password',
      });
    }

    throw new HttpError(400, `MikroTik LAN network change failed: ${error.message}`, {
      field: 'mikrotik.host',
    });
  }
};

// dans module.exports:
module.exports = {
  // ...existing exports
  buildLanNetworkCommands,
  applyLanNetworkChange,
};