const fs = require('fs');
const { Client } = require('ssh2');
const logger = require('../../config/logger');
const HttpError = require('../../utils/http-error');

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
  const sipAllowRule = lines.find(
    (line) =>
      /action=accept/i.test(line) &&
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
    hasSipAllowRule: Boolean(sipAllowRule),
    matchingRule: sipBlockedRule || null,
    matchingSipAllowRule: sipAllowRule || null,
    hasRtpAllowRule: Boolean(rtpAllowRule),
    hasRtpBlockRule: Boolean(rtpBlockedRule),
    matchingRtpAllowRule: rtpAllowRule || null,
    matchingRtpBlockRule: rtpBlockedRule || null,
  };
};

const analyzeNatForSip = (natRaw, firewallRaw = '') => {
  const lines = natRaw.split('\n').map((line) => line.trim()).filter(Boolean);
  const firewallLines = firewallRaw.split('\n').map((line) => line.trim()).filter(Boolean);
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
  const dstNatRules = lines
    .filter((line) => /chain=dstnat/i.test(line) && /action=dst-nat/i.test(line))
    .map((line) => {
      const protocolMatch = line.match(/protocol=(tcp|udp)/i);
      const dstPortMatch = line.match(/dst-port=([0-9,-]+)/i);
      return {
        raw: line,
        protocol: (protocolMatch?.[1] || '').toLowerCase(),
        dstPort: dstPortMatch?.[1] || '',
      };
    })
    .filter((rule) => rule.protocol && rule.dstPort);

  const forwardAllowSignatures = new Set(
    firewallLines
      .filter((line) => /chain=forward/i.test(line) && /action=accept/i.test(line))
      .map((line) => {
        const protocolMatch = line.match(/protocol=(tcp|udp)/i);
        const dstPortMatch = line.match(/dst-port=([0-9,-]+)/i);
        if (!protocolMatch?.[1] || !dstPortMatch?.[1]) return null;
        return `${protocolMatch[1].toLowerCase()}:${dstPortMatch[1]}`;
      })
      .filter(Boolean)
  );

  const unprotectedDstNatRules = dstNatRules.filter(
    (rule) => !forwardAllowSignatures.has(`${rule.protocol}:${rule.dstPort}`)
  );

  return {
    hasSipDstNat: Boolean(sipDstNatRule),
    hasRtpDstNat: Boolean(rtpDstNatRule),
    hasSrcNat: Boolean(srcNatRule),
    matchingSipDstNatRule: sipDstNatRule || null,
    matchingRtpDstNatRule: rtpDstNatRule || null,
    unprotectedDstNatRules,
  };
};

const analyzeLanDhcpState = (dhcpNetworkRaw, poolRaw) => {
  const networkLines = dhcpNetworkRaw.split('\n').map((line) => line.trim()).filter(Boolean);
  const poolLines = poolRaw.split('\n').map((line) => line.trim()).filter(Boolean);

  const hasDhcpNetwork = networkLines.some((line) => /address=\d{1,3}(?:\.\d{1,3}){3}\/\d+/.test(line));
  const hasDhcpPool = poolLines.some((line) => /ranges=\d{1,3}(?:\.\d{1,3}){3}-\d{1,3}(?:\.\d{1,3}){3}/.test(line));

  return {
    hasDhcpNetwork,
    hasDhcpPool,
  };
};

const buildPortForwardCommands = (config) => {
  const { protocol, externalPort, internalIp, internalPort, publicIp } = config;

  const natParts = [
    '/ip firewall nat add',
    'chain=dstnat',
    `protocol=${protocol}`,
    `dst-port=${externalPort}`,
    ...(publicIp ? [`dst-address=${publicIp}`] : []),
    'action=dst-nat',
    `to-addresses=${internalIp}`,
    `to-ports=${internalPort}`,
  ];

  const filterParts = [
    '/ip firewall filter add',
    'chain=forward',
    `protocol=${protocol}`,
    `dst-port=${externalPort}`,
    `dst-address=${internalIp}`,
    'action=accept',
  ];

  return {
    nat: natParts.join(' '),
    filter: filterParts.join(' '),
  };
};

const parseRouterOsRecords = (raw = '') =>
  raw
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line && /=/.test(line));

const hasExistingNatRule = (natRaw, config) => {
  const records = parseRouterOsRecords(natRaw);
  return records.some((line) => {
    const baseMatch =
      /chain=dstnat/i.test(line) &&
      new RegExp(`protocol=${config.protocol}\\b`, 'i').test(line) &&
      new RegExp(`dst-port=${config.externalPort}\\b`, 'i').test(line) &&
      /action=dst-nat/i.test(line) &&
      new RegExp(`to-addresses=${config.internalIp}\\b`, 'i').test(line) &&
      new RegExp(`to-ports=${config.internalPort}\\b`, 'i').test(line);

    if (!baseMatch) {
      return false;
    }

    if (config.publicIp) {
      return new RegExp(`dst-address=${config.publicIp}\\b`, 'i').test(line);
    }

    return true;
  });
};

const hasExistingFilterRule = (filterRaw, config) => {
  const records = parseRouterOsRecords(filterRaw);

  return records.some(
    (line) =>
      /chain=forward/i.test(line) &&
      new RegExp(`protocol=${config.protocol}\\b`, 'i').test(line) &&
      new RegExp(`dst-port=${config.externalPort}\\b`, 'i').test(line) &&
      new RegExp(`dst-address=${config.internalIp}\\b`, 'i').test(line) &&
      /action=accept/i.test(line)
  );
};

const applyPortForwarding = async ({ mikrotik, config }) => {
  const commands = buildPortForwardCommands(config);
  const context = { host: mikrotik.host, username: mikrotik.username, externalPort: config.externalPort, protocol: config.protocol };

  try {
    logger.info(context, 'Checking existing MikroTik NAT and filter rules for port forwarding');

    const natRaw = await runSshCommand(mikrotik, '/ip firewall nat print terse without-paging');
    const filterRaw = await runSshCommand(mikrotik, '/ip firewall filter print terse without-paging');

    const natAlreadyExists = hasExistingNatRule(natRaw, config);
    const filterAlreadyExists = hasExistingFilterRule(filterRaw, config);

    if (!natAlreadyExists) {
      logger.info(context, 'Executing MikroTik NAT command for port forwarding');
      await runSshCommand(mikrotik, commands.nat);
    } else {
      logger.info(context, 'Skipping NAT command because matching rule already exists');
    }

    if (!filterAlreadyExists) {
      logger.info(context, 'Executing MikroTik filter command for port forwarding');
      await runSshCommand(mikrotik, commands.filter);
    } else {
      logger.info(context, 'Skipping filter command because matching rule already exists');
    }

    return {
      success: true,
      commands,
      skipped: {
        nat: natAlreadyExists,
        filter: filterAlreadyExists,
      },
    };
  } catch (error) {
    logger.error({ ...context, error: error.message }, 'Failed to apply MikroTik port forwarding commands');

    if (looksLikeAuthFailure(error.message)) {
      throw new HttpError(401, 'MikroTik authentication failed. Please check username/password and retry.', {
        field: 'mikrotik.password',
      });
    }

    throw new HttpError(400, `MikroTik port forwarding failed: ${error.message}`, {
      field: 'mikrotik.host',
    });
  }
};



const buildStaticIpCommands = (config) => {
  const { publicIp, outInterface } = config;

  return {
    addressList: `/ip firewall address-list add list=public-add address=${publicIp} comment="Static public IP"`,
    srcNat: `/ip firewall nat add chain=srcnat out-interface=${outInterface} action=src-nat to-addresses=${publicIp} comment="Static public IP"`,
  };
};

const hasExistingAddressListEntry = (raw, publicIp) => {
  const records = parseRouterOsRecords(raw);
  return records.some(
    (line) => /list=public-add/i.test(line) && new RegExp(`address=${publicIp}\\b`, 'i').test(line)
  );
};

const hasExistingStaticSrcNat = (raw, config) => {
  const records = parseRouterOsRecords(raw);
  return records.some(
    (line) =>
      /chain=srcnat/i.test(line) &&
      new RegExp(`out-interface=${config.outInterface}\\b`, 'i').test(line) &&
      /action=src-nat/i.test(line) &&
      new RegExp(`to-addresses=${config.publicIp}\\b`, 'i').test(line)
  );
};

const applyStaticPublicIp = async ({ mikrotik, config }) => {
  const commands = buildStaticIpCommands(config);
  const context = { host: mikrotik.host, username: mikrotik.username, outInterface: config.outInterface, publicIp: config.publicIp };

  try {
    logger.info(context, 'Checking existing MikroTik static public IP configuration');

    const addressListRaw = await runSshCommand(mikrotik, '/ip firewall address-list print terse without-paging');
    const natRaw = await runSshCommand(mikrotik, '/ip firewall nat print terse without-paging');

    const addressListExists = hasExistingAddressListEntry(addressListRaw, config.publicIp);
    const srcNatExists = hasExistingStaticSrcNat(natRaw, config);

    if (!addressListExists) {
      logger.info(context, 'Executing MikroTik address-list command for static public IP');
      await runSshCommand(mikrotik, commands.addressList);
    } else {
      logger.info(context, 'Skipping address-list command because entry already exists');
    }

    if (!srcNatExists) {
      logger.info(context, 'Executing MikroTik src-nat command for static public IP');
      await runSshCommand(mikrotik, commands.srcNat);
    } else {
      logger.info(context, 'Skipping src-nat command because matching rule already exists');
    }

    return {
      success: true,
      commands,
      skipped: {
        addressList: addressListExists,
        srcNat: srcNatExists,
      },
    };
  } catch (error) {
    logger.error({ ...context, error: error.message }, 'Failed to apply MikroTik static public IP configuration');

    if (looksLikeAuthFailure(error.message)) {
      throw new HttpError(401, 'MikroTik authentication failed. Please check username/password and retry.', {
        field: 'mikrotik.password',
      });
    }

    throw new HttpError(400, `MikroTik static public IP assignment failed: ${error.message}`, {
      field: 'mikrotik.host',
    });
  }
};

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

    if (!new RegExp(`\\bname=${config.interface}\\b`, 'i').test(interfaceRaw) && !new RegExp(`\\b${config.interface}\\b`, 'i').test(interfaceRaw)) {
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

    if (error instanceof HttpError) {
      throw error;
    }

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
    const dhcpNetworkRaw = await runSshCommand(
      connection,
      '/ip dhcp-server network print terse without-paging'
    );
    const poolRaw = await runSshCommand(
      connection,
      '/ip pool print terse without-paging'
    );

    const firewallAnalysis = analyzeFirewallForSipBlock(firewallRaw);
    const natAnalysis = analyzeNatForSip(natRaw, firewallRaw);
    const lanAnalysis = analyzeLanDhcpState(dhcpNetworkRaw, poolRaw);

    const payload = {
      enabled: true,
      firewallRaw,
      natRaw,
      interfacesRaw,
      dhcpNetworkRaw,
      poolRaw,
      analysis: {
        firewall: firewallAnalysis,
        nat: natAnalysis,
        lan: lanAnalysis,
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
          hasSipAllowRule: false,
          matchingRule: null,
          matchingSipAllowRule: null,
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
          unprotectedDstNatRules: [],
        },
        lan: {
          hasDhcpNetwork: false,
          hasDhcpPool: false,
        },
      },
    };

    logger.warn({ host: connection.host, error: error.message }, 'MikroTik snapshot failed');
    return payload;
  }
};
const escapeRouterOsString = (value = '') => value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');

const buildWifiUpdateCommands = (config) => {
  const ssid = escapeRouterOsString(config.ssid);
  const wifiPassword = escapeRouterOsString(config.wifiPassword);

  return {
    wlan1: `/interface wireless set [find default-name=wlan1] ssid="${ssid}" security-profile=default wps-mode=disabled`,
    wlan2: `/interface wireless set [find default-name=wlan2] ssid="${ssid}" security-profile=default wps-mode=disabled`,
    security: `/interface wireless security-profiles set [find name="default"] mode=dynamic-keys authentication-types=wpa2-psk unicast-ciphers=aes-ccm group-ciphers=aes-ccm wpa2-pre-shared-key="${wifiPassword}"`,
  };
};

const applyWifiConfiguration = async ({ mikrotik, config }) => {
  const commands = buildWifiUpdateCommands(config);
  const context = {
    host: mikrotik.host,
    username: mikrotik.username,
    ssid: config.ssid,
  };

  try {
    logger.info(context, 'Applying MikroTik WiFi settings (SSID + WPA2 profile)');
    await runSshCommand(mikrotik, commands.wlan1);
    await runSshCommand(mikrotik, commands.wlan2);
    await runSshCommand(mikrotik, commands.security);
    logger.info(context, 'MikroTik WiFi settings updated successfully');
    return { success: true, commands };
  } catch (error) {
    logger.error({ ...context, error: error.message }, 'Failed to update MikroTik WiFi settings');

    if (looksLikeAuthFailure(error.message)) {
      throw new HttpError(401, 'MikroTik authentication failed. Please check username/password and retry.', {
        field: 'mikrotik.password',
      });
    }

    throw new HttpError(400, `MikroTik WiFi update failed: ${error.message}`, {
      field: 'mikrotik.host',
    });
  }
};
const MAIL_PORTS = '25,110,143,465,587,993,995';

const buildRouteMail4gCommands = (config) => {
  if (config.deviceType === 'mr100') {
    return {
      mode: 'mr100',
      routingTable: '/routing table add name=mail_via_4g fib',
      route: `/ip route add dst-address=0.0.0.0/0 gateway=${config.gateway4g}@main routing-table=mail_via_4g comment="Route mail via MR100 4G"`,
      mangleConnection: `/ip firewall mangle add chain=prerouting in-interface=${config.lanInterface} protocol=tcp dst-port=${MAIL_PORTS} dst-address-type=!local connection-state=new action=mark-connection new-connection-mark=mail_4g_conn passthrough=yes comment="Mark mail connections to 4G"`,
      mangleRouting: `/ip firewall mangle add chain=prerouting in-interface=${config.lanInterface} connection-mark=mail_4g_conn action=mark-routing new-routing-mark=mail_via_4g passthrough=no comment="Route marked mail via 4G"`,
      filter: '/ip firewall filter add chain=forward connection-mark=mail_4g_conn action=accept place-before=[find where action=fasttrack-connection] comment="Bypass FastTrack for mail via 4G"',
      nat: `/ip firewall nat add chain=srcnat out-interface=${config.wan4gInterface} action=masquerade comment="NAT mail via 4G"`,
    };
  }

  return {
    mode: 'chateau',
    routingTable: '/routing table add name=mail_via_lte fib',
    route: '/ip route add dst-address=0.0.0.0/0 gateway=lte1 routing-table=mail_via_lte comment="Mail via LTE Chateau"',
    mangleConnection: `/ip firewall mangle add chain=prerouting in-interface=${config.lanInterface} protocol=tcp dst-port=${MAIL_PORTS} dst-address-type=!local connection-state=new action=mark-connection new-connection-mark=mail_lte_conn passthrough=yes comment="Mark mail connections to LTE"`,
    mangleRouting: `/ip firewall mangle add chain=prerouting in-interface=${config.lanInterface} connection-mark=mail_lte_conn action=mark-routing new-routing-mark=mail_via_lte passthrough=no comment="Route marked mail via LTE"`,
    filter: '/ip firewall filter add chain=forward connection-mark=mail_lte_conn action=accept place-before=[find where action=fasttrack-connection] comment="Bypass FastTrack for mail via LTE"',
    nat: '/ip firewall nat add chain=srcnat out-interface=lte1 action=masquerade comment="NAT via LTE"',
  };
};

const hasPattern = (raw = '', pattern) => new RegExp(pattern, 'i').test(raw);

const applyMailRoutingVia4g = async ({ mikrotik, config }) => {
  const commandSet = buildRouteMail4gCommands(config);
  const context = {
    host: mikrotik.host,
    username: mikrotik.username,
    mode: commandSet.mode,
    lanInterface: config.lanInterface,
    wan4gInterface: config.wan4gInterface,
  };

  try {
    logger.info(context, 'Checking existing MikroTik rules for mail routing via 4G/LTE');

    const routingTableRaw = await runSshCommand(mikrotik, '/routing table print terse without-paging');
    const routeRaw = await runSshCommand(mikrotik, '/ip route print terse without-paging');
    const mangleRaw = await runSshCommand(mikrotik, '/ip firewall mangle print terse without-paging');
    const filterRaw = await runSshCommand(mikrotik, '/ip firewall filter print terse without-paging');
    const natRaw = await runSshCommand(mikrotik, '/ip firewall nat print terse without-paging');

    const tableName = commandSet.mode === 'mr100' ? 'mail_via_4g' : 'mail_via_lte';
    const connectionMark = commandSet.mode === 'mr100' ? 'mail_4g_conn' : 'mail_lte_conn';
    const natComment = commandSet.mode === 'mr100' ? 'NAT mail via 4G' : 'NAT via LTE';

    const skipped = {
      routingTable: hasPattern(routingTableRaw, `\\bname=${tableName}\\b`),
      route: hasPattern(routeRaw, `\\brouting-table=${tableName}\\b`) && hasPattern(routeRaw, '\\bdst-address=0\\.0\\.0\\.0/0\\b'),
      mangleConnection: hasPattern(mangleRaw, `\\bnew-connection-mark=${connectionMark}\\b`) && hasPattern(mangleRaw, `\\bdst-port=${MAIL_PORTS}\\b`),
      mangleRouting: hasPattern(mangleRaw, `\\bconnection-mark=${connectionMark}\\b`) && hasPattern(mangleRaw, `\\bnew-routing-mark=${tableName}\\b`),
      filter: hasPattern(filterRaw, `\\bconnection-mark=${connectionMark}\\b`) && hasPattern(filterRaw, '\\bchain=forward\\b'),
      nat: hasPattern(natRaw, `\\bcomment="${natComment}"\\b`) || (hasPattern(natRaw, '\\bchain=srcnat\\b') && hasPattern(natRaw, `\\bout-interface=${config.wan4gInterface}\\b`)),
    };

    if (!skipped.routingTable) await runSshCommand(mikrotik, commandSet.routingTable);
    if (!skipped.route) await runSshCommand(mikrotik, commandSet.route);
    if (!skipped.mangleConnection) await runSshCommand(mikrotik, commandSet.mangleConnection);
    if (!skipped.mangleRouting) await runSshCommand(mikrotik, commandSet.mangleRouting);
    if (!skipped.filter) await runSshCommand(mikrotik, commandSet.filter);
    if (!skipped.nat) await runSshCommand(mikrotik, commandSet.nat);

    logger.info(context, 'MikroTik mail routing via 4G/LTE updated successfully');
    return {
      success: true,
      mode: commandSet.mode,
      commands: [
        commandSet.routingTable,
        commandSet.route,
        commandSet.mangleConnection,
        commandSet.mangleRouting,
        commandSet.filter,
        commandSet.nat,
      ],
      skipped,
    };
  } catch (error) {
    logger.error({ ...context, error: error.message }, 'Failed to configure MikroTik mail routing via 4G/LTE');

    if (looksLikeAuthFailure(error.message)) {
      throw new HttpError(401, 'MikroTik authentication failed. Please check username/password and retry.', {
        field: 'mikrotik.password',
      });
    }

    throw new HttpError(400, `MikroTik mail 4G routing failed: ${error.message}`, {
      field: 'mikrotik.host',
    });
  }
};

module.exports = {
  fetchMikrotikSnapshot,
  buildPortForwardCommands,
  applyPortForwarding,
  buildStaticIpCommands,
  applyStaticPublicIp,
  buildLanNetworkCommands,
  applyLanNetworkChange,
  buildWifiUpdateCommands,
applyWifiConfiguration,
buildRouteMail4gCommands,
applyMailRoutingVia4g,
};