const HttpError = require('../utils/http-error');

const ipv4Regex = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const cidrRegex = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}\/(3[0-2]|[12]?\d)$/;
const hostnameRegex = /^(?=.{1,253}$)(?:(?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+(?:[a-zA-Z]{2,63})$/;

const isValidTarget = (value) => ipv4Regex.test(value) || hostnameRegex.test(value) || value === 'localhost';
const ipToInt = (ip) => ip.split('.').map(Number).reduce((acc, octet) => (acc << 8) + octet, 0) >>> 0;

const validatePortValue = (value, field) => {
  if (!Number.isInteger(value) || value < 1 || value > 65535) {
    throw new HttpError(400, `${field} must be an integer between 1 and 65535.`, { field });
  }
};

const validateMikrotikCredentials = (mikrotik) => {
  if (!mikrotik || typeof mikrotik !== 'object' || Array.isArray(mikrotik)) {
    throw new HttpError(400, 'mikrotik object is required.', { field: 'mikrotik' });
  }

  const { host, username, password, port } = mikrotik;
  if (!host || typeof host !== 'string' || !host.trim()) {
    throw new HttpError(400, 'mikrotik.host is required and must be a string.', { field: 'mikrotik.host' });
  }
  if (!username || typeof username !== 'string' || !username.trim()) {
    throw new HttpError(400, 'mikrotik.username is required and must be a string.', { field: 'mikrotik.username' });
  }
  if (!password || typeof password !== 'string') {
    throw new HttpError(400, 'mikrotik.password is required and must be a string.', { field: 'mikrotik.password' });
  }
  if (port !== undefined && (!Number.isInteger(port) || port < 1 || port > 65535)) {
    throw new HttpError(400, 'mikrotik.port must be an integer between 1 and 65535.', { field: 'mikrotik.port' });
  }

  return {
    host: host.trim(),
    username: username.trim(),
    password,
    ...(port !== undefined ? { port } : {}),
  };
};

const validateCreateDiagnostic = (req, _res, next) => {
  const { target, ports, expectsSipService, safeRangeScan, mikrotik } = req.body || {};

  if (!target || typeof target !== 'string' || !isValidTarget(target.trim())) {
    return next(new HttpError(400, 'Invalid target. Provide a valid IPv4 address, hostname, or localhost.', { field: 'target' }));
  }

  if (ports !== undefined) {
    if (!Array.isArray(ports) || ports.length === 0) {
      return next(new HttpError(400, 'Ports must be a non-empty array when provided.', { field: 'ports' }));
    }
    const invalidPort = ports.find((port) => !Number.isInteger(port) || port < 1 || port > 65535);
    if (invalidPort !== undefined) {
      return next(new HttpError(400, 'Every port must be an integer between 1 and 65535.', { field: 'ports' }));
    }
  }

  if (mikrotik !== undefined) {
    try {
      validateMikrotikCredentials(mikrotik);
    } catch (error) {
      return next(error);
    }
  }

  if (expectsSipService !== undefined && typeof expectsSipService !== 'boolean') {
    return next(new HttpError(400, 'expectsSipService must be a boolean when provided.', { field: 'expectsSipService' }));
  }

  if (safeRangeScan !== undefined && typeof safeRangeScan !== 'boolean') {
    return next(new HttpError(400, 'safeRangeScan must be a boolean when provided.', { field: 'safeRangeScan' }));
  }

  req.body.target = target.trim();
  next();
};

const validatePortForwardingRequest = (req, _res, next) => {
  try {
    const { mikrotik, config } = req.body || {};
    if (!config || typeof config !== 'object' || Array.isArray(config)) {
      throw new HttpError(400, 'config object is required.', { field: 'config' });
    }

    const sanitizedMikrotik = validateMikrotikCredentials(mikrotik);
    const { publicIp, externalPort, internalIp, internalPort, protocol } = config;

    if (publicIp !== undefined && publicIp !== '' && (typeof publicIp !== 'string' || !ipv4Regex.test(publicIp.trim()))) {
      throw new HttpError(400, 'config.publicIp must be a valid IPv4 address when provided.', { field: 'config.publicIp' });
    }

    if (typeof internalIp !== 'string' || !ipv4Regex.test(internalIp.trim())) {
      throw new HttpError(400, 'config.internalIp is required and must be a valid IPv4 address.', { field: 'config.internalIp' });
    }

    validatePortValue(externalPort, 'config.externalPort');
    validatePortValue(internalPort, 'config.internalPort');

    if (!['tcp', 'udp'].includes(String(protocol || '').toLowerCase())) {
      throw new HttpError(400, 'config.protocol must be either tcp or udp.', { field: 'config.protocol' });
    }

    req.body = {
      ...req.body,
      mikrotik: sanitizedMikrotik,
      config: {
        publicIp: publicIp ? publicIp.trim() : '',
        externalPort,
        internalIp: internalIp.trim(),
        internalPort,
        protocol: String(protocol).toLowerCase(),
      },
    };

    next();
  } catch (error) {
    next(error);
  }
};

const validateStaticIpRequest = (req, _res, next) => {
  try {
    const { mikrotik, config } = req.body || {};
    if (!config || typeof config !== 'object' || Array.isArray(config)) {
      throw new HttpError(400, 'config object is required.', { field: 'config' });
    }

    const sanitizedMikrotik = validateMikrotikCredentials(mikrotik);
    const { publicIp, outInterface } = config;

    if (typeof publicIp !== 'string' || !ipv4Regex.test(publicIp.trim())) {
      throw new HttpError(400, 'config.publicIp is required and must be a valid IPv4 address.', { field: 'config.publicIp' });
    }
    if (typeof outInterface !== 'string' || !outInterface.trim()) {
      throw new HttpError(400, 'config.outInterface is required and must be a string.', { field: 'config.outInterface' });
    }

    req.body = {
      ...req.body,
      mikrotik: sanitizedMikrotik,
      config: { publicIp: publicIp.trim(), outInterface: outInterface.trim() },
    };

    next();
  } catch (error) {
    next(error);
  }
};

const validateLanNetworkChangeRequest = (req, _res, next) => {
  try {
    const { mikrotik, config } = req.body || {};
    if (!config || typeof config !== 'object' || Array.isArray(config)) {
      throw new HttpError(400, 'config object is required.', { field: 'config' });
    }

    const sanitizedMikrotik = validateMikrotikCredentials(mikrotik);
    const {
      oldNetwork,
      oldGateway,
      newNetwork,
      newGateway,
      interface: interfaceName,
      dhcpPoolStart,
      dhcpPoolEnd,
      dnsServer,
      dhcpName,
    } = config;

    const requiredCidr = [
      ['oldNetwork', oldNetwork],
      ['oldGateway', oldGateway],
      ['newNetwork', newNetwork],
      ['newGateway', newGateway],
    ];

    requiredCidr.forEach(([field, value]) => {
      if (typeof value !== 'string' || !cidrRegex.test(value.trim())) {
        throw new HttpError(400, `config.${field} must be a valid CIDR (e.g. 192.168.1.0/24).`, { field: `config.${field}` });
      }
    });

    if (typeof interfaceName !== 'string' || !interfaceName.trim()) {
      throw new HttpError(400, 'config.interface is required and must be a string.', { field: 'config.interface' });
    }

    const ipFields = [
      ['dhcpPoolStart', dhcpPoolStart],
      ['dhcpPoolEnd', dhcpPoolEnd],
      ['dnsServer', dnsServer],
    ];

    ipFields.forEach(([field, value]) => {
      if (typeof value !== 'string' || !ipv4Regex.test(value.trim())) {
        throw new HttpError(400, `config.${field} must be a valid IPv4 address.`, { field: `config.${field}` });
      }
    });

    if (typeof dhcpName !== 'string' || !dhcpName.trim()) {
      throw new HttpError(400, 'config.dhcpName is required and must be a string.', { field: 'config.dhcpName' });
    }

    if (ipToInt(dhcpPoolStart.trim()) > ipToInt(dhcpPoolEnd.trim())) {
      throw new HttpError(400, 'config.dhcpPoolStart must be lower than or equal to config.dhcpPoolEnd.', { field: 'config.dhcpPoolStart' });
    }

    req.body = {
      ...req.body,
      mikrotik: sanitizedMikrotik,
      config: {
        oldNetwork: oldNetwork.trim(),
        oldGateway: oldGateway.trim(),
        newNetwork: newNetwork.trim(),
        newGateway: newGateway.trim(),
        interface: interfaceName.trim(),
        dhcpPoolStart: dhcpPoolStart.trim(),
        dhcpPoolEnd: dhcpPoolEnd.trim(),
        dnsServer: dnsServer.trim(),
        dhcpName: dhcpName.trim(),
      },
    };

    next();
  } catch (error) {
    next(error);
  }
};
const validateWifiUpdateRequest = (req, _res, next) => {
  try {
    const { mikrotik, config } = req.body || {};
    if (!config || typeof config !== 'object' || Array.isArray(config)) {
      throw new HttpError(400, 'config object is required.', { field: 'config' });
    }

    const sanitizedMikrotik = validateMikrotikCredentials(mikrotik);
    const { ssid, wifiPassword } = config;

    if (typeof ssid !== 'string' || !ssid.trim()) {
      throw new HttpError(400, 'config.ssid is required and must be a non-empty string.', { field: 'config.ssid' });
    }

    if (typeof wifiPassword !== 'string' || wifiPassword.length < 8) {
      throw new HttpError(400, 'config.wifiPassword must be at least 8 characters.', { field: 'config.wifiPassword' });
    }

    req.body = {
      ...req.body,
      mikrotik: sanitizedMikrotik,
      config: {
        ssid: ssid.trim(),
        wifiPassword,
      },
    };

    next();
  } catch (error) {
    next(error);
  }
};
const validateRouteMail4gRequest = (req, _res, next) => {
  try {
    const { mikrotik, config } = req.body || {};
    if (!config || typeof config !== 'object' || Array.isArray(config)) {
      throw new HttpError(400, 'config object is required.', { field: 'config' });
    }

    const sanitizedMikrotik = validateMikrotikCredentials(mikrotik);
    const { deviceType, lanInterface, wan4gInterface, gateway4g } = config;

    if (!['mr100', 'chateau'].includes(String(deviceType || '').toLowerCase())) {
      throw new HttpError(400, 'config.deviceType must be either mr100 or chateau.', { field: 'config.deviceType' });
    }

    if (typeof lanInterface !== 'string' || !lanInterface.trim()) {
      throw new HttpError(400, 'config.lanInterface is required and must be a string.', { field: 'config.lanInterface' });
    }

    if (typeof wan4gInterface !== 'string' || !wan4gInterface.trim()) {
      throw new HttpError(400, 'config.wan4gInterface is required and must be a string.', { field: 'config.wan4gInterface' });
    }

    const normalizedDeviceType = String(deviceType).toLowerCase();
    if (normalizedDeviceType === 'mr100') {
      if (typeof gateway4g !== 'string' || !ipv4Regex.test(gateway4g.trim())) {
        throw new HttpError(400, 'config.gateway4g is required for mr100 and must be a valid IPv4 address.', {
          field: 'config.gateway4g',
        });
      }
    }

    req.body = {
      ...req.body,
      mikrotik: sanitizedMikrotik,
      config: {
        deviceType: normalizedDeviceType,
        lanInterface: lanInterface.trim(),
        wan4gInterface: wan4gInterface.trim(),
        gateway4g: typeof gateway4g === 'string' ? gateway4g.trim() : '',
      },
    };

    next();
  } catch (error) {
    next(error);
  }
};
module.exports = {
  validateWifiUpdateRequest,
  validateCreateDiagnostic,
  validatePortForwardingRequest,
  validateStaticIpRequest,
  validateLanNetworkChangeRequest,
  validateRouteMail4gRequest,
};