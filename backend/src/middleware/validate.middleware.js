const HttpError = require('../utils/http-error');

const ipv4Regex = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const hostnameRegex = /^(?=.{1,253}$)(?:(?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+(?:[a-zA-Z]{2,63})$/;

const isValidTarget = (value) => ipv4Regex.test(value) || hostnameRegex.test(value) || value === 'localhost';

const validateCreateDiagnostic = (req, _res, next) => {
  const { target, ports, expectsSipService, mikrotik } = req.body || {};

  if (!target || typeof target !== 'string' || !isValidTarget(target.trim())) {
    return next(
      new HttpError(400, 'Invalid target. Provide a valid IPv4 address, hostname, or localhost.', {
        field: 'target',
      })
    );
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
    if (typeof mikrotik !== 'object' || mikrotik === null || Array.isArray(mikrotik)) {
      return next(new HttpError(400, 'mikrotik must be an object when provided.', { field: 'mikrotik' }));
    }

    const { host, username, password, port, privateKeyPath } = mikrotik;

    if (!host || typeof host !== 'string') {
      return next(new HttpError(400, 'mikrotik.host is required and must be a string.', { field: 'mikrotik.host' }));
    }

    if (!username || typeof username !== 'string') {
      return next(new HttpError(400, 'mikrotik.username is required and must be a string.', { field: 'mikrotik.username' }));
    }

    if (password !== undefined && typeof password !== 'string') {
      return next(new HttpError(400, 'mikrotik.password must be a string when provided.', { field: 'mikrotik.password' }));
    }

    if (port !== undefined && (!Number.isInteger(port) || port < 1 || port > 65535)) {
      return next(new HttpError(400, 'mikrotik.port must be an integer between 1 and 65535.', { field: 'mikrotik.port' }));
    }

    if (privateKeyPath !== undefined && typeof privateKeyPath !== 'string') {
      return next(new HttpError(400, 'mikrotik.privateKeyPath must be a string when provided.', { field: 'mikrotik.privateKeyPath' }));
    }

    if (!password && !privateKeyPath) {
      return next(
        new HttpError(400, 'Provide mikrotik.password or mikrotik.privateKeyPath for authentication.', {
          field: 'mikrotik.password',
        })
      );
    }
  }

  if (expectsSipService !== undefined && typeof expectsSipService !== 'boolean') {
    return next(new HttpError(400, 'expectsSipService must be a boolean when provided.', { field: 'expectsSipService' }));
  }

  req.body.target = target.trim();
  next();
};

module.exports = {
  validateCreateDiagnostic,
};