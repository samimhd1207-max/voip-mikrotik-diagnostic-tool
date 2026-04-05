const HttpError = require('../utils/http-error');

const ipv4Regex = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const hostnameRegex = /^(?=.{1,253}$)(?:(?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+(?:[a-zA-Z]{2,63})$/;

const isValidTarget = (value) => ipv4Regex.test(value) || hostnameRegex.test(value) || value === 'localhost';

const validateCreateDiagnostic = (req, _res, next) => {
  const { target, ports } = req.body || {};

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

  req.body.target = target.trim();
  next();
};

module.exports = {
  validateCreateDiagnostic,
};
