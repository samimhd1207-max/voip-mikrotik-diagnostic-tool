const pino = require('pino');
const env = require('./env');

const logger = pino({
  level: env.logLevel,
  base: undefined,
  timestamp: pino.stdTimeFunctions.isoTime,
  redact: {
    paths: ['req.body.mikrotik.password', 'mikrotik.password', 'password'],
    censor: '[REDACTED]',
  },
});

module.exports = logger;