const path = require('path');
const dotenv = require('dotenv');

dotenv.config();

const env = {
  nodeEnv: process.env.NODE_ENV || 'development',
  port: Number(process.env.PORT || 4000),
  host: process.env.HOST || '0.0.0.0',
  logLevel: process.env.LOG_LEVEL || 'info',
  corsOrigin: process.env.CORS_ORIGIN || '*',
  diagnosticsStoreFile: process.env.DIAGNOSTICS_STORE_FILE
    ? path.resolve(process.cwd(), process.env.DIAGNOSTICS_STORE_FILE)
    : path.resolve(process.cwd(), 'data/diagnostics.json'),
};

module.exports = env;
