const app = require('./app');
const env = require('./config/env');
const logger = require('./config/logger');
const repository = require('./repositories/diagnostic.repository');

const start = async () => {
  try {
    await repository.loadStore();

    app.listen(env.port, env.host, () => {
      logger.info({ host: env.host, port: env.port }, 'Backend server started');
    });
  } catch (error) {
    logger.error({ err: error }, 'Failed to start server');
    process.exit(1);
  }
};

start();
