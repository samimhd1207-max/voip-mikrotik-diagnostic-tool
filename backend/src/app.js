const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const pinoHttp = require('pino-http');

const env = require('./config/env');
const logger = require('./config/logger');
const diagnosticsRoutes = require('./routes/diagnostics.routes');
const healthRoutes = require('./routes/health.routes');
const mikrotikRoutes = require('./routes/mikrotik.routes');
const { notFoundHandler, errorHandler } = require('./middleware/error.middleware');

const app = express();

app.use(
  pinoHttp({
    logger,
    autoLogging: true,
  })
);

app.use(helmet());
app.use(
  cors({
    origin: env.corsOrigin,
  })
);
app.use(express.json({ limit: '100kb' }));
app.use(
  rateLimit({
    windowMs: 60 * 1000,
    limit: 60,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

app.use('/health', healthRoutes);
app.use('/api/v1/diagnostics', diagnosticsRoutes);
app.use('/api/v1/mikrotik', mikrotikRoutes);

app.use(notFoundHandler);
app.use(errorHandler);

module.exports = app;