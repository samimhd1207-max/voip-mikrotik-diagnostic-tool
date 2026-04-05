const logger = require('../config/logger');

const notFoundHandler = (req, _res, next) => {
  const error = new Error(`Route not found: ${req.method} ${req.originalUrl}`);
  error.statusCode = 404;
  next(error);
};

const errorHandler = (err, req, res, _next) => {
  const statusCode = err.statusCode || 500;

  if (statusCode >= 500) {
    logger.error(
      {
        err,
        method: req.method,
        path: req.originalUrl,
      },
      'Unhandled error'
    );
  }

  res.status(statusCode).json({
    error: {
      message: err.message || 'Internal Server Error',
      details: err.details || null,
    },
  });
};

module.exports = {
  notFoundHandler,
  errorHandler,
};
