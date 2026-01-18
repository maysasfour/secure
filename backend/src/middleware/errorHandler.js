const logger = require('../utils/logger');
const constants = require('../config/constants');
const AuditLog = require('../models/AuditLog');

class AppError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
    this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
    this.isOperational = true;

    Error.captureStackTrace(this, this.constructor);
  }
}

// Handle specific error types
const handleJWTError = () => 
  new AppError('Invalid token. Please log in again.', 401);

const handleJWTExpiredError = () => 
  new AppError('Your token has expired. Please log in again.', 401);

const handleValidationErrorDB = (err) => {
  const errors = Object.values(err.errors).map(el => el.message);
  const message = `Invalid input data. ${errors.join('. ')}`;
  return new AppError(message, 400);
};

const handleDuplicateFieldsDB = (err) => {
  const value = err.errmsg.match(/(["'])(\\?.)*?\1/)[0];
  const message = `Duplicate field value: ${value}. Please use another value.`;
  return new AppError(message, 400);
};

const handleCastErrorDB = (err) => {
  const message = `Invalid ${err.path}: ${err.value}.`;
  return new AppError(message, 400);
};

// Global error handling middleware
const errorHandler = (err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'error';

  // Log error
  logger.error(`${err.statusCode} - ${err.message}`, {
    stack: err.stack,
    url: req.originalUrl,
    method: req.method,
    ip: req.ip,
    user: req.user ? req.user._id : 'anonymous'
  });

  // Log to audit trail for security-related errors
  if (err.statusCode === 401 || err.statusCode === 403 || err.statusCode >= 500) {
    AuditLog.log({
      userId: req.user ? req.user._id : null,
      action: 'ERROR',
      resource: req.originalUrl,
      method: req.method,
      statusCode: err.statusCode,
      error: {
        message: err.message,
        code: err.code
      },
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      requestTime: req._startTime,
      responseTime: new Date()
    }).catch(logError => {
      logger.error('Failed to log audit trail for error:', logError);
    });
  }

  // Development vs Production error responses
  if (process.env.NODE_ENV === 'development') {
    sendErrorDev(err, req, res);
  } else {
    let error = { ...err };
    error.message = err.message;

    // Handle specific MongoDB errors
    if (error.name === 'CastError') error = handleCastErrorDB(error);
    if (error.code === 11000) error = handleDuplicateFieldsDB(error);
    if (error.name === 'ValidationError') error = handleValidationErrorDB(error);
    if (error.name === 'JsonWebTokenError') error = handleJWTError();
    if (error.name === 'TokenExpiredError') error = handleJWTExpiredError();

    sendErrorProd(error, req, res);
  }
};

const sendErrorDev = (err, req, res) => {
  // API error response
  if (req.originalUrl.startsWith('/api')) {
    return res.status(err.statusCode).json({
      success: false,
      status: err.status,
      error: err,
      message: err.message,
      stack: err.stack
    });
  }

  // Render error page for web
  logger.error('ERROR 💥', err);
  res.status(err.statusCode).render('error', {
    title: 'Something went wrong!',
    msg: err.message
  });
};

const sendErrorProd = (err, req, res) => {
  // Operational, trusted error: send message to client
  if (err.isOperational) {
    return res.status(err.statusCode).json({
      success: false,
      status: err.status,
      message: err.message
    });
  }

  // Programming or other unknown error: don't leak error details
  logger.error('ERROR 💥', err);

  // Send generic message
  res.status(500).json({
    success: false,
    status: 'error',
    message: 'Something went wrong!'
  });
};

// 404 Not Found handler
const notFoundHandler = (req, res, next) => {
  const error = new AppError(`Cannot find ${req.originalUrl} on this server!`, 404);
  next(error);
};

// Async error wrapper (eliminates need for try-catch blocks)
const catchAsync = (fn) => {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

// Security error handler for suspicious activities
const securityErrorHandler = (err, req, res, next) => {
  // Check if error is security related
  const securityErrors = [
    'SQL injection attempt',
    'XSS attempt',
    'CSRF token mismatch',
    'Invalid file upload',
    'Rate limit exceeded',
    'Brute force attempt'
  ];

  const isSecurityError = securityErrors.some(error => 
    err.message.toLowerCase().includes(error.toLowerCase())
  );

  if (isSecurityError) {
    // Log security event
    const auditService = require('../services/auditService');
    auditService.logSecurityEvent({
      type: 'SECURITY_ERROR',
      severity: 'HIGH',
      ip: req.ip,
      user: req.user ? req.user._id : null,
      endpoint: req.originalUrl,
      error: err.message,
      timestamp: new Date()
    });

    // Send generic error to avoid information leakage
    return res.status(400).json({
      success: false,
      error: 'Invalid request'
    });
  }

  next(err);
};

module.exports = {
  AppError,
  errorHandler,
  notFoundHandler,
  catchAsync,
  securityErrorHandler
};