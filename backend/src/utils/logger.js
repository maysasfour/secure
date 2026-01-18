const winston = require('winston');
const path = require('path');
const fs = require('fs');

// Create logs directory if it doesn't exist
const logsDir = path.join(__dirname, '../../logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

// Define log format
const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.splat(),
  winston.format.json()
);

// Define console format for development
const consoleFormat = winston.format.combine(
  winston.format.colorize(),
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.printf(
    ({ timestamp, level, message, ...meta }) => {
      let log = `${timestamp} [${level}]: ${message}`;
      
      if (Object.keys(meta).length > 0) {
        log += ` ${JSON.stringify(meta)}`;
      }
      
      return log;
    }
  )
);

// Create the logger
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: logFormat,
  defaultMeta: { service: 'secure-campus-portal' },
  transports: [
    // Console transport for all environments
    new winston.transports.Console({
      format: consoleFormat,
      handleExceptions: true,
      handleRejections: true
    }),
    
    // File transport for errors
    new winston.transports.File({
      filename: path.join(logsDir, 'error.log'),
      level: 'error',
      maxsize: 5242880, // 5MB
      maxFiles: 5,
      tailable: true
    }),
    
    // File transport for all logs
    new winston.transports.File({
      filename: path.join(logsDir, 'combined.log'),
      maxsize: 5242880, // 5MB
      maxFiles: 5,
      tailable: true
    }),
    
    // File transport for security events
    new winston.transports.File({
      filename: path.join(logsDir, 'security.log'),
      level: 'warn',
      maxsize: 5242880,
      maxFiles: 10,
      tailable: true
    }),
    
    // File transport for audit trail
    new winston.transports.File({
      filename: path.join(logsDir, 'audit.log'),
      level: 'info',
      maxsize: 10485760, // 10MB
      maxFiles: 10,
      tailable: true,
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      )
    })
  ],
  exitOnError: false
});

// If we're in production, add some additional transports
if (process.env.NODE_ENV === 'production') {
  // Add a transport for monitoring (e.g., Datadog, Loggly, etc.)
  logger.add(new winston.transports.Console({
    format: winston.format.simple(),
    level: 'warn'
  }));
}

// Create a stream object for Morgan (HTTP logging)
logger.stream = {
  write: (message) => {
    logger.info(message.trim());
  }
};

// Custom logger methods for security events
logger.security = {
  info: (message, meta = {}) => {
    logger.info(`[SECURITY] ${message}`, { ...meta, category: 'security' });
  },
  warn: (message, meta = {}) => {
    logger.warn(`[SECURITY] ${message}`, { ...meta, category: 'security' });
  },
  error: (message, meta = {}) => {
    logger.error(`[SECURITY] ${message}`, { ...meta, category: 'security' });
  },
  alert: (message, meta = {}) => {
    logger.alert(`[SECURITY ALERT] ${message}`, { ...meta, category: 'security-alert' });
  }
};

// Custom logger methods for audit trail
logger.audit = (action, user, resource, details = {}) => {
  logger.info(`[AUDIT] ${action}`, {
    category: 'audit',
    action,
    user: user ? {
      id: user._id || user.id,
      email: user.email,
      role: user.role
    } : null,
    resource,
    details,
    timestamp: new Date().toISOString()
  });
};

// Request logging middleware
logger.logRequest = (req, res, next) => {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    
    const logData = {
      method: req.method,
      url: req.originalUrl,
      status: res.statusCode,
      duration: `${duration}ms`,
      ip: req.ip,
      userAgent: req.get('user-agent'),
      userId: req.user ? req.user._id : 'anonymous'
    };
    
    // Log based on status code
    if (res.statusCode >= 400) {
      logger.warn('HTTP Request', logData);
    } else {
      logger.info('HTTP Request', logData);
    }
  });
  
  next();
};

// Error logging helper
logger.logError = (error, context = {}) => {
  const errorData = {
    message: error.message,
    stack: error.stack,
    name: error.name,
    ...context
  };
  
  // Log to error file
  logger.error('Application Error', errorData);
  
  // Also log to security if it's a security error
  if (error.name === 'SecurityError' || error.message.includes('security') || error.message.includes('unauthorized')) {
    logger.security.error('Security Error', errorData);
  }
};

// Performance logging
logger.performance = (operation, duration, meta = {}) => {
  logger.debug(`[PERFORMANCE] ${operation} took ${duration}ms`, {
    category: 'performance',
    operation,
    duration,
    ...meta
  });
};

// Database query logging
logger.query = (query, duration, collection) => {
  logger.debug(`[DATABASE] Query on ${collection} took ${duration}ms`, {
    category: 'database',
    collection,
    duration,
    query: typeof query === 'string' ? query : JSON.stringify(query)
  });
};

module.exports = logger;