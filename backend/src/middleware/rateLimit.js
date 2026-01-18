const rateLimit = require('express-rate-limit');
const constants = require('../config/constants');

// Create rate limiters
const authLimiter = rateLimit({
  windowMs: constants.RATE_LIMITS.AUTH.windowMs,
  max: constants.RATE_LIMITS.AUTH.max,
  message: {
    success: false,
    error: 'Too many login attempts. Please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  keyGenerator: (req) => {
    // Use IP + email for more granular rate limiting
    return `${req.ip}-${req.body.email || 'unknown'}`;
  },
  handler: (req, res, next, options) => {
    // Log suspicious activity
    const auditService = require('../services/auditService');
    auditService.logSuspiciousActivity({
      ip: req.ip,
      action: 'RATE_LIMIT_EXCEEDED',
      endpoint: req.originalUrl,
      userAgent: req.get('user-agent'),
      details: {
        windowMs: options.windowMs,
        maxAttempts: options.max,
        currentCount: req.rateLimit.current
      }
    });
    
    res.status(429).json(options.message);
  }
});

const apiLimiter = rateLimit({
  windowMs: constants.RATE_LIMITS.API.windowMs,
  max: constants.RATE_LIMITS.API.max,
  message: {
    success: false,
    error: 'Too many requests. Please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip,
  skip: (req) => {
    // Skip rate limiting for certain paths or IPs
    const skipPaths = ['/health', '/api-docs', '/favicon.ico'];
    if (skipPaths.includes(req.path)) return true;
    
    // Skip for trusted IPs (e.g., internal services)
    const trustedIPs = ['127.0.0.1', '::1'];
    if (trustedIPs.includes(req.ip)) return true;
    
    return false;
  }
});

const registerLimiter = rateLimit({
  windowMs: constants.RATE_LIMITS.REGISTER.windowMs,
  max: constants.RATE_LIMITS.REGISTER.max,
  message: {
    success: false,
    error: 'Too many registration attempts. Please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip,
  skip: (req) => {
    // Allow admin to bypass registration limits
    return req.user && req.user.role === 'admin';
  }
});

// Dynamic rate limiting based on user behavior
const dynamicRateLimit = (defaultMax = 100) => {
  return (req, res, next) => {
    let maxRequests = defaultMax;
    
    // Reduce limit for unauthenticated users
    if (!req.user) {
      maxRequests = Math.floor(defaultMax / 2);
    }
    
    // Increase limit for trusted users
    if (req.user && req.user.role === 'admin') {
      maxRequests = defaultMax * 2;
    }
    
    // Check for suspicious behavior
    if (req.user && req.user.loginAttempts > 3) {
      maxRequests = Math.floor(defaultMax / 4);
    }
    
    return rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: maxRequests,
      message: {
        success: false,
        error: 'Rate limit exceeded. Please try again later.'
      },
      standardHeaders: true,
      legacyHeaders: false,
      keyGenerator: (req) => req.user ? req.user._id.toString() : req.ip
    })(req, res, next);
  };
};

// Rate limiting for specific endpoints
const endpointSpecificLimit = (endpoint, max) => {
  return rateLimit({
    windowMs: 15 * 60 * 1000,
    max: max,
    message: {
      success: false,
      error: `Too many requests to ${endpoint}. Please try again later.`
    },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => req.ip,
    skip: (req) => req.path !== endpoint
  });
};

module.exports = {
  authLimiter,
  apiLimiter,
  registerLimiter,
  dynamicRateLimit,
  endpointSpecificLimit
};