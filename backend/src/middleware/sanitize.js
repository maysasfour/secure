const xss = require('xss');
const validator = require('validator');
const mongoSanitize = require('express-mongo-sanitize');
const constants = require('../config/constants');

// Custom XSS options
const xssOptions = {
  whiteList: {
    a: ['href', 'title', 'target'],
    br: [],
    b: [],
    i: [],
    strong: [],
    em: [],
    code: [],
    pre: [],
    ul: [],
    ol: [],
    li: [],
    p: []
  },
  stripIgnoreTag: true,
  stripIgnoreTagBody: ['script', 'style', 'iframe', 'object', 'embed']
};

// XSS sanitization middleware
const xssSanitize = (req, res, next) => {
  // Sanitize request body
  if (req.body) {
    Object.keys(req.body).forEach(key => {
      if (typeof req.body[key] === 'string') {
        req.body[key] = xss(req.body[key], xssOptions);
        req.body[key] = validator.trim(req.body[key]);
        
        // Remove null bytes and other dangerous characters
        req.body[key] = req.body[key].replace(/\0/g, '');
        req.body[key] = req.body[key].replace(/[\x00-\x1F\x7F]/g, '');
      }
    });
  }
  
  // Sanitize query parameters
  if (req.query) {
    Object.keys(req.query).forEach(key => {
      if (typeof req.query[key] === 'string') {
        req.query[key] = xss(req.query[key], xssOptions);
        req.query[key] = validator.trim(req.query[key]);
        req.query[key] = req.query[key].replace(/\0/g, '');
      }
    });
  }
  
  // Sanitize URL parameters
  if (req.params) {
    Object.keys(req.params).forEach(key => {
      if (typeof req.params[key] === 'string') {
        req.params[key] = xss(req.params[key], xssOptions);
        req.params[key] = validator.trim(req.params[key]);
        req.params[key] = req.params[key].replace(/\0/g, '');
      }
    });
  }
  
  next();
};

// MongoDB injection prevention
const mongoSanitizeMiddleware = mongoSanitize({
  replaceWith: '_',
  onSanitize: ({ req, key }) => {
    // Log potential injection attempts
    if (req.body && req.body[key]) {
      const auditService = require('../services/auditService');
      auditService.logSuspiciousActivity({
        ip: req.ip,
        action: 'MONGO_INJECTION_ATTEMPT',
        endpoint: req.originalUrl,
        details: {
          key: key,
          value: req.body[key],
          sanitizedValue: req.body[key].replace(/[$.]/g, '_')
        }
      });
    }
  }
});

// SQL injection prevention
const sqlInjectionProtection = (req, res, next) => {
  const sqlKeywords = [
    'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'UNION', 'OR', 'AND',
    'EXEC', 'EXECUTE', 'TRUNCATE', 'CREATE', 'ALTER', 'TABLE', 'DATABASE'
  ];
  
  const checkForSQL = (input) => {
    if (typeof input !== 'string') return false;
    
    const upperInput = input.toUpperCase();
    return sqlKeywords.some(keyword => 
      upperInput.includes(keyword) && 
      !upperInput.includes(`'${keyword}'`) // Allow quoted keywords
    );
  };
  
  // Check request body
  if (req.body) {
    for (const key in req.body) {
      if (typeof req.body[key] === 'string' && checkForSQL(req.body[key])) {
        const auditService = require('../services/auditService');
        auditService.logSuspiciousActivity({
          ip: req.ip,
          action: 'SQL_INJECTION_ATTEMPT',
          endpoint: req.originalUrl,
          details: { key, value: req.body[key] }
        });
        
        return res.status(400).json({
          success: false,
          error: 'Invalid input detected'
        });
      }
    }
  }
  
  // Check query parameters
  if (req.query) {
    for (const key in req.query) {
      if (typeof req.query[key] === 'string' && checkForSQL(req.query[key])) {
        const auditService = require('../services/auditService');
        auditService.logSuspiciousActivity({
          ip: req.ip,
          action: 'SQL_INJECTION_ATTEMPT',
          endpoint: req.originalUrl,
          details: { key, value: req.query[key] }
        });
        
        return res.status(400).json({
          success: false,
          error: 'Invalid input detected'
        });
      }
    }
  }
  
  next();
};

// File upload sanitization
const fileUploadSanitization = (req, res, next) => {
  if (!req.file) return next();
  
  // Check file extension
  const allowedExtensions = ['.jpg', '.jpeg', '.png', '.pdf', '.doc', '.docx'];
  const fileExtension = req.file.originalname.toLowerCase().slice(
    req.file.originalname.lastIndexOf('.')
  );
  
  if (!allowedExtensions.includes(fileExtension)) {
    return res.status(400).json({
      success: false,
      error: `Invalid file type. Allowed: ${allowedExtensions.join(', ')}`
    });
  }
  
  // Check for double extensions (e.g., file.jpg.exe)
  if (req.file.originalname.split('.').length > 2) {
    const auditService = require('../services/auditService');
    auditService.logSuspiciousActivity({
      ip: req.ip,
      action: 'MALICIOUS_FILE_UPLOAD_ATTEMPT',
      endpoint: req.originalUrl,
      details: { filename: req.file.originalname }
    });
    
    return res.status(400).json({
      success: false,
      error: 'Invalid file name'
    });
  }
  
  // Sanitize filename
  req.file.originalname = req.file.originalname
    .replace(/[^a-zA-Z0-9._-]/g, '_') // Replace special chars
    .replace(/\.{2,}/g, '.') // Remove multiple dots
    .replace(/^\.+|\.+$/g, ''); // Remove leading/trailing dots
  
  next();
};

// Input type validation
const validateInputTypes = (req, res, next) => {
  const typeValidators = {
    email: validator.isEmail,
    url: validator.isURL,
    phone: (value) => validator.isMobilePhone(value, 'any'),
    date: (value) => !isNaN(Date.parse(value)),
    number: (value) => !isNaN(parseFloat(value)) && isFinite(value),
    integer: (value) => Number.isInteger(Number(value)),
    boolean: (value) => value === 'true' || value === 'false' || value === true || value === false
  };
  
  // Schema for different endpoints (simplified example)
  const schemas = {
    '/api/auth/register': {
      email: 'email',
      name: 'string',
      password: 'string',
      dateOfBirth: 'date'
    },
    '/api/users/:id': {
      phone: 'phone',
      department: 'string'
    }
  };
  
  const schema = schemas[req.path] || {};
  
  for (const [field, type] of Object.entries(schema)) {
    if (req.body[field] !== undefined) {
      const validator = typeValidators[type];
      if (validator && !validator(req.body[field])) {
        return res.status(400).json({
          success: false,
          error: `Invalid ${field}. Expected type: ${type}`
        });
      }
    }
  }
  
  next();
};

module.exports = {
  xssSanitize,
  mongoSanitizeMiddleware,
  sqlInjectionProtection,
  fileUploadSanitization,
  validateInputTypes
};