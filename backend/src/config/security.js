const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const cors = require('cors');

const securityConfig = {
  helmet: helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        baseUri: ["'self'"],
        fontSrc: ["'self'", "https:", "data:"],
        frameAncestors: ["'self'"],
        imgSrc: ["'self'", "data:", "https:"],
        objectSrc: ["'none'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        scriptSrcAttr: ["'none'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        upgradeInsecureRequests: [],
      },
    },
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" },
  }),
  
  cors: cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-Requested-With',
      'Accept',
      'Origin',
      'Access-Control-Request-Method',
      'Access-Control-Request-Headers'
    ],
    exposedHeaders: ['Content-Range', 'X-Content-Range'],
    maxAge: 86400
  }),
  
  rateLimiters: {
    auth: rateLimit({
      windowMs: 15 * 60 * 1000,
      max: 5,
      message: 'Too many login attempts from this IP, please try again after 15 minutes',
      standardHeaders: true,
      legacyHeaders: false,
      skipSuccessfulRequests: true,
      keyGenerator: (req) => req.ip,
    }),
    
    api: rateLimit({
      windowMs: 15 * 60 * 1000,
      max: 100,
      message: 'Too many requests from this IP, please try again after 15 minutes',
      standardHeaders: true,
      legacyHeaders: false,
    }),
    
    register: rateLimit({
      windowMs: 60 * 60 * 1000,
      max: 3,
      message: 'Too many registration attempts from this IP',
      standardHeaders: true,
      legacyHeaders: false,
    }),
  },

  mongoSanitize: mongoSanitize({
    replaceWith: '_',
    onSanitize: ({ req, key }) => {
      console.warn(`Sanitized ${key} in request`);
    }
  }),
  
  xss: xss(),
  
  hpp: hpp(),
};

module.exports = securityConfig;