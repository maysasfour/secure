const recaptchaService = require('../services/recaptchaService');
const { AppError } = require('./errorHandler');
const AuditLog = require('../models/AuditLog');

/**
 * reCAPTCHA verification middleware
 * @param {Object} options - Middleware options
 * @param {string} options.action - reCAPTCHA action name
 * @param {number} options.threshold - Score threshold (0.0-1.0)
 * @param {boolean} options.required - Whether reCAPTCHA is required
 * @returns {Function} - Express middleware
 */
const verifyRecaptcha = (options = {}) => {
  const {
    action = 'DEFAULT_ACTION',
    threshold = 0.5,
    required = true,
    logAction = true
  } = options;

  return async (req, res, next) => {
    try {
      // Check if reCAPTCHA is enabled
      if (process.env.ENABLE_RECAPTCHA !== 'true') {
        return next();
      }

      const token = req.body.recaptchaToken || req.headers['x-recaptcha-token'];
      const ipAddress = req.ip;

      if (!token && required) {
        throw new AppError('reCAPTCHA token is required', 400);
      }

      if (!token && !required) {
        return next();
      }

      // Verify the token
      const verification = await recaptchaService.verifyToken(
        token,
        action,
        {
          threshold,
          ipAddress
        }
      );

      // Attach verification result to request
      req.recaptcha = verification;

      // Log the verification if enabled
      if (logAction && req.user) {
        await AuditLog.log({
          userId: req.user._id,
          email: req.user.email,
          action: 'RECAPTCHA_VERIFICATION',
          resource: 'Auth',
          method: req.method,
          endpoint: req.originalUrl,
          ipAddress,
          metadata: {
            action,
            score: verification.score,
            passed: verification.passed,
            threshold,
            reasons: verification.reasons,
            assessmentId: verification.assessmentId
          }
        });
      }

      // Check if verification passed
      if (!verification.passed) {
        // Log failed attempt
        await AuditLog.log({
          email: req.body.email,
          action: 'RECAPTCHA_FAILED',
          resource: 'Auth',
          method: req.method,
          endpoint: req.originalUrl,
          ipAddress,
          metadata: {
            action,
            score: verification.score,
            threshold,
            reasons: verification.reasons,
            assessmentId: verification.assessmentId
          },
          isSuspicious: true
        });

        throw new AppError('reCAPTCHA verification failed. Please try again.', 403);
      }

      next();
    } catch (error) {
      next(error);
    }
  };
};

/**
 * reCAPTCHA verification for specific actions
 */
const recaptcha = {
  // Login verification
  login: verifyRecaptcha({
    action: 'LOGIN',
    threshold: 0.7,
    required: true
  }),

  // Registration verification
  register: verifyRecaptcha({
    action: 'REGISTER',
    threshold: 0.6,
    required: true
  }),

  // Password reset verification
  passwordReset: verifyRecaptcha({
    action: 'PASSWORD_RESET',
    threshold: 0.6,
    required: true
  }),

  // Sensitive operations verification
  sensitive: (action, threshold = 0.8) =>
    verifyRecaptcha({
      action,
      threshold,
      required: true
    }),

  // Optional verification (for less sensitive operations)
  optional: (action, threshold = 0.5) =>
    verifyRecaptcha({
      action,
      threshold,
      required: false
    }),

  // Custom verification
  custom: verifyRecaptcha
};

module.exports = recaptcha;