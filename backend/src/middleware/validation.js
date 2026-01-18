const { body, param, query, validationResult } = require('express-validator');
const validator = require('validator');
const constants = require('../config/constants');

// Common validation chains
const validateRegistration = [
  body('email')
    .trim()
    .normalizeEmail()
    .isEmail().withMessage('Please provide a valid email address')
    .isLength({ max: 100 }).withMessage('Email cannot exceed 100 characters'),
  
  body('password')
    .isLength({ min: constants.SECURITY.PASSWORD_MIN_LENGTH })
    .withMessage(`Password must be at least ${constants.SECURITY.PASSWORD_MIN_LENGTH} characters`)
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'),
  
  body('name')
    .trim()
    .escape()
    .isLength({ min: 2, max: 50 })
    .withMessage('Name must be between 2 and 50 characters')
    .matches(/^[a-zA-Z\s]*$/)
    .withMessage('Name can only contain letters and spaces'),
  
  body('dateOfBirth')
    .isDate()
    .withMessage('Please provide a valid date of birth')
    .custom((value) => {
      const birthDate = new Date(value);
      const today = new Date();
      const age = today.getFullYear() - birthDate.getFullYear();
      
      if (age < 13) {
        throw new Error('You must be at least 13 years old');
      }
      if (age > 120) {
        throw new Error('Please provide a valid date of birth');
      }
      return true;
    }),
  
  body('phone')
    .optional({ checkFalsy: true })
    .trim()
    .custom((value) => {
      if (!validator.isMobilePhone(value, 'any', { strictMode: true })) {
        throw new Error('Please provide a valid phone number');
      }
      return true;
    }),
  
  body('studentId')
    .optional({ checkFalsy: true })
    .trim()
    .isAlphanumeric()
    .withMessage('Student ID must be alphanumeric')
    .isLength({ min: 6, max: 10 })
    .withMessage('Student ID must be between 6 and 10 characters'),
  
  body('department')
    .optional({ checkFalsy: true })
    .trim()
    .escape()
    .isLength({ max: 100 })
    .withMessage('Department cannot exceed 100 characters'),
];

const validateLogin = [
  body('email')
    .trim()
    .normalizeEmail()
    .isEmail().withMessage('Please provide a valid email address'),
  
  body('password')
    .notEmpty()
    .withMessage('Password is required'),
];

const validatePasswordChange = [
  body('currentPassword')
    .notEmpty()
    .withMessage('Current password is required'),
  
  body('newPassword')
    .isLength({ min: constants.SECURITY.PASSWORD_MIN_LENGTH })
    .withMessage(`Password must be at least ${constants.SECURITY.PASSWORD_MIN_LENGTH} characters`)
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character')
    .custom((value, { req }) => {
      if (value === req.body.currentPassword) {
        throw new Error('New password must be different from current password');
      }
      return true;
    }),
  
  body('confirmPassword')
    .custom((value, { req }) => {
      if (value !== req.body.newPassword) {
        throw new Error('Passwords do not match');
      }
      return true;
    }),
];

const validateEmail = [
  body('email')
    .trim()
    .normalizeEmail()
    .isEmail().withMessage('Please provide a valid email address'),
];

const validateUserId = [
  param('id')
    .isMongoId()
    .withMessage('Invalid user ID format'),
];

const validatePagination = [
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be a positive integer')
    .toInt(),
  
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100')
    .toInt(),
  
  query('sort')
    .optional()
    .trim()
    .escape(),
  
  query('search')
    .optional()
    .trim()
    .escape()
    .isLength({ max: 100 })
    .withMessage('Search query cannot exceed 100 characters'),
];

// File upload validation
const validateFileUpload = [
  body('file')
    .custom((value, { req }) => {
      if (!req.file) {
        throw new Error('File is required');
      }
      
      // Check file type
      if (!constants.FILE.ALLOWED_TYPES.includes(req.file.mimetype)) {
        throw new Error(`Invalid file type. Allowed types: ${constants.FILE.ALLOWED_TYPES.join(', ')}`);
      }
      
      // Check file size
      if (req.file.size > constants.FILE.MAX_SIZE) {
        throw new Error(`File size must be less than ${constants.FILE.MAX_SIZE / 1024 / 1024}MB`);
      }
      
      return true;
    }),
];

// Sanitize user input
const sanitizeInput = [
  body('*').escape(),
  body('*').trim(),
];

// Validate and sanitize middleware
const validate = (validations) => {
  return async (req, res, next) => {
    // Run all validations
    await Promise.all(validations.map(validation => validation.run(req)));
    
    // Check for validation errors
    const errors = validationResult(req);
    
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        errors: errors.array().map(err => ({
          field: err.path,
          message: err.msg
        }))
      });
    }
    
    // Apply XSS protection to string fields
    if (req.body) {
      Object.keys(req.body).forEach(key => {
        if (typeof req.body[key] === 'string') {
          req.body[key] = validator.escape(req.body[key]);
          req.body[key] = validator.trim(req.body[key]);
        }
      });
    }
    
    next();
  };
};

module.exports = {
  validate,
  validateRegistration,
  validateLogin,
  validatePasswordChange,
  validateEmail,
  validateUserId,
  validatePagination,
  validateFileUpload,
  sanitizeInput
};