const validator = require('validator');
const constants = require('../config/constants');

class ValidationUtils {
  /**
   * Validate user registration data
   * @param {Object} data - User data
   * @returns {Object} - Validation result
   */
  validateRegistration(data) {
    const errors = {};

    // Email validation
    if (!data.email || !validator.isEmail(data.email)) {
      errors.email = 'Valid email is required';
    }

    // Password validation
    const passwordValidation = this.validatePassword(data.password);
    if (!passwordValidation.isValid) {
      errors.password = passwordValidation.suggestions.join(', ');
    }

    // Name validation
    if (!data.name || data.name.trim().length < 2) {
      errors.name = 'Name must be at least 2 characters';
    }

    // Date of birth validation
    if (!data.dateOfBirth || !this.isValidDate(data.dateOfBirth)) {
      errors.dateOfBirth = 'Valid date of birth is required';
    } else {
      const age = this.calculateAge(new Date(data.dateOfBirth));
      if (age < 13) {
        errors.dateOfBirth = 'You must be at least 13 years old';
      }
    }

    // Optional fields validation
    if (data.phone && !validator.isMobilePhone(data.phone, 'any', { strictMode: true })) {
      errors.phone = 'Valid phone number is required';
    }

    if (data.studentId && !/^[A-Z0-9]{6,10}$/i.test(data.studentId)) {
      errors.studentId = 'Student ID must be 6-10 alphanumeric characters';
    }

    return {
      isValid: Object.keys(errors).length === 0,
      errors
    };
  }

  /**
   * Validate password strength
   * @param {string} password - Password to validate
   * @returns {Object} - Validation result
   */
  validatePassword(password) {
    const requirements = {
      minLength: password.length >= constants.SECURITY.PASSWORD_MIN_LENGTH,
      hasUpperCase: /[A-Z]/.test(password),
      hasLowerCase: /[a-z]/.test(password),
      hasNumbers: /\d/.test(password),
      hasSpecialChar: /[!@#$%^&*(),.?":{}|<>]/.test(password),
      noSpaces: !/\s/.test(password),
      noCommonPatterns: !this.isCommonPassword(password)
    };

    const isValid = Object.values(requirements).every(req => req === true);
    const suggestions = [];

    if (!requirements.minLength) {
      suggestions.push(`Password must be at least ${constants.SECURITY.PASSWORD_MIN_LENGTH} characters`);
    }
    if (!requirements.hasUpperCase) {
      suggestions.push('Password must contain at least one uppercase letter');
    }
    if (!requirements.hasLowerCase) {
      suggestions.push('Password must contain at least one lowercase letter');
    }
    if (!requirements.hasNumbers) {
      suggestions.push('Password must contain at least one number');
    }
    if (!requirements.hasSpecialChar) {
      suggestions.push('Password must contain at least one special character');
    }
    if (!requirements.noSpaces) {
      suggestions.push('Password must not contain spaces');
    }
    if (!requirements.noCommonPatterns) {
      suggestions.push('Password is too common or follows a common pattern');
    }

    return { isValid, suggestions };
  }

  /**
   * Check if password is common
   * @param {string} password - Password to check
   * @returns {boolean} - True if common
   */
  isCommonPassword(password) {
    const commonPasswords = [
      'password', '123456', '12345678', '123456789', '12345',
      'qwerty', 'abc123', 'password1', 'admin', 'letmein'
    ];
    return commonPasswords.includes(password.toLowerCase());
  }

  /**
   * Validate email
   * @param {string} email - Email to validate
   * @returns {Object} - Validation result
   */
  validateEmail(email) {
    const isValid = validator.isEmail(email);
    const normalized = isValid ? validator.normalizeEmail(email) : null;

    return {
      isValid,
      normalized,
      suggestions: isValid ? [] : ['Please provide a valid email address']
    };
  }

  /**
   * Validate date
   * @param {string} date - Date string
   * @returns {boolean} - True if valid date
   */
  isValidDate(date) {
    return !isNaN(Date.parse(date));
  }

  /**
   * Calculate age from date of birth
   * @param {Date} birthDate - Date of birth
   * @returns {number} - Age in years
   */
  calculateAge(birthDate) {
    const today = new Date();
    let age = today.getFullYear() - birthDate.getFullYear();
    const monthDiff = today.getMonth() - birthDate.getMonth();

    if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birthDate.getDate())) {
      age--;
    }

    return age;
  }

  /**
   * Sanitize input string
   * @param {string} input - Input to sanitize
   * @returns {string} - Sanitized input
   */
  sanitizeString(input) {
    if (typeof input !== 'string') return input;

    return validator.escape(validator.trim(input));
  }

  /**
   * Validate URL
   * @param {string} url - URL to validate
   * @returns {boolean} - True if valid URL
   */
  isValidUrl(url) {
    return validator.isURL(url, {
      protocols: ['http', 'https'],
      require_protocol: true,
      require_valid_protocol: true
    });
  }

  /**
   * Validate file type
   * @param {string} mimeType - MIME type
   * @param {Array} allowedTypes - Allowed MIME types
   * @returns {boolean} - True if valid
   */
  isValidFileType(mimeType, allowedTypes = constants.FILE.ALLOWED_TYPES) {
    return allowedTypes.includes(mimeType);
  }

  /**
   * Validate file size
   * @param {number} size - File size in bytes
   * @param {number} maxSize - Maximum size in bytes
   * @returns {boolean} - True if valid
   */
  isValidFileSize(size, maxSize = constants.FILE.MAX_SIZE) {
    return size <= maxSize;
  }

  /**
   * Validate user update data
   * @param {Object} data - Update data
   * @returns {Object} - Validation result
   */
  validateUserUpdate(data) {
    const errors = {};

    if (data.email && !validator.isEmail(data.email)) {
      errors.email = 'Valid email is required';
    }

    if (data.phone && !validator.isMobilePhone(data.phone, 'any', { strictMode: true })) {
      errors.phone = 'Valid phone number is required';
    }

    if (data.name && data.name.trim().length < 2) {
      errors.name = 'Name must be at least 2 characters';
    }

    return {
      isValid: Object.keys(errors).length === 0,
      errors
    };
  }

  /**
   * Validate pagination parameters
   * @param {number} page - Page number
   * @param {number} limit - Items per page
   * @returns {Object} - Validation result
   */
  validatePagination(page, limit) {
    const errors = {};

    if (page && (!Number.isInteger(page) || page < 1)) {
      errors.page = 'Page must be a positive integer';
    }

    if (limit && (!Number.isInteger(limit) || limit < 1 || limit > 100)) {
      errors.limit = 'Limit must be between 1 and 100';
    }

    return {
      isValid: Object.keys(errors).length === 0,
      errors
    };
  }

  /**
   * Validate search query
   * @param {string} query - Search query
   * @returns {Object} - Validation result
   */
  validateSearchQuery(query) {
    const errors = {};

    if (query && query.length > 100) {
      errors.query = 'Search query cannot exceed 100 characters';
    }

    // Check for potentially dangerous characters
    const dangerousPatterns = /[<>$(){}[\]\\]/;
    if (query && dangerousPatterns.test(query)) {
      errors.query = 'Search query contains invalid characters';
    }

    return {
      isValid: Object.keys(errors).length === 0,
      errors
    };
  }
}

// Create singleton instance
const validationUtils = new ValidationUtils();

module.exports = validationUtils;