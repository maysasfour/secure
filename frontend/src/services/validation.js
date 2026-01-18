// Frontend validation utilities

/**
 * Validate password strength
 * @param {string} password - Password to validate
 * @returns {Object} - Validation result
 */
export const validatePassword = (password) => {
  const requirements = {
    minLength: password.length >= 8,
    hasUpperCase: /[A-Z]/.test(password),
    hasLowerCase: /[a-z]/.test(password),
    hasNumbers: /\d/.test(password),
    hasSpecialChar: /[!@#$%^&*(),.?":{}|<>]/.test(password),
    noSpaces: !/\s/.test(password),
    noCommonPatterns: !isCommonPassword(password)
  };

  const isValid = Object.values(requirements).every(req => req === true);
  const score = calculatePasswordScore(password);

  return {
    isValid,
    score,
    requirements,
    suggestions: !isValid ? getPasswordSuggestions(requirements) : []
  };
};

/**
 * Calculate password score (0-100)
 * @param {string} password - Password to score
 * @returns {number} - Score
 */
const calculatePasswordScore = (password) => {
  let score = 0;
  
  // Length
  if (password.length >= 8) score += 20;
  if (password.length >= 12) score += 10;
  if (password.length >= 16) score += 10;
  
  // Character variety
  if (/[a-z]/.test(password)) score += 10;
  if (/[A-Z]/.test(password)) score += 10;
  if (/\d/.test(password)) score += 10;
  if (/[^a-zA-Z0-9]/.test(password)) score += 10;
  
  // Entropy approximation
  const charSet = new Set(password);
  const entropy = password.length * Math.log2(charSet.size || 1);
  score += Math.min(entropy / 2, 20);
  
  return Math.min(Math.round(score), 100);
};

/**
 * Check if password is common
 * @param {string} password - Password to check
 * @returns {boolean} - True if common
 */
const isCommonPassword = (password) => {
  const commonPasswords = [
    'password', '123456', '12345678', '123456789', '12345',
    'qwerty', 'abc123', 'password1', 'admin', 'letmein',
    'welcome', 'monkey', 'login', 'passw0rd', 'master',
    'hello', 'iloveyou', 'welcome123', 'sunshine', 'football'
  ];
  
  return commonPasswords.includes(password.toLowerCase());
};

/**
 * Get password improvement suggestions
 * @param {Object} requirements - Failed requirements
 * @returns {Array} - Suggestions
 */
const getPasswordSuggestions = (requirements) => {
  const suggestions = [];
  
  if (!requirements.minLength) {
    suggestions.push('Password must be at least 8 characters long');
  }
  if (!requirements.hasUpperCase) {
    suggestions.push('Add at least one uppercase letter');
  }
  if (!requirements.hasLowerCase) {
    suggestions.push('Add at least one lowercase letter');
  }
  if (!requirements.hasNumbers) {
    suggestions.push('Add at least one number');
  }
  if (!requirements.hasSpecialChar) {
    suggestions.push('Add at least one special character (!@#$%^&* etc.)');
  }
  if (!requirements.noSpaces) {
    suggestions.push('Remove spaces from password');
  }
  if (!requirements.noCommonPatterns) {
    suggestions.push('Avoid common passwords and patterns');
  }
  
  return suggestions;
};

/**
 * Validate email address
 * @param {string} email - Email to validate
 * @returns {Object} - Validation result
 */
export const validateEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const isValid = emailRegex.test(email);
  
  return {
    isValid,
    suggestions: !isValid ? ['Please enter a valid email address'] : []
  };
};

/**
 * Validate phone number
 * @param {string} phone - Phone number to validate
 * @returns {Object} - Validation result
 */
export const validatePhone = (phone) => {
  const phoneRegex = /^[\+]?[1-9][\d]{0,15}$/;
  const isValid = phoneRegex.test(phone.replace(/[-\s]/g, ''));
  
  return {
    isValid,
    suggestions: !isValid ? ['Please enter a valid phone number'] : []
  };
};

/**
 * Validate date of birth
 * @param {string} dateOfBirth - Date string
 * @returns {Object} - Validation result
 */
export const validateDateOfBirth = (dateOfBirth) => {
  const date = new Date(dateOfBirth);
  const today = new Date();
  const age = today.getFullYear() - date.getFullYear();
  
  const isValid = !isNaN(date.getTime()) && age >= 13 && age <= 120;
  
  return {
    isValid,
    suggestions: !isValid ? ['You must be at least 13 years old'] : []
  };
};

/**
 * Validate student ID
 * @param {string} studentId - Student ID
 * @returns {Object} - Validation result
 */
export const validateStudentId = (studentId) => {
  const isValid = /^[A-Z0-9]{6,10}$/i.test(studentId);
  
  return {
    isValid,
    suggestions: !isValid ? ['Student ID must be 6-10 alphanumeric characters'] : []
  };
};

/**
 * Validate name
 * @param {string} name - Name to validate
 * @returns {Object} - Validation result
 */
export const validateName = (name) => {
  const isValid = name.trim().length >= 2 && /^[a-zA-Z\s]*$/.test(name);
  
  return {
    isValid,
    suggestions: !isValid ? ['Name must be at least 2 letters with no special characters'] : []
  };
};

/**
 * Validate URL
 * @param {string} url - URL to validate
 * @returns {Object} - Validation result
 */
export const validateUrl = (url) => {
  try {
    new URL(url);
    return { isValid: true, suggestions: [] };
  } catch {
    return { 
      isValid: false, 
      suggestions: ['Please enter a valid URL (e.g., https://example.com)'] 
    };
  }
};

/**
 * Validate file upload
 * @param {File} file - File to validate
 * @param {Object} options - Validation options
 * @returns {Object} - Validation result
 */
export const validateFile = (file, options = {}) => {
  const {
    maxSize = 5 * 1024 * 1024, // 5MB
    allowedTypes = ['image/jpeg', 'image/png', 'application/pdf'],
    allowedExtensions = ['.jpg', '.jpeg', '.png', '.pdf']
  } = options;
  
  const errors = [];
  
  // Check file size
  if (file.size > maxSize) {
    errors.push(`File size must be less than ${maxSize / 1024 / 1024}MB`);
  }
  
  // Check file type
  if (!allowedTypes.includes(file.type)) {
    errors.push(`File type not allowed. Allowed types: ${allowedTypes.join(', ')}`);
  }
  
  // Check file extension
  const extension = file.name.toLowerCase().slice(file.name.lastIndexOf('.'));
  if (!allowedExtensions.includes(extension)) {
    errors.push(`File extension not allowed. Allowed: ${allowedExtensions.join(', ')}`);
  }
  
  // Check for dangerous extensions
  const dangerousExtensions = ['.exe', '.bat', '.sh', '.php', '.js', '.py'];
  if (dangerousExtensions.includes(extension)) {
    errors.push('This file type may be dangerous');
  }
  
  return {
    isValid: errors.length === 0,
    errors
  };
};

/**
 * Validate credit card number
 * @param {string} cardNumber - Credit card number
 * @returns {Object} - Validation result
 */
export const validateCreditCard = (cardNumber) => {
  // Remove spaces and dashes
  const cleaned = cardNumber.replace(/[-\s]/g, '');
  
  // Check if it's all numbers and correct length
  if (!/^\d{13,19}$/.test(cleaned)) {
    return {
      isValid: false,
      suggestions: ['Please enter a valid credit card number (13-19 digits)']
    };
  }
  
  // Luhn algorithm check
  let sum = 0;
  let shouldDouble = false;
  
  for (let i = cleaned.length - 1; i >= 0; i--) {
    let digit = parseInt(cleaned.charAt(i));
    
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) {
        digit -= 9;
      }
    }
    
    sum += digit;
    shouldDouble = !shouldDouble;
  }
  
  const isValid = sum % 10 === 0;
  
  return {
    isValid,
    suggestions: !isValid ? ['Invalid credit card number'] : []
  };
};

/**
 * Validate form field
 * @param {string} field - Field name
 * @param {string} value - Field value
 * @param {Object} rules - Validation rules
 * @returns {Object} - Validation result
 */
export const validateField = (field, value, rules = {}) => {
  const defaultRules = {
    required: false,
    minLength: 0,
    maxLength: Infinity,
    pattern: null,
    custom: null
  };
  
  const mergedRules = { ...defaultRules, ...rules };
  const errors = [];
  
  // Check required
  if (mergedRules.required && (!value || value.trim().length === 0)) {
    errors.push(`${field} is required`);
    return { isValid: false, errors };
  }
  
  // Skip further checks if value is empty and not required
  if (!value || value.trim().length === 0) {
    return { isValid: true, errors: [] };
  }
  
  // Check min length
  if (value.length < mergedRules.minLength) {
    errors.push(`${field} must be at least ${mergedRules.minLength} characters`);
  }
  
  // Check max length
  if (value.length > mergedRules.maxLength) {
    errors.push(`${field} must be at most ${mergedRules.maxLength} characters`);
  }
  
  // Check pattern
  if (mergedRules.pattern && !mergedRules.pattern.test(value)) {
    errors.push(`${field} format is invalid`);
  }
  
  // Custom validation
  if (mergedRules.custom && typeof mergedRules.custom === 'function') {
    const customResult = mergedRules.custom(value);
    if (customResult !== true) {
      errors.push(customResult);
    }
  }
  
  return {
    isValid: errors.length === 0,
    errors
  };
};

/**
 * Sanitize input for XSS protection
 * @param {string} input - Input to sanitize
 * @returns {string} - Sanitized input
 */
export const sanitizeInput = (input) => {
  if (typeof input !== 'string') return input;
  
  // Replace potentially dangerous characters
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;')
    .replace(/`/g, '&#96;')
    .replace(/=/g, '&#61;');
};

/**
 * Escape HTML entities
 * @param {string} text - Text to escape
 * @returns {string} - Escaped text
 */
export const escapeHtml = (text) => {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  
  return text.replace(/[&<>"']/g, m => map[m]);
};

/**
 * Validate JSON string
 * @param {string} jsonString - JSON string to validate
 * @returns {Object} - Validation result
 */
export const validateJson = (jsonString) => {
  try {
    JSON.parse(jsonString);
    return { isValid: true, error: null };
  } catch (error) {
    return { 
      isValid: false, 
      error: error.message 
    };
  }
};

/**
 * Validate CAPTCHA response
 * @param {string} captchaResponse - CAPTCHA response
 * @returns {Object} - Validation result
 */
export const validateCaptcha = (captchaResponse) => {
  const isValid = captchaResponse && captchaResponse.length > 0;
  
  return {
    isValid,
    suggestions: !isValid ? ['Please complete the CAPTCHA'] : []
  };
};

/**
 * Validate social security number (US)
 * @param {string} ssn - SSN to validate
 * @returns {Object} - Validation result
 */
export const validateSSN = (ssn) => {
  const cleaned = ssn.replace(/[-\s]/g, '');
  const isValid = /^\d{9}$/.test(cleaned);
  
  return {
    isValid,
    suggestions: !isValid ? ['Please enter a valid SSN (9 digits)'] : [],
    masked: isValid ? `***-**-${cleaned.slice(5)}` : ''
  };
};