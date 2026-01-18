const crypto = require('crypto');
const validator = require('validator');
const constants = require('../config/constants');
const logger = require('./logger');

class SecurityUtils {
  /**
   * Validate password strength
   * @param {string} password - Password to validate
   * @returns {Object} - Validation result
   */
  validatePassword(password) {
    const requirements = {
      minLength: constants.SECURITY.PASSWORD_MIN_LENGTH,
      hasUpperCase: /[A-Z]/.test(password),
      hasLowerCase: /[a-z]/.test(password),
      hasNumbers: /\d/.test(password),
      hasSpecialChar: /[!@#$%^&*(),.?":{}|<>]/.test(password),
      noSpaces: !/\s/.test(password),
      noCommonPatterns: !this.isCommonPassword(password)
    };

    const isValid = Object.values(requirements).every(req => req === true);
    const score = this.calculatePasswordStrength(password);

    return {
      isValid,
      score,
      requirements,
      suggestions: !isValid ? this.getPasswordSuggestions(requirements) : []
    };
  }

  /**
   * Calculate password strength score (0-100)
   * @param {string} password - Password to score
   * @returns {number} - Strength score
   */
  calculatePasswordStrength(password) {
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
    
    // Entropy calculation
    const charSetSize = this.getCharacterSetSize(password);
    const entropy = password.length * Math.log2(charSetSize);
    score += Math.min(entropy / 2, 20); // Max 20 points for entropy
    
    return Math.min(Math.round(score), 100);
  }

  /**
   * Get character set size used in password
   * @param {string} password - Password to analyze
   * @returns {number} - Character set size
   */
  getCharacterSetSize(password) {
    let size = 0;
    if (/[a-z]/.test(password)) size += 26;
    if (/[A-Z]/.test(password)) size += 26;
    if (/\d/.test(password)) size += 10;
    if (/[^a-zA-Z0-9]/.test(password)) size += 32; // Approximate for special chars
    
    return size;
  }

  /**
   * Check if password is in common password list
   * @param {string} password - Password to check
   * @returns {boolean} - True if password is common
   */
  isCommonPassword(password) {
    const commonPasswords = [
      'password', '123456', '12345678', '123456789', '12345',
      'qwerty', 'abc123', 'password1', 'admin', 'letmein',
      'welcome', 'monkey', 'login', 'passw0rd', 'master'
    ];
    
    return commonPasswords.includes(password.toLowerCase());
  }

  /**
   * Get password improvement suggestions
   * @param {Object} requirements - Failed requirements
   * @returns {Array} - List of suggestions
   */
  getPasswordSuggestions(requirements) {
    const suggestions = [];
    
    if (!requirements.minLength) {
      suggestions.push(`Password must be at least ${constants.SECURITY.PASSWORD_MIN_LENGTH} characters long`);
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
      suggestions.push('Add at least one special character');
    }
    if (!requirements.noSpaces) {
      suggestions.push('Remove spaces from password');
    }
    if (!requirements.noCommonPatterns) {
      suggestions.push('Avoid common passwords and patterns');
    }
    
    return suggestions;
  }

  /**
   * Sanitize user input
   * @param {string} input - Input to sanitize
   * @returns {string} - Sanitized input
   */
  sanitizeInput(input) {
    if (typeof input !== 'string') return input;
    
    let sanitized = input;
    
    // Remove null bytes
    sanitized = sanitized.replace(/\0/g, '');
    
    // Remove control characters
    sanitized = sanitized.replace(/[\x00-\x1F\x7F]/g, '');
    
    // Trim whitespace
    sanitized = sanitized.trim();
    
    // Escape HTML
    sanitized = validator.escape(sanitized);
    
    // Remove potential SQL injection patterns
    const sqlPatterns = [
      /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|EXEC|ALTER|CREATE)\b)/gi,
      /(\-\-)/g,
      /(\/\*)/g,
      /(\*\/)/g,
      /(;)/g
    ];
    
    sqlPatterns.forEach(pattern => {
      sanitized = sanitized.replace(pattern, '');
    });
    
    return sanitized;
  }

  /**
   * Validate email address
   * @param {string} email - Email to validate
   * @returns {Object} - Validation result
   */
  validateEmail(email) {
    const isValid = validator.isEmail(email);
    const normalized = isValid ? validator.normalizeEmail(email) : null;
    
    // Additional checks for disposable emails
    const isDisposable = this.isDisposableEmail(email);
    
    return {
      isValid,
      normalized,
      isDisposable,
      suggestions: isDisposable ? ['Consider using a permanent email address'] : []
    };
  }

  /**
   * Check if email is from disposable email service
   * @param {string} email - Email to check
   * @returns {boolean} - True if disposable
   */
  isDisposableEmail(email) {
    const disposableDomains = [
      'tempmail.com', 'guerrillamail.com', 'mailinator.com',
      'throwawaymail.com', 'yopmail.com', '10minutemail.com'
    ];
    
    const domain = email.split('@')[1];
    return disposableDomains.some(d => domain.includes(d));
  }

  /**
   * Generate secure random number
   * @param {number} min - Minimum value
   * @param {number} max - Maximum value
   * @returns {number} - Random number
   */
  secureRandom(min, max) {
    const range = max - min + 1;
    const bytesNeeded = Math.ceil(Math.log2(range) / 8);
    const maxValidRange = Math.pow(2, bytesNeeded * 8);
    
    let randomValue;
    do {
      const randomBytes = crypto.randomBytes(bytesNeeded);
      randomValue = randomBytes.readUIntBE(0, bytesNeeded);
    } while (randomValue >= maxValidRange - (maxValidRange % range));
    
    return min + (randomValue % range);
  }

  /**
   * Generate CAPTCHA code
   * @param {number} length - Code length
   * @returns {Object} - CAPTCHA data
   */
  generateCaptcha(length = 6) {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Avoid confusing characters
    let code = '';
    
    for (let i = 0; i < length; i++) {
      const randomIndex = this.secureRandom(0, chars.length - 1);
      code += chars[randomIndex];
    }
    
    // Create hash for verification
    const hash = crypto
      .createHash('sha256')
      .update(code.toLowerCase() + process.env.CAPTCHA_SECRET)
      .digest('hex');
    
    return {
      code,
      hash,
      expiresAt: Date.now() + (10 * 60 * 1000) // 10 minutes
    };
  }

  /**
   * Verify CAPTCHA code
   * @param {string} code - User input
   * @param {string} hash - Stored hash
   * @returns {boolean} - True if valid
   */
  verifyCaptcha(code, hash) {
    const expectedHash = crypto
      .createHash('sha256')
      .update(code.toLowerCase() + process.env.CAPTCHA_SECRET)
      .digest('hex');
    
    return crypto.timingSafeEqual(
      Buffer.from(expectedHash, 'hex'),
      Buffer.from(hash, 'hex')
    );
  }

  /**
   * Check IP address reputation
   * @param {string} ip - IP address
   * @returns {Object} - Reputation data
   */
  async checkIPReputation(ip) {
    // In production, this would call a service like AbuseIPDB
    // For now, implement basic checks
    
    const isPrivate = this.isPrivateIP(ip);
    const isLoopback = ip === '127.0.0.1' || ip === '::1';
    
    // Simple rate limiting check (would be more sophisticated in production)
    const recentRequests = await this.getRecentRequests(ip);
    const requestCount = recentRequests.length;
    
    return {
      ip,
      isPrivate,
      isLoopback,
      requestCount,
      riskLevel: this.calculateRiskLevel(requestCount, isPrivate),
      suggestions: []
    };
  }

  /**
   * Check if IP is private
   * @param {string} ip - IP address
   * @returns {boolean} - True if private
   */
  isPrivateIP(ip) {
    const privateRanges = [
      /^10\./, // 10.0.0.0 - 10.255.255.255
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./, // 172.16.0.0 - 172.31.255.255
      /^192\.168\./, // 192.168.0.0 - 192.168.255.255
      /^127\./, // 127.0.0.0 - 127.255.255.255
      /^::1$/, // IPv6 localhost
      /^fc00:/, // IPv6 private
      /^fe80:/ // IPv6 link-local
    ];
    
    return privateRanges.some(range => range.test(ip));
  }

  /**
   * Calculate risk level based on request count
   * @param {number} requestCount - Number of requests
   * @param {boolean} isPrivate - Is private IP
   * @returns {string} - Risk level
   */
  calculateRiskLevel(requestCount, isPrivate) {
    if (isPrivate) return 'low';
    
    if (requestCount > 1000) return 'critical';
    if (requestCount > 500) return 'high';
    if (requestCount > 100) return 'medium';
    if (requestCount > 50) return 'low';
    
    return 'very-low';
  }

  /**
   * Get recent requests for IP (mock implementation)
   * @param {string} ip - IP address
   * @returns {Array} - Recent requests
   */
  async getRecentRequests(ip) {
    // In production, this would query a database
    // For now, return empty array
    return [];
  }

  /**
   * Generate secure session ID
   * @returns {string} - Session ID
   */
  generateSessionId() {
    return crypto.randomBytes(32).toString('hex');
  }

  /**
   * Create CSRF token
   * @param {string} sessionId - Session ID
   * @returns {string} - CSRF token
   */
  createCsrfToken(sessionId) {
    const timestamp = Date.now();
    const data = `${sessionId}:${timestamp}:${process.env.CSRF_SECRET}`;
    
    return crypto
      .createHash('sha256')
      .update(data)
      .digest('hex');
  }

  /**
   * Verify CSRF token
   * @param {string} token - Token to verify
   * @param {string} sessionId - Session ID
   * @param {number} maxAge - Maximum age in milliseconds
   * @returns {boolean} - True if valid
   */
  verifyCsrfToken(token, sessionId, maxAge = 3600000) {
    // Generate tokens for last hour
    const now = Date.now();
    
    for (let i = 0; i <= maxAge; i += 60000) { // Check every minute
      const timestamp = now - i;
      const data = `${sessionId}:${timestamp}:${process.env.CSRF_SECRET}`;
      const expectedToken = crypto
        .createHash('sha256')
        .update(data)
        .digest('hex');
      
      if (crypto.timingSafeEqual(
        Buffer.from(expectedToken, 'hex'),
        Buffer.from(token, 'hex')
      )) {
        return true;
      }
    }
    
    return false;
  }

  /**
   * Validate file upload
   * @param {Object} file - File object
   * @returns {Object} - Validation result
   */
  validateFileUpload(file) {
    const maxSize = constants.FILE.MAX_SIZE;
    const allowedTypes = constants.FILE.ALLOWED_TYPES;
    
    const validation = {
      isValid: true,
      errors: [],
      warnings: []
    };
    
    // Check file size
    if (file.size > maxSize) {
      validation.isValid = false;
      validation.errors.push(`File size exceeds limit of ${maxSize / 1024 / 1024}MB`);
    }
    
    // Check file type
    if (!allowedTypes.includes(file.mimetype)) {
      validation.isValid = false;
      validation.errors.push(`File type not allowed. Allowed: ${allowedTypes.join(', ')}`);
    }
    
    // Check file extension
    const extension = file.originalname.split('.').pop().toLowerCase();
    const dangerousExtensions = ['exe', 'bat', 'sh', 'php', 'js', 'py'];
    
    if (dangerousExtensions.includes(extension)) {
      validation.warnings.push('File extension may be dangerous');
    }
    
    // Check for double extensions
    if (file.originalname.split('.').length > 2) {
      validation.warnings.push('File has multiple extensions');
    }
    
    // Check filename for suspicious patterns
    const suspiciousPatterns = [
      /\.\.\//, // Path traversal
      /\/etc\//,
      /\/bin\//,
      /cmd\.exe/i,
      /powershell/i
    ];
    
    suspiciousPatterns.forEach(pattern => {
      if (pattern.test(file.originalname)) {
        validation.isValid = false;
        validation.errors.push('Suspicious filename detected');
      }
    });
    
    return validation;
  }
}

// Create singleton instance
const securityUtils = new SecurityUtils();

module.exports = securityUtils;