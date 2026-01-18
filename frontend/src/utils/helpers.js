// Utility functions for the frontend

/**
 * Format a date string to a readable format
 * @param {string} dateString - ISO date string
 * @param {boolean} withTime - Include time in output
 * @returns {string} - Formatted date string
 */
export const formatDate = (dateString, withTime = true) => {
  if (!dateString) return 'N/A';
  
  const date = new Date(dateString);
  if (isNaN(date.getTime())) return 'Invalid Date';
  
  const options = {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  };
  
  if (withTime) {
    options.hour = '2-digit';
    options.minute = '2-digit';
  }
  
  return date.toLocaleDateString('en-US', options);
};

/**
 * Truncate a string to a specified length
 * @param {string} str - String to truncate
 * @param {number} length - Maximum length
 * @returns {string} - Truncated string
 */
export const truncateString = (str, length = 50) => {
  if (!str) return '';
  if (str.length <= length) return str;
  return str.substring(0, length) + '...';
};

/**
 * Generate a random color based on a string
 * @param {string} str - String to generate color from
 * @returns {string} - Hex color code
 */
export const stringToColor = (str) => {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = str.charCodeAt(i) + ((hash << 5) - hash);
  }
  
  let color = '#';
  for (let i = 0; i < 3; i++) {
    const value = (hash >> (i * 8)) & 0xFF;
    color += ('00' + value.toString(16)).substr(-2);
  }
  
  return color;
};

/**
 * Debounce function to limit how often a function is called
 * @param {Function} func - Function to debounce
 * @param {number} wait - Wait time in milliseconds
 * @returns {Function} - Debounced function
 */
export const debounce = (func, wait) => {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
};

/**
 * Validate email address
 * @param {string} email - Email to validate
 * @returns {boolean} - True if email is valid
 */
export const isValidEmail = (email) => {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
};

/**
 * Validate URL
 * @param {string} url - URL to validate
 * @returns {boolean} - True if URL is valid
 */
export const isValidUrl = (url) => {
  try {
    new URL(url);
    return true;
  } catch (error) {
    return false;
  }
};

/**
 * Format file size
 * @param {number} bytes - File size in bytes
 * @returns {string} - Formatted file size
 */
export const formatFileSize = (bytes) => {
  if (bytes === 0) return '0 Bytes';
  
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

/**
 * Get initials from a name
 * @param {string} name - Full name
 * @returns {string} - Initials (max 2 characters)
 */
export const getInitials = (name) => {
  if (!name) return '?';
  
  const names = name.trim().split(' ');
  if (names.length === 1) return names[0].charAt(0).toUpperCase();
  
  return (names[0].charAt(0) + names[names.length - 1].charAt(0)).toUpperCase();
};

/**
 * Copy text to clipboard
 * @param {string} text - Text to copy
 * @returns {Promise<boolean>} - True if copy was successful
 */
export const copyToClipboard = async (text) => {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (error) {
    // Fallback for older browsers
    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.style.position = 'fixed';
    textArea.style.opacity = '0';
    document.body.appendChild(textArea);
    textArea.select();
    const success = document.execCommand('copy');
    document.body.removeChild(textArea);
    return success;
  }
};

/**
 * Sanitize HTML input to prevent XSS
 * @param {string} input - Input to sanitize
 * @returns {string} - Sanitized input
 */
export const sanitizeInput = (input) => {
  if (typeof input !== 'string') return input;
  
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
};

/**
 * Generate a unique ID
 * @param {number} length - Length of the ID
 * @returns {string} - Unique ID
 */
export const generateId = (length = 8) => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
};

/**
 * Check if a value is empty
 * @param {*} value - Value to check
 * @returns {boolean} - True if value is empty
 */
export const isEmpty = (value) => {
  if (value === null || value === undefined) return true;
  if (typeof value === 'string') return value.trim().length === 0;
  if (Array.isArray(value)) return value.length === 0;
  if (typeof value === 'object') return Object.keys(value).length === 0;
  return false;
};

/**
 * Delay execution for a specified time
 * @param {number} ms - Time to delay in milliseconds
 * @returns {Promise} - Promise that resolves after delay
 */
export const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

/**
 * Parse JWT token
 * @param {string} token - JWT token
 * @returns {Object|null} - Decoded token payload or null
 */
export const parseJwt = (token) => {
  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split('')
        .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    );
    return JSON.parse(jsonPayload);
  } catch (error) {
    console.error('Failed to parse JWT:', error);
    return null;
  }
};

/**
 * Check if token is expired
 * @param {string} token - JWT token
 * @returns {boolean} - True if token is expired
 */
export const isTokenExpired = (token) => {
  const payload = parseJwt(token);
  if (!payload || !payload.exp) return true;
  
  const currentTime = Date.now() / 1000;
  return payload.exp < currentTime;
};

/**
 * Get browser information
 * @returns {Object} - Browser information
 */
export const getBrowserInfo = () => {
  const ua = navigator.userAgent;
  let browser = 'Unknown';
  let version = '';
  let os = 'Unknown';
  
  // Browser detection
  if (ua.includes('Chrome') && !ua.includes('Edg')) {
    browser = 'Chrome';
    version = ua.match(/Chrome\/(\d+)/)?.[1] || '';
  } else if (ua.includes('Firefox')) {
    browser = 'Firefox';
    version = ua.match(/Firefox\/(\d+)/)?.[1] || '';
  } else if (ua.includes('Safari') && !ua.includes('Chrome')) {
    browser = 'Safari';
    version = ua.match(/Version\/(\d+)/)?.[1] || '';
  } else if (ua.includes('Edg')) {
    browser = 'Edge';
    version = ua.match(/Edg\/(\d+)/)?.[1] || '';
  }
  
  // OS detection
  if (ua.includes('Windows')) {
    os = 'Windows';
  } else if (ua.includes('Mac')) {
    os = 'Mac OS';
  } else if (ua.includes('Linux')) {
    os = 'Linux';
  } else if (ua.includes('Android')) {
    os = 'Android';
  } else if (ua.includes('iOS')) {
    os = 'iOS';
  }
  
  // Device detection
  const device = ua.includes('Mobile') ? 'Mobile' : 
                 ua.includes('Tablet') ? 'Tablet' : 'Desktop';
  
  return { browser, version, os, device, userAgent: ua };
};

/**
 * Create a data URI from a file
 * @param {File} file - File to convert
 * @returns {Promise<string>} - Data URI
 */
export const fileToDataUri = (file) => {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = (e) => resolve(e.target.result);
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
};

/**
 * Calculate password strength score
 * @param {string} password - Password to evaluate
 * @returns {number} - Strength score (0-100)
 */
export const calculatePasswordStrength = (password) => {
  if (!password) return 0;
  
  let score = 0;
  
  // Length
  if (password.length >= 8) score += 25;
  if (password.length >= 12) score += 10;
  if (password.length >= 16) score += 10;
  
  // Character variety
  if (/[a-z]/.test(password)) score += 10;
  if (/[A-Z]/.test(password)) score += 10;
  if (/\d/.test(password)) score += 10;
  if (/[^a-zA-Z0-9]/.test(password)) score += 10;
  
  // Entropy approximation
  const charSetSize = new Set(password).size;
  const entropy = password.length * Math.log2(charSetSize);
  score += Math.min(entropy, 25);
  
  return Math.min(score, 100);
};

/**
 * Get password strength label
 * @param {number} score - Password strength score
 * @returns {Object} - Label and color
 */
export const getPasswordStrengthLabel = (score) => {
  if (score >= 80) return { label: 'Strong', color: 'success' };
  if (score >= 60) return { label: 'Good', color: 'warning' };
  if (score >= 40) return { label: 'Fair', color: 'info' };
  if (score >= 20) return { label: 'Weak', color: 'danger' };
  return { label: 'Very Weak', color: 'danger' };
};