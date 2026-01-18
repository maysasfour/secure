import CryptoJS from 'crypto-js';

// Frontend encryption utilities (for demonstration purposes only)
// Note: In production, encryption should happen on the backend
// This is for demonstrating encryption concepts in the UI

/**
 * Generate a random encryption key (for demo purposes)
 * @returns {string} - Hex encoded key
 */
export const generateDemoKey = () => {
  return CryptoJS.lib.WordArray.random(32).toString(CryptoJS.enc.Hex);
};

/**
 * Generate a random IV (for demo purposes)
 * @returns {string} - Hex encoded IV
 */
export const generateDemoIV = () => {
  return CryptoJS.lib.WordArray.random(16).toString(CryptoJS.enc.Hex);
};

/**
 * Encrypt text using AES (frontend demo)
 * @param {string} text - Text to encrypt
 * @param {string} key - Encryption key (hex)
 * @returns {Object} - Encrypted data with IV
 */
export const encryptTextDemo = (text, key) => {
  try {
    const iv = CryptoJS.lib.WordArray.random(16);
    const encrypted = CryptoJS.AES.encrypt(text, CryptoJS.enc.Hex.parse(key), {
      iv: iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7
    });
    
    return {
      encrypted: encrypted.toString(),
      iv: iv.toString(CryptoJS.enc.Hex),
      key: key
    };
  } catch (error) {
    console.error('Encryption error:', error);
    throw new Error('Failed to encrypt text');
  }
};

/**
 * Decrypt text using AES (frontend demo)
 * @param {string} encryptedText - Encrypted text
 * @param {string} key - Encryption key (hex)
 * @param {string} iv - IV (hex)
 * @returns {string} - Decrypted text
 */
export const decryptTextDemo = (encryptedText, key, iv) => {
  try {
    const decrypted = CryptoJS.AES.decrypt(encryptedText, CryptoJS.enc.Hex.parse(key), {
      iv: CryptoJS.enc.Hex.parse(iv),
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7
    });
    
    return decrypted.toString(CryptoJS.enc.Utf8);
  } catch (error) {
    console.error('Decryption error:', error);
    throw new Error('Failed to decrypt text');
  }
};

/**
 * Hash text using SHA-256 (frontend)
 * @param {string} text - Text to hash
 * @returns {string} - Hex encoded hash
 */
export const hashText = (text) => {
  return CryptoJS.SHA256(text).toString(CryptoJS.enc.Hex);
};

/**
 * Generate a password hash with salt (for demo)
 * @param {string} password - Password to hash
 * @param {string} salt - Salt
 * @returns {string} - Hex encoded hash
 */
export const hashPasswordDemo = (password, salt) => {
  const iterations = 1000;
  const keySize = 256 / 32;
  
  const key = CryptoJS.PBKDF2(password, salt, {
    keySize: keySize,
    iterations: iterations
  });
  
  return key.toString(CryptoJS.enc.Hex);
};

/**
 * Generate a salt for password hashing
 * @returns {string} - Hex encoded salt
 */
export const generateSalt = () => {
  return CryptoJS.lib.WordArray.random(16).toString(CryptoJS.enc.Hex);
};

/**
 * Create HMAC signature
 * @param {string} data - Data to sign
 * @param {string} secret - Secret key
 * @returns {string} - Hex encoded HMAC
 */
export const createHmac = (data, secret) => {
  return CryptoJS.HmacSHA256(data, secret).toString(CryptoJS.enc.Hex);
};

/**
 * Base64 encode
 * @param {string} text - Text to encode
 * @returns {string} - Base64 encoded string
 */
export const base64Encode = (text) => {
  return CryptoJS.enc.Base64.stringify(CryptoJS.enc.Utf8.parse(text));
};

/**
 * Base64 decode
 * @param {string} base64 - Base64 string
 * @returns {string} - Decoded text
 */
export const base64Decode = (base64) => {
  return CryptoJS.enc.Base64.parse(base64).toString(CryptoJS.enc.Utf8);
};

/**
 * Generate a secure random string
 * @param {number} length - Length of string
 * @returns {string} - Random string
 */
export const generateRandomString = (length = 32) => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
  let result = '';
  const randomValues = new Uint8Array(length);
  crypto.getRandomValues(randomValues);
  
  for (let i = 0; i < length; i++) {
    result += chars[randomValues[i] % chars.length];
  }
  
  return result;
};

/**
 * Mask sensitive data (for display)
 * @param {string} data - Data to mask
 * @param {number} visibleChars - Number of visible characters at start and end
 * @returns {string} - Masked data
 */
export const maskSensitiveData = (data, visibleChars = 4) => {
  if (!data || data.length <= visibleChars * 2) {
    return '*'.repeat(data?.length || 0);
  }
  
  const start = data.substring(0, visibleChars);
  const end = data.substring(data.length - visibleChars);
  const middle = '*'.repeat(data.length - visibleChars * 2);
  
  return start + middle + end;
};

/**
 * Check if text looks like encrypted data
 * @param {string} text - Text to check
 * @returns {boolean} - True if likely encrypted
 */
export const looksLikeEncrypted = (text) => {
  if (!text) return false;
  
  // Check for common encryption patterns
  const base64Regex = /^[A-Za-z0-9+/]+={0,2}$/;
  const hexRegex = /^[0-9a-fA-F]+$/;
  
  // If it's valid base64 or hex and reasonably long, assume encrypted
  return (base64Regex.test(text) || hexRegex.test(text)) && text.length >= 32;
};

/**
 * Simple XOR encryption (for very basic demo, NOT secure)
 * @param {string} text - Text to encrypt
 * @param {string} key - Encryption key
 * @returns {string} - Encrypted text
 */
export const xorEncrypt = (text, key) => {
  let result = '';
  for (let i = 0; i < text.length; i++) {
    const charCode = text.charCodeAt(i) ^ key.charCodeAt(i % key.length);
    result += String.fromCharCode(charCode);
  }
  return btoa(result);
};

/**
 * Simple XOR decryption (for very basic demo, NOT secure)
 * @param {string} encryptedText - Encrypted text
 * @param {string} key - Encryption key
 * @returns {string} - Decrypted text
 */
export const xorDecrypt = (encryptedText, key) => {
  const decoded = atob(encryptedText);
  let result = '';
  for (let i = 0; i < decoded.length; i++) {
    const charCode = decoded.charCodeAt(i) ^ key.charCodeAt(i % key.length);
    result += String.fromCharCode(charCode);
  }
  return result;
};