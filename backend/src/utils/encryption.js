const crypto = require('crypto');
const logger = require('./logger');

class EncryptionService {
  constructor() {
    // Validate encryption key from environment
    this.encryptionKey = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
    this.ivKey = Buffer.from(process.env.IV_KEY, 'hex');
    
    if (!this.encryptionKey || this.encryptionKey.length !== 32) {
      throw new Error('ENCRYPTION_KEY must be a 32-byte (64-character) hex string');
    }
    
    if (!this.ivKey || this.ivKey.length !== 16) {
      throw new Error('IV_KEY must be a 16-byte (32-character) hex string');
    }
    
    this.algorithm = 'aes-256-gcm';
    this.key = this.encryptionKey;
    this.ivLength = 16;
    this.authTagLength = 16;
    
    logger.info('✅ Encryption service initialized with AES-256-GCM');
  }

  /**
   * Encrypt data using AES-256-GCM
   * @param {string|Buffer} data - Data to encrypt
   * @returns {Object} - Encrypted data with metadata
   */
  encrypt(data) {
    try {
      // Convert string to buffer if needed
      const dataBuffer = Buffer.isBuffer(data) ? data : Buffer.from(String(data), 'utf8');
      
      // Generate random IV
      const iv = crypto.randomBytes(this.ivLength);
      
      // Create cipher
      const cipher = crypto.createCipheriv(this.algorithm, this.key, iv);
      
      // Encrypt the data
      let encrypted = cipher.update(dataBuffer);
      encrypted = Buffer.concat([encrypted, cipher.final()]);
      
      // Get authentication tag
      const authTag = cipher.getAuthTag();
      
      // Combine IV, auth tag, and encrypted data
      const result = Buffer.concat([iv, authTag, encrypted]);
      
      return {
        encrypted: result.toString('base64'),
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex'),
        algorithm: this.algorithm,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      logger.error('Encryption failed:', error);
      throw new Error(`Encryption failed: ${error.message}`);
    }
  }

  /**
   * Decrypt data using AES-256-GCM
   * @param {string} encryptedData - Base64 encoded encrypted data
   * @returns {string} - Decrypted data
   */
  decrypt(encryptedData) {
    try {
      // Convert from base64
      const encryptedBuffer = Buffer.from(encryptedData, 'base64');
      
      // Extract IV (first 16 bytes)
      const iv = encryptedBuffer.slice(0, this.ivLength);
      
      // Extract auth tag (next 16 bytes)
      const authTag = encryptedBuffer.slice(this.ivLength, this.ivLength + this.authTagLength);
      
      // Extract encrypted text (remaining bytes)
      const encryptedText = encryptedBuffer.slice(this.ivLength + this.authTagLength);
      
      // Create decipher
      const decipher = crypto.createDecipheriv(this.algorithm, this.key, iv);
      decipher.setAuthTag(authTag);
      
      // Decrypt the text
      let decrypted = decipher.update(encryptedText);
      decrypted = Buffer.concat([decrypted, decipher.final()]);
      
      return decrypted.toString('utf8');
    } catch (error) {
      logger.error('Decryption failed:', error);
      
      if (error.message.includes('Unsupported state or unable to authenticate data')) {
        throw new Error('Invalid encryption data or tampering detected');
      }
      throw new Error(`Decryption failed: ${error.message}`);
    }
  }

  /**
   * Encrypt sensitive fields in an object
   * @param {Object} data - Object containing sensitive data
   * @param {Array} fields - Fields to encrypt
   * @returns {Object} - Object with encrypted fields
   */
  encryptSensitiveFields(data, fields) {
    const result = { ...data };
    
    fields.forEach(field => {
      if (result[field] && typeof result[field] === 'string') {
        const encrypted = this.encrypt(result[field]);
        result[field] = encrypted.encrypted;
        result[`${field}_iv`] = encrypted.iv;
        result[`${field}_authTag`] = encrypted.authTag;
      }
    });
    
    return result;
  }

  /**
   * Decrypt sensitive fields in an object
   * @param {Object} data - Object with encrypted fields
   * @param {Array} fields - Fields to decrypt
   * @returns {Object} - Object with decrypted fields
   */
  decryptSensitiveFields(data, fields) {
    const result = { ...data };
    
    fields.forEach(field => {
      if (result[field] && result[`${field}_iv`] && result[`${field}_authTag`]) {
        try {
          // Reconstruct the encrypted data format
          const iv = Buffer.from(result[`${field}_iv`], 'hex');
          const authTag = Buffer.from(result[`${field}_authTag`], 'hex');
          const encryptedText = Buffer.from(result[field], 'base64');
          
          const encryptedBuffer = Buffer.concat([iv, authTag, encryptedText]);
          const decrypted = this.decrypt(encryptedBuffer.toString('base64'));
          
          result[field] = decrypted;
          
          // Remove the helper fields
          delete result[`${field}_iv`];
          delete result[`${field}_authTag`];
        } catch (error) {
          logger.warn(`Failed to decrypt field ${field}:`, error.message);
          result[field] = '[ENCRYPTION_ERROR]';
        }
      }
    });
    
    return result;
  }

  /**
   * Hash data using SHA-256
   * @param {string} data - Data to hash
   * @returns {string} - Hex encoded hash
   */
  hash(data) {
    return crypto
      .createHash('sha256')
      .update(data)
      .digest('hex');
  }

  /**
   * Generate secure random string
   * @param {number} length - Length of the random string
   * @returns {string} - Random string
   */
  generateRandomString(length = 32) {
    return crypto
      .randomBytes(Math.ceil(length / 2))
      .toString('hex')
      .slice(0, length);
  }

  /**
   * Generate secure token
   * @param {number} bytes - Number of bytes
   * @returns {string} - Hex encoded token
   */
  generateToken(bytes = 32) {
    return crypto.randomBytes(bytes).toString('hex');
  }

  /**
   * Create HMAC signature
   * @param {string} data - Data to sign
   * @param {string} secret - Secret key
   * @returns {string} - Hex encoded HMAC
   */
  createHmac(data, secret) {
    return crypto
      .createHmac('sha256', secret)
      .update(data)
      .digest('hex');
  }

  /**
   * Verify HMAC signature
   * @param {string} data - Original data
   * @param {string} signature - Received signature
   * @param {string} secret - Secret key
   * @returns {boolean} - True if signature is valid
   */
  verifyHmac(data, signature, secret) {
    const expectedSignature = this.createHmac(data, secret);
    return crypto.timingSafeEqual(
      Buffer.from(expectedSignature, 'hex'),
      Buffer.from(signature, 'hex')
    );
  }

  /**
   * Generate salt for password hashing
   * @param {number} length - Salt length in bytes
   * @returns {string} - Hex encoded salt
   */
  generateSalt(length = 16) {
    return crypto.randomBytes(length).toString('hex');
  }

  /**
   * Create password hash with salt
   * @param {string} password - Plain text password
   * @param {string} salt - Salt
   * @returns {string} - Hex encoded hash
   */
  hashPassword(password, salt) {
    return crypto
      .pbkdf2Sync(password, salt, 100000, 64, 'sha512')
      .toString('hex');
  }

  /**
   * Verify password against hash
   * @param {string} password - Plain text password
   * @param {string} hash - Stored hash
   * @param {string} salt - Salt used for hash
   * @returns {boolean} - True if password matches
   */
  verifyPassword(password, hash, salt) {
    const passwordHash = this.hashPassword(password, salt);
    return crypto.timingSafeEqual(
      Buffer.from(passwordHash, 'hex'),
      Buffer.from(hash, 'hex')
    );
  }

  /**
   * Generate key pair for asymmetric encryption
   * @returns {Object} - Public and private keys
   */
  generateKeyPair() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
      }
    });
    
    return { publicKey, privateKey };
  }

  /**
   * Test encryption/decryption functionality
   * @returns {Object} - Test results
   */
  testEncryption() {
    const testData = {
      message: 'Test encryption functionality',
      timestamp: new Date().toISOString(),
      random: this.generateRandomString(16)
    };
    
    const testString = JSON.stringify(testData);
    
    try {
      // Encrypt
      const encrypted = this.encrypt(testString);
      
      // Decrypt
      const decrypted = this.decrypt(encrypted.encrypted);
      
      // Verify
      const success = testString === decrypted;
      
      return {
        success,
        algorithm: this.algorithm,
        keyLength: 256,
        testData,
        encrypted: {
          length: encrypted.encrypted.length,
          iv: encrypted.iv,
          authTag: encrypted.authTag
        },
        decrypted: JSON.parse(decrypted),
        message: success ? 'Encryption/Decryption test passed' : 'Test failed'
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
        message: 'Encryption/Decryption test failed'
      };
    }
  }

  /**
   * Get encryption service status
   * @returns {Object} - Service status
   */
  getStatus() {
    return {
      algorithm: this.algorithm,
      keyConfigured: !!this.key,
      keyLength: this.key ? this.key.length * 8 : 0,
      ivLength: this.ivLength,
      testResult: this.testEncryption()
    };
  }
}

// Create singleton instance with your encryption key
const encryptionService = new EncryptionService();

// Export individual functions
const encryptData = (text) => encryptionService.encrypt(text).encrypted;
const decryptData = (encryptedText) => encryptionService.decrypt(encryptedText);
const hashData = (data) => encryptionService.hash(data);
const generateToken = (bytes) => encryptionService.generateToken(bytes);

module.exports = {
  encryptionService,
  encryptData,
  decryptData,
  hashData,
  generateToken
};