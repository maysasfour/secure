const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const logger = require('./logger');

class TokenService {
  constructor() {
    this.accessTokenSecret = process.env.JWT_SECRET;
    this.refreshTokenSecret = process.env.JWT_REFRESH_SECRET;
    this.accessTokenExpiry = process.env.JWT_EXPIRE || '15m';
    this.refreshTokenExpiry = process.env.JWT_REFRESH_EXPIRE || '7d';
    
    this.validateSecrets();
  }

  validateSecrets() {
    if (!this.accessTokenSecret || this.accessTokenSecret.length < 32) {
      throw new Error('JWT_SECRET must be at least 32 characters long');
    }
    
    if (!this.refreshTokenSecret || this.refreshTokenSecret.length < 32) {
      throw new Error('JWT_REFRESH_SECRET must be at least 32 characters long');
    }
    
    if (this.accessTokenSecret === this.refreshTokenSecret) {
      throw new Error('JWT_SECRET and JWT_REFRESH_SECRET must be different');
    }
    
    logger.info('✅ JWT secrets validated successfully');
  }

  /**
   * Generate access token
   * @param {string} userId - User ID
   * @param {string} role - User role
   * @returns {string} - JWT access token
   */
  generateAccessToken(userId, role) {
    const payload = {
      sub: userId,
      role: role,
      type: 'access',
      iat: Math.floor(Date.now() / 1000),
      iss: 'secure-campus-portal',
      aud: 'web-client'
    };

    return jwt.sign(payload, this.accessTokenSecret, {
      expiresIn: this.accessTokenExpiry,
      algorithm: 'HS256'
    });
  }

  /**
   * Generate refresh token
   * @param {string} userId - User ID
   * @returns {string} - JWT refresh token
   */
  generateRefreshToken(userId) {
    const payload = {
      sub: userId,
      type: 'refresh',
      iat: Math.floor(Date.now() / 1000),
      iss: 'secure-campus-portal',
      aud: 'web-client'
    };

    return jwt.sign(payload, this.refreshTokenSecret, {
      expiresIn: this.refreshTokenExpiry,
      algorithm: 'HS256'
    });
  }

  /**
   * Generate both tokens
   * @param {string} userId - User ID
   * @param {string} role - User role
   * @returns {Object} - Access and refresh tokens
   */
  generateTokens(userId, role) {
    return {
      accessToken: this.generateAccessToken(userId, role),
      refreshToken: this.generateRefreshToken(userId)
    };
  }

  /**
   * Verify access token
   * @param {string} token - JWT token
   * @returns {Object} - Decoded payload
   */
  verifyAccessToken(token) {
    try {
      return jwt.verify(token, this.accessTokenSecret, {
        algorithms: ['HS256'],
        issuer: 'secure-campus-portal',
        audience: 'web-client'
      });
    } catch (error) {
      logger.warn('Access token verification failed:', error.message);
      throw error;
    }
  }

  /**
   * Verify refresh token
   * @param {string} token - JWT token
   * @returns {Object} - Decoded payload
   */
  verifyRefreshToken(token) {
    try {
      return jwt.verify(token, this.refreshTokenSecret, {
        algorithms: ['HS256'],
        issuer: 'secure-campus-portal',
        audience: 'web-client'
      });
    } catch (error) {
      logger.warn('Refresh token verification failed:', error.message);
      throw error;
    }
  }

  /**
   * Decode token without verification
   * @param {string} token - JWT token
   * @returns {Object} - Decoded payload
   */
  decodeToken(token) {
    try {
      return jwt.decode(token);
    } catch (error) {
      logger.error('Token decoding failed:', error);
      return null;
    }
  }

  /**
   * Check if token is expired
   * @param {string} token - JWT token
   * @returns {boolean} - True if expired
   */
  isTokenExpired(token) {
    try {
      const decoded = this.decodeToken(token);
      if (!decoded || !decoded.exp) return true;
      
      const currentTime = Math.floor(Date.now() / 1000);
      return decoded.exp < currentTime;
    } catch (error) {
      return true;
    }
  }

  /**
   * Get token expiry time
   * @param {string} token - JWT token
   * @returns {Date|null} - Expiry date
   */
  getTokenExpiry(token) {
    try {
      const decoded = this.decodeToken(token);
      if (!decoded || !decoded.exp) return null;
      
      return new Date(decoded.exp * 1000);
    } catch (error) {
      return null;
    }
  }

  /**
   * Generate random token (for password reset, email verification)
   * @param {number} length - Token length in bytes
   * @returns {Object} - Token and hashed token
   */
  generateRandomToken(length = 32) {
    const token = crypto.randomBytes(length).toString('hex');
    const hashedToken = crypto
      .createHash('sha256')
      .update(token)
      .digest('hex');
    
    return {
      token,
      hashedToken
    };
  }

  /**
   * Verify random token
   * @param {string} token - Plain token
   * @param {string} hashedToken - Hashed token
   * @returns {boolean} - True if valid
   */
  verifyRandomToken(token, hashedToken) {
    const computedHash = crypto
      .createHash('sha256')
      .update(token)
      .digest('hex');
    
    return crypto.timingSafeEqual(
      Buffer.from(computedHash, 'hex'),
      Buffer.from(hashedToken, 'hex')
    );
  }

  /**
   * Generate API key
   * @param {string} userId - User ID
   * @param {Array} permissions - Permissions array
   * @returns {Object} - API key and hashed key
   */
  generateApiKey(userId, permissions = []) {
    const apiKey = `sk_${crypto.randomBytes(32).toString('hex')}`;
    const hashedKey = crypto
      .createHash('sha256')
      .update(apiKey)
      .digest('hex');
    
    const payload = {
      sub: userId,
      permissions: permissions,
      type: 'api_key',
      iat: Math.floor(Date.now() / 1000)
    };
    
    const token = jwt.sign(payload, this.accessTokenSecret, {
      expiresIn: '365d',
      algorithm: 'HS256'
    });
    
    return {
      apiKey,
      hashedKey,
      token
    };
  }

  /**
   * Blacklist token (for logout, password change)
   * @param {string} token - Token to blacklist
   * @param {number} expirySeconds - Expiry time in seconds
   * @returns {string} - Blacklist key
   */
  async blacklistToken(token, expirySeconds = 3600) {
    const tokenHash = crypto
      .createHash('sha256')
      .update(token)
      .digest('hex');
    
    // In production, you would store this in Redis
    // For now, we'll just return the hash
    const blacklistKey = `blacklist:${tokenHash}`;
    
    logger.info(`Token blacklisted: ${blacklistKey}`);
    return blacklistKey;
  }

  /**
   * Check if token is blacklisted
   * @param {string} token - Token to check
   * @returns {boolean} - True if blacklisted
   */
  async isTokenBlacklisted(token) {
    const tokenHash = crypto
      .createHash('sha256')
      .update(token)
      .digest('hex');
    
    const blacklistKey = `blacklist:${tokenHash}`;
    
    // In production, check Redis
    // For now, return false
    return false;
  }

  /**
   * Get token information
   * @param {string} token - JWT token
   * @returns {Object} - Token information
   */
  getTokenInfo(token) {
    try {
      const decoded = this.decodeToken(token);
      if (!decoded) {
        return { valid: false, error: 'Invalid token' };
      }
      
      const isExpired = this.isTokenExpired(token);
      const expiryDate = this.getTokenExpiry(token);
      
      return {
        valid: !isExpired,
        expired: isExpired,
        type: decoded.type || 'unknown',
        userId: decoded.sub,
        role: decoded.role,
        issuedAt: decoded.iat ? new Date(decoded.iat * 1000) : null,
        expiresAt: expiryDate,
        issuer: decoded.iss,
        audience: decoded.aud,
        algorithm: decoded.alg,
        payload: decoded
      };
    } catch (error) {
      return { valid: false, error: error.message };
    }
  }
}

// Create singleton instance
const tokenService = new TokenService();

// Export individual functions for convenience
const generateToken = (userId, role) => tokenService.generateAccessToken(userId, role);
const generateRefreshToken = (userId) => tokenService.generateRefreshToken(userId);
const verifyToken = (token) => tokenService.verifyAccessToken(token);
const decodeToken = (token) => tokenService.decodeToken(token);
const isTokenExpired = (token) => tokenService.isTokenExpired(token);

module.exports = {
  tokenService,
  generateToken,
  generateRefreshToken,
  verifyToken,
  decodeToken,
  isTokenExpired
};