const {RecaptchaEnterpriseServiceClient} = require('@google-cloud/recaptcha-enterprise');
const logger = require('../utils/logger');

class RecaptchaService {
  constructor() {
    // Your Google Cloud Project ID
    this.projectId = process.env.GOOGLE_CLOUD_PROJECT_ID || 'secret-timing-397615';
    
    // Your reCAPTCHA Enterprise site key
    this.recaptchaKey = process.env.RECAPTCHA_SITE_KEY || '6LfPqE4sAAAAACBKer-6qKwg5xFXSRDtDRSyjdSp';
    
    // Initialize the client (will use application default credentials)
    this.client = new RecaptchaEnterpriseServiceClient();
  }

  /**
   * Create an assessment to analyze the risk of a UI action
   * @param {Object} params - Assessment parameters
   * @param {string} params.token - The generated token from the client
   * @param {string} params.action - Action name corresponding to the token
   * @param {string} params.ipAddress - User's IP address (optional)
   * @returns {Promise<Object>} - Assessment result
   */
  async createAssessment({ token, action, ipAddress = null }) {
    try {
      if (!token || !action) {
        throw new Error('Token and action are required for reCAPTCHA assessment');
      }

      const projectPath = this.client.projectPath(this.projectId);

      // Build the assessment request
      const request = {
        assessment: {
          event: {
            token: token,
            siteKey: this.recaptchaKey,
            expectedAction: action,
            userIpAddress: ipAddress || undefined
          },
        },
        parent: projectPath,
      };

      const [response] = await this.client.createAssessment(request);

      // Check if the token is valid
      if (!response.tokenProperties || !response.tokenProperties.valid) {
        const reason = response.tokenProperties?.invalidReason || 'UNKNOWN';
        logger.warn(`reCAPTCHA token invalid: ${reason}`, {
          action,
          ipAddress,
          invalidReason: reason
        });
        
        return {
          valid: false,
          score: 0,
          reasons: [reason],
          assessmentId: response.name
        };
      }

      // Check if the expected action was executed
      if (response.tokenProperties.action !== action) {
        logger.warn(`reCAPTCHA action mismatch: expected ${action}, got ${response.tokenProperties.action}`, {
          expected: action,
          actual: response.tokenProperties.action,
          ipAddress
        });
        
        return {
          valid: false,
          score: 0,
          reasons: ['ACTION_MISMATCH'],
          assessmentId: response.name
        };
      }

      // Get the risk score and reasons
      const score = response.riskAnalysis?.score || 0;
      const reasons = response.riskAnalysis?.reasons || [];
      const isLegitimate = response.riskAnalysis?.extendedVerdictReasons?.includes('PASSED_TWO_FACTOR') || false;

      // Log the assessment
      logger.info(`reCAPTCHA assessment completed`, {
        action,
        score,
        reasons,
        valid: true,
        assessmentId: response.name,
        ipAddress
      });

      return {
        valid: true,
        score,
        reasons,
        isLegitimate,
        assessmentId: response.name,
        tokenProperties: {
          hostname: response.tokenProperties.hostname,
          action: response.tokenProperties.action,
          createTime: response.tokenProperties.createTime
        }
      };
    } catch (error) {
      logger.error('reCAPTCHA assessment failed:', error);
      
      // Return a safe default in case of error
      return {
        valid: false,
        score: 0,
        reasons: ['ASSESSMENT_ERROR'],
        error: error.message
      };
    }
  }

  /**
   * Verify reCAPTCHA token for a specific action with threshold
   * @param {string} token - reCAPTCHA token from client
   * @param {string} action - Expected action name
   * @param {Object} options - Verification options
   * @returns {Promise<Object>} - Verification result
   */
  async verifyToken(token, action, options = {}) {
    const {
      threshold = 0.5,
      ipAddress = null,
      requireLegitimateUser = false
    } = options;

    const assessment = await this.createAssessment({
      token,
      action,
      ipAddress
    });

    if (!assessment.valid) {
      return {
        success: false,
        score: 0,
        passed: false,
        reasons: assessment.reasons,
        error: 'Invalid reCAPTCHA token'
      };
    }

    const passedThreshold = assessment.score >= threshold;
    const passedLegitimate = requireLegitimateUser ? assessment.isLegitimate : true;
    const passed = passedThreshold && passedLegitimate;

    return {
      success: true,
      score: assessment.score,
      passed,
      reasons: assessment.reasons,
      threshold,
      assessmentId: assessment.assessmentId,
      details: {
        isLegitimate: assessment.isLegitimate,
        tokenProperties: assessment.tokenProperties,
        scoreCategory: this.getScoreCategory(assessment.score)
      }
    };
  }

  /**
   * Get category for score
   * @param {number} score - reCAPTCHA score (0.0 - 1.0)
   * @returns {string} - Score category
   */
  getScoreCategory(score) {
    if (score >= 0.9) return 'VERY_LIKELY_HUMAN';
    if (score >= 0.7) return 'LIKELY_HUMAN';
    if (score >= 0.5) return 'POSSIBLY_HUMAN';
    if (score >= 0.3) return 'POSSIBLY_BOT';
    return 'LIKELY_BOT';
  }

  /**
   * Verify login attempt with enhanced security
   * @param {string} token - reCAPTCHA token
   * @param {string} email - User email
   * @param {string} ipAddress - User IP address
   * @returns {Promise<Object>} - Verification result
   */
  async verifyLogin(token, email, ipAddress) {
    return this.verifyToken(token, 'LOGIN', {
      threshold: 0.7, // Higher threshold for login
      ipAddress,
      requireLegitimateUser: true
    });
  }

  /**
   * Verify registration attempt
   * @param {string} token - reCAPTCHA token
   * @param {string} email - User email
   * @param {string} ipAddress - User IP address
   * @returns {Promise<Object>} - Verification result
   */
  async verifyRegistration(token, email, ipAddress) {
    return this.verifyToken(token, 'REGISTER', {
      threshold: 0.6,
      ipAddress,
      requireLegitimateUser: false
    });
  }

  /**
   * Verify password reset attempt
   * @param {string} token - reCAPTCHA token
   * @param {string} email - User email
   * @param {string} ipAddress - User IP address
   * @returns {Promise<Object>} - Verification result
   */
  async verifyPasswordReset(token, email, ipAddress) {
    return this.verifyToken(token, 'PASSWORD_RESET', {
      threshold: 0.6,
      ipAddress,
      requireLegitimateUser: false
    });
  }

  /**
   * Verify sensitive operation
   * @param {string} token - reCAPTCHA token
   * @param {string} action - Action name
   * @param {string} ipAddress - User IP address
   * @returns {Promise<Object>} - Verification result
   */
  async verifySensitiveOperation(token, action, ipAddress) {
    return this.verifyToken(token, action, {
      threshold: 0.8, // Very high threshold for sensitive operations
      ipAddress,
      requireLegitimateUser: true
    });
  }

  /**
   * Get assessment statistics
   * @returns {Object} - Service statistics
   */
  getStats() {
    return {
      projectId: this.projectId,
      recaptchaKey: this.recaptchaKey?.substring(0, 10) + '...',
      clientInitialized: !!this.client
    };
  }
}

// Create singleton instance
const recaptchaService = new RecaptchaService();

module.exports = recaptchaService;