const nodemailer = require('nodemailer');
const logger = require('../utils/logger');

class EmailService {
  constructor() {
    this.transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: process.env.SMTP_PORT,
      secure: process.env.SMTP_PORT == 465,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      },
      tls: {
        rejectUnauthorized: false // For self-signed certificates
      }
    });

    // Verify transporter configuration
    this.transporter.verify((error) => {
      if (error) {
        logger.error('Email transporter verification failed:', error);
      } else {
        logger.info('Email transporter is ready');
      }
    });
  }

  /**
   * Send email
   * @param {Object} options - Email options
   * @returns {Promise<Object>} - Send result
   */
  async sendEmail(options) {
    const mailOptions = {
      from: `"Secure Campus Portal" <${process.env.SMTP_USER}>`,
      to: options.to,
      subject: options.subject,
      text: options.text,
      html: options.html,
      attachments: options.attachments
    };

    try {
      const info = await this.transporter.sendMail(mailOptions);
      logger.info(`Email sent to ${options.to}: ${info.messageId}`);
      return { success: true, messageId: info.messageId };
    } catch (error) {
      logger.error('Failed to send email:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Send verification email
   * @param {Object} data - Verification data
   * @returns {Promise<Object>} - Send result
   */
  async sendVerificationEmail(data) {
    const verificationUrl = data.verificationUrl;
    
    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background-color: #4a6fa5; color: white; padding: 20px; text-align: center; }
          .content { padding: 30px; background-color: #f9f9f9; }
          .button { 
            display: inline-block; 
            padding: 12px 24px; 
            background-color: #4a6fa5; 
            color: white; 
            text-decoration: none; 
            border-radius: 4px; 
            margin: 20px 0; 
          }
          .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 12px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Email Verification</h1>
          </div>
          <div class="content">
            <p>Hello ${data.name},</p>
            <p>Thank you for registering with Secure Campus Portal. Please verify your email address by clicking the button below:</p>
            <p>
              <a href="${verificationUrl}" class="button">Verify Email Address</a>
            </p>
            <p>Or copy and paste this link into your browser:</p>
            <p>${verificationUrl}</p>
            <p>This link will expire in 24 hours.</p>
            <p>If you did not create an account, please ignore this email.</p>
          </div>
          <div class="footer">
            <p>© ${new Date().getFullYear()} Secure Campus Portal. All rights reserved.</p>
            <p>This is an automated message, please do not reply to this email.</p>
          </div>
        </div>
      </body>
      </html>
    `;

    const text = `
      Email Verification

      Hello ${data.name},

      Thank you for registering with Secure Campus Portal. Please verify your email address by visiting this link:

      ${verificationUrl}

      This link will expire in 24 hours.

      If you did not create an account, please ignore this email.

      © ${new Date().getFullYear()} Secure Campus Portal. All rights reserved.
      This is an automated message, please do not reply to this email.
    `;

    return this.sendEmail({
      to: data.email,
      subject: 'Verify Your Email - Secure Campus Portal',
      text,
      html
    });
  }

  /**
   * Send password reset email
   * @param {Object} data - Password reset data
   * @returns {Promise<Object>} - Send result
   */
  async sendPasswordResetEmail(data) {
    const resetUrl = data.resetUrl;
    
    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background-color: #d9534f; color: white; padding: 20px; text-align: center; }
          .content { padding: 30px; background-color: #f9f9f9; }
          .button { 
            display: inline-block; 
            padding: 12px 24px; 
            background-color: #d9534f; 
            color: white; 
            text-decoration: none; 
            border-radius: 4px; 
            margin: 20px 0; 
          }
          .warning { background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; margin: 20px 0; border-radius: 4px; }
          .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 12px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Password Reset Request</h1>
          </div>
          <div class="content">
            <p>Hello ${data.name},</p>
            <p>We received a request to reset your password for your Secure Campus Portal account.</p>
            <p>Click the button below to reset your password:</p>
            <p>
              <a href="${resetUrl}" class="button">Reset Password</a>
            </p>
            <p>Or copy and paste this link into your browser:</p>
            <p>${resetUrl}</p>
            <div class="warning">
              <p><strong>Important:</strong> This password reset link will expire in 10 minutes.</p>
              <p>If you did not request a password reset, please ignore this email or contact support if you have concerns.</p>
            </div>
          </div>
          <div class="footer">
            <p>© ${new Date().getFullYear()} Secure Campus Portal. All rights reserved.</p>
            <p>This is an automated message, please do not reply to this email.</p>
          </div>
        </div>
      </body>
      </html>
    `;

    const text = `
      Password Reset Request

      Hello ${data.name},

      We received a request to reset your password for your Secure Campus Portal account.

      Click the link below to reset your password:

      ${resetUrl}

      Important: This password reset link will expire in 10 minutes.

      If you did not request a password reset, please ignore this email or contact support if you have concerns.

      © ${new Date().getFullYear()} Secure Campus Portal. All rights reserved.
      This is an automated message, please do not reply to this email.
    `;

    return this.sendEmail({
      to: data.email,
      subject: 'Password Reset Request - Secure Campus Portal',
      text,
      html
    });
  }

  /**
   * Send account locked email
   * @param {Object} data - Account lock data
   * @returns {Promise<Object>} - Send result
   */
  async sendAccountLockedEmail(data) {
    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background-color: #f0ad4e; color: white; padding: 20px; text-align: center; }
          .content { padding: 30px; background-color: #f9f9f9; }
          .warning { background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; margin: 20px 0; border-radius: 4px; }
          .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 12px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Account Security Alert</h1>
          </div>
          <div class="content">
            <p>Hello ${data.name},</p>
            <p>We detected multiple failed login attempts on your Secure Campus Portal account.</p>
            <div class="warning">
              <p><strong>Your account has been temporarily locked for security reasons.</strong></p>
              <p>Lockout duration: ${data.lockoutDuration}</p>
              <p>Failed attempts: ${data.attempts}</p>
              <p>IP Address: ${data.ipAddress}</p>
              <p>Time: ${new Date(data.timestamp).toLocaleString()}</p>
            </div>
            <p>If this was you, please wait for the lockout period to expire or contact support to unlock your account.</p>
            <p>If this was not you, we recommend:</p>
            <ul>
              <li>Changing your password immediately after unlocking</li>
              <li>Enabling two-factor authentication</li>
              <li>Reviewing your account activity</li>
            </ul>
          </div>
          <div class="footer">
            <p>© ${new Date().getFullYear()} Secure Campus Portal. All rights reserved.</p>
            <p>This is an automated security message, please do not reply to this email.</p>
          </div>
        </div>
      </body>
      </html>
    `;

    const text = `
      Account Security Alert

      Hello ${data.name},

      We detected multiple failed login attempts on your Secure Campus Portal account.

      Your account has been temporarily locked for security reasons.

      Lockout duration: ${data.lockoutDuration}
      Failed attempts: ${data.attempts}
      IP Address: ${data.ipAddress}
      Time: ${new Date(data.timestamp).toLocaleString()}

      If this was you, please wait for the lockout period to expire or contact support to unlock your account.

      If this was not you, we recommend:
      - Changing your password immediately after unlocking
      - Enabling two-factor authentication
      - Reviewing your account activity

      © ${new Date().getFullYear()} Secure Campus Portal. All rights reserved.
      This is an automated security message, please do not reply to this email.
    `;

    return this.sendEmail({
      to: data.email,
      subject: 'Account Security Alert - Secure Campus Portal',
      text,
      html
    });
  }

  /**
   * Send welcome email
   * @param {Object} data - Welcome email data
   * @returns {Promise<Object>} - Send result
   */
  async sendWelcomeEmail(data) {
    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background-color: #5cb85c; color: white; padding: 20px; text-align: center; }
          .content { padding: 30px; background-color: #f9f9f9; }
          .feature { background-color: white; border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 4px; }
          .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 12px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Welcome to Secure Campus Portal!</h1>
          </div>
          <div class="content">
            <p>Hello ${data.name},</p>
            <p>Welcome to Secure Campus Portal! Your account has been successfully created and verified.</p>
            <p>Here are some features you can explore:</p>
            <div class="feature">
              <strong>🔐 Secure Authentication</strong>
              <p>Your account is protected with industry-standard security measures.</p>
            </div>
            <div class="feature">
              <strong>📊 Personal Dashboard</strong>
              <p>Access your personalized dashboard with all your information in one place.</p>
            </div>
            <div class="feature">
              <strong>🔒 Data Encryption</strong>
              <p>Your sensitive data is encrypted both in transit and at rest.</p>
            </div>
            <p>To get started, log in to your account and complete your profile.</p>
            <p>If you have any questions or need assistance, please contact our support team.</p>
          </div>
          <div class="footer">
            <p>© ${new Date().getFullYear()} Secure Campus Portal. All rights reserved.</p>
            <p>This is an automated message, please do not reply to this email.</p>
          </div>
        </div>
      </body>
      </html>
    `;

    const text = `
      Welcome to Secure Campus Portal!

      Hello ${data.name},

      Welcome to Secure Campus Portal! Your account has been successfully created and verified.

      Here are some features you can explore:

      🔐 Secure Authentication
      Your account is protected with industry-standard security measures.

      📊 Personal Dashboard
      Access your personalized dashboard with all your information in one place.

      🔒 Data Encryption
      Your sensitive data is encrypted both in transit and at rest.

      To get started, log in to your account and complete your profile.

      If you have any questions or need assistance, please contact our support team.

      © ${new Date().getFullYear()} Secure Campus Portal. All rights reserved.
      This is an automated message, please do not reply to this email.
    `;

    return this.sendEmail({
      to: data.email,
      subject: 'Welcome to Secure Campus Portal!',
      text,
      html
    });
  }

  /**
   * Send admin alert email
   * @param {Object} data - Admin alert data
   * @returns {Promise<Object>} - Send result
   */
  async sendAdminAlert(data) {
    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background-color: #d9534f; color: white; padding: 20px; text-align: center; }
          .content { padding: 30px; background-color: #f9f9f9; }
          .alert { background-color: #f2dede; border: 1px solid #ebcccc; padding: 15px; margin: 20px 0; border-radius: 4px; }
          .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 12px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🔔 Admin Security Alert</h1>
          </div>
          <div class="content">
            <div class="alert">
              <h3>${data.title}</h3>
              <p><strong>Severity:</strong> ${data.severity}</p>
              <p><strong>Time:</strong> ${new Date(data.timestamp).toLocaleString()}</p>
            </div>
            <p><strong>Details:</strong></p>
            <pre style="background-color: #f5f5f5; padding: 15px; border-radius: 4px; overflow-x: auto;">${JSON.stringify(data.details, null, 2)}</pre>
            <p>Please review this alert and take appropriate action if necessary.</p>
          </div>
          <div class="footer">
            <p>© ${new Date().getFullYear()} Secure Campus Portal. All rights reserved.</p>
            <p>This is an automated security alert for administrators only.</p>
          </div>
        </div>
      </body>
      </html>
    `;

    const text = `
      Admin Security Alert

      ${data.title}

      Severity: ${data.severity}
      Time: ${new Date(data.timestamp).toLocaleString()}

      Details:
      ${JSON.stringify(data.details, null, 2)}

      Please review this alert and take appropriate action if necessary.

      © ${new Date().getFullYear()} Secure Campus Portal. All rights reserved.
      This is an automated security alert for administrators only.
    `;

    return this.sendEmail({
      to: data.adminEmails,
      subject: `Admin Alert: ${data.title} - Secure Campus Portal`,
      text,
      html
    });
  }
}

// Create singleton instance
const emailService = new EmailService();

module.exports = emailService;