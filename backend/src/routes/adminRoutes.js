const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { validate } = require('../middleware/validation');
const {
  validateRegistration,
  validateLogin,
  validatePasswordChange,
  validateEmail
} = require('../middleware/validation');
const { protect } = require('../middleware/auth');
const { authLimiter, registerLimiter } = require('../middleware/rateLimit');
const recaptcha = require('../middleware/recaptcha');

// Public routes with reCAPTCHA
router.post(
  '/register',
  registerLimiter,
  recaptcha.register, // Add reCAPTCHA verification
  validate(validateRegistration),
  authController.register
);

router.post(
  '/login',
  authLimiter,
  recaptcha.login, // Add reCAPTCHA verification
  validate(validateLogin),
  authController.login
);

router.post(
  '/forgot-password',
  authLimiter,
  recaptcha.passwordReset, // Add reCAPTCHA verification
  validate(validateEmail),
  authController.forgotPassword
);

router.patch(
  '/reset-password/:token',
  authLimiter,
  validate(validatePasswordChange),
  authController.resetPassword
);

router.post(
  '/refresh-token',
  authController.refreshToken
);

// Protected routes (no reCAPTCHA needed for authenticated users)
router.use(protect);

router.post(
  '/logout',
  authController.logout
);

router.patch(
  '/change-password',
  validate(validatePasswordChange),
  authController.changePassword
);

router.get(
  '/me',
  authController.getMe
);

router.patch(
  '/update-me',
  authController.updateMe
);

router.delete(
  '/deactivate',
  authController.deactivateMe
);

// New endpoint to get reCAPTCHA site key
router.get('/recaptcha-key', (req, res) => {
  res.json({
    success: true,
    data: {
      siteKey: process.env.RECAPTCHA_SITE_KEY,
      enabled: process.env.ENABLE_RECAPTCHA === 'true'
    }
  });
});

module.exports = router;