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

// Public routes
router.post(
  '/register',
  registerLimiter,
  validate(validateRegistration),
  authController.register
);

router.post(
  '/login',
  authLimiter,
  validate(validateLogin),
  authController.login
);

router.post(
  '/forgot-password',
  authLimiter,
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

// Protected routes
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

module.exports = router;