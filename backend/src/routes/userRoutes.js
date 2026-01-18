const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const { protect, authorize, isAdmin } = require('../middleware/auth');
const { validate } = require('../middleware/validation');
const { validateUserId, validatePagination } = require('../middleware/validation');
const { apiLimiter } = require('../middleware/rateLimit');

// Apply rate limiting to all routes
router.use(apiLimiter);

// Apply protection to all routes
router.use(protect);

// Admin only routes
router.get(
  '/',
  isAdmin,
  validate(validatePagination),
  userController.getAllUsers
);

router.get(
  '/stats',
  isAdmin,
  userController.getUserStats
);

router.post(
  '/',
  isAdmin,
  userController.createUser
);

// User routes (admin or self)
router.get(
  '/:id',
  validate(validateUserId),
  userController.getUser
);

router.patch(
  '/:id',
  validate(validateUserId),
  userController.updateUser
);

router.delete(
  '/:id',
  isAdmin,
  validate(validateUserId),
  userController.deleteUser
);

// Session management routes
router.get(
  '/:id/sessions',
  validate(validateUserId),
  userController.getUserSessions
);

router.delete(
  '/:id/sessions',
  validate(validateUserId),
  userController.revokeAllUserSessions
);

router.delete(
  '/:userId/sessions/:sessionId',
  userController.revokeUserSession
);

// Audit logs (admin only)
router.get(
  '/:id/audit-logs',
  isAdmin,
  validate(validateUserId),
  validate(validatePagination),
  userController.getUserAuditLogs
);

module.exports = router;