const express = require('express');
const router = express.Router();
const dataController = require('../controllers/dataController');
const { protect } = require('../middleware/auth');
const { apiLimiter } = require('../middleware/rateLimit');

// Apply protection and rate limiting to all routes
router.use(protect);
router.use(apiLimiter);

// Data encryption endpoints
router.post(
  '/data',
  dataController.createData
);

router.get(
  '/data',
  dataController.getAllData
);

router.get(
  '/data/:id',
  dataController.getData
);

router.put(
  '/data/:id',
  dataController.updateData
);

router.delete(
  '/data/:id',
  dataController.deleteData
);

router.post(
  '/data/:id/verify',
  dataController.verifyDataIntegrity
);

// Encryption utilities
router.post(
  '/data/encrypt-text',
  dataController.encryptText
);

router.post(
  '/data/decrypt-text',
  dataController.decryptText
);

router.get(
  '/data/encryption-status',
  dataController.getEncryptionStatus
);

module.exports = router;