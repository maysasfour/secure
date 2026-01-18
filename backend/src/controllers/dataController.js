const crypto = require('crypto');
const { catchAsync, AppError } = require('../middleware/errorHandler');
const constants = require('../config/constants');
const { encryptData, decryptData } = require('../utils/encryption');
const logger = require('../utils/logger');

// Sample data model (in a real app, this would be a proper Mongoose model)
class SecureData {
  constructor() {
    this.data = [];
  }
  
  async create(data, userId) {
    const encryptedData = encryptData(JSON.stringify(data));
    
    const record = {
      id: crypto.randomBytes(16).toString('hex'),
      userId,
      encryptedData,
      dataHash: crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex'),
      createdAt: new Date(),
      updatedAt: new Date(),
      isActive: true
    };
    
    this.data.push(record);
    return record;
  }
  
  async findById(id, userId) {
    const record = this.data.find(d => 
      d.id === id && 
      d.userId === userId && 
      d.isActive
    );
    
    if (!record) return null;
    
    return {
      ...record,
      decryptedData: JSON.parse(decryptData(record.encryptedData))
    };
  }
  
  async findByUser(userId) {
    return this.data
      .filter(d => d.userId === userId && d.isActive)
      .map(record => ({
        ...record,
        decryptedData: JSON.parse(decryptData(record.encryptedData))
      }));
  }
  
  async update(id, data, userId) {
    const index = this.data.findIndex(d => 
      d.id === id && 
      d.userId === userId && 
      d.isActive
    );
    
    if (index === -1) return null;
    
    const encryptedData = encryptData(JSON.stringify(data));
    
    this.data[index] = {
      ...this.data[index],
      encryptedData,
      dataHash: crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex'),
      updatedAt: new Date()
    };
    
    return {
      ...this.data[index],
      decryptedData: data
    };
  }
  
  async delete(id, userId) {
    const index = this.data.findIndex(d => 
      d.id === id && 
      d.userId === userId && 
      d.isActive
    );
    
    if (index === -1) return false;
    
    this.data[index].isActive = false;
    this.data[index].deletedAt = new Date();
    
    return true;
  }
}

const secureDataModel = new SecureData();

// @desc    Create secure data
// @route   POST /api/data
// @access  Private
const createData = catchAsync(async (req, res, next) => {
  const { data } = req.body;
  
  if (!data || typeof data !== 'object') {
    return next(new AppError('Valid data object is required', 400));
  }
  
  // Validate sensitive data structure
  if (data.sensitive) {
    const sensitiveFields = ['ssn', 'creditCard', 'bankAccount', 'medicalRecords'];
    const hasSensitiveFields = sensitiveFields.some(field => 
      data.sensitive[field] !== undefined
    );
    
    if (!hasSensitiveFields) {
      return next(new AppError('Sensitive data must contain valid sensitive fields', 400));
    }
  }
  
  const record = await secureDataModel.create(data, req.user._id);
  
  res.status(201).json({
    success: true,
    message: 'Data encrypted and stored successfully',
    data: {
      id: record.id,
      createdAt: record.createdAt,
      dataHash: record.dataHash
    }
  });
});

// @desc    Get all user's secure data
// @route   GET /api/data
// @access  Private
const getAllData = catchAsync(async (req, res, next) => {
  const records = await secureDataModel.findByUser(req.user._id);
  
  // Mask sensitive data in list view
  const safeRecords = records.map(record => ({
    id: record.id,
    dataHash: record.dataHash,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    dataType: record.decryptedData.type || 'unknown',
    hasSensitiveData: !!record.decryptedData.sensitive
  }));
  
  res.status(200).json({
    success: true,
    count: safeRecords.length,
    data: safeRecords
  });
});

// @desc    Get single secure data record
// @route   GET /api/data/:id
// @access  Private
const getData = catchAsync(async (req, res, next) => {
  const { id } = req.params;
  
  const record = await secureDataModel.findById(id, req.user._id);
  
  if (!record) {
    return next(new AppError('Data record not found', 404));
  }
  
  // Additional security check: verify data integrity
  const currentHash = crypto.createHash('sha256')
    .update(JSON.stringify(record.decryptedData))
    .digest('hex');
  
  if (currentHash !== record.dataHash) {
    logger.error(`Data integrity check failed for record ${id}`);
    return next(new AppError('Data integrity verification failed', 500));
  }
  
  res.status(200).json({
    success: true,
    data: {
      id: record.id,
      data: record.decryptedData,
      dataHash: record.dataHash,
      createdAt: record.createdAt,
      updatedAt: record.updatedAt,
      integrityCheck: 'passed'
    }
  });
});

// @desc    Update secure data
// @route   PUT /api/data/:id
// @access  Private
const updateData = catchAsync(async (req, res, next) => {
  const { id } = req.params;
  const { data } = req.body;
  
  if (!data || typeof data !== 'object') {
    return next(new AppError('Valid data object is required', 400));
  }
  
  const updatedRecord = await secureDataModel.update(id, data, req.user._id);
  
  if (!updatedRecord) {
    return next(new AppError('Data record not found or unauthorized', 404));
  }
  
  res.status(200).json({
    success: true,
    message: 'Data updated successfully',
    data: {
      id: updatedRecord.id,
      dataHash: updatedRecord.dataHash,
      updatedAt: updatedRecord.updatedAt
    }
  });
});

// @desc    Delete secure data
// @route   DELETE /api/data/:id
// @access  Private
const deleteData = catchAsync(async (req, res, next) => {
  const { id } = req.params;
  
  const deleted = await secureDataModel.delete(id, req.user._id);
  
  if (!deleted) {
    return next(new AppError('Data record not found or unauthorized', 404));
  }
  
  res.status(200).json({
    success: true,
    message: 'Data deleted successfully'
  });
});

// @desc    Verify data integrity
// @route   POST /api/data/:id/verify
// @access  Private
const verifyDataIntegrity = catchAsync(async (req, res, next) => {
  const { id } = req.params;
  
  const record = await secureDataModel.findById(id, req.user._id);
  
  if (!record) {
    return next(new AppError('Data record not found', 404));
  }
  
  // Calculate current hash
  const currentHash = crypto.createHash('sha256')
    .update(JSON.stringify(record.decryptedData))
    .digest('hex');
  
  const integrityCheck = {
    storedHash: record.dataHash,
    calculatedHash: currentHash,
    match: currentHash === record.dataHash,
    timestamp: new Date(),
    recordId: id
  };
  
  // Log integrity check result
  if (!integrityCheck.match) {
    logger.warn(`Data integrity mismatch for record ${id}`, integrityCheck);
  }
  
  res.status(200).json({
    success: true,
    data: integrityCheck
  });
});

// @desc    Encrypt text (demo endpoint)
// @route   POST /api/data/encrypt-text
// @access  Private
const encryptText = catchAsync(async (req, res, next) => {
  const { text } = req.body;
  
  if (!text || typeof text !== 'string') {
    return next(new AppError('Text to encrypt is required', 400));
  }
  
  if (text.length > 10000) {
    return next(new AppError('Text too long (max 10000 characters)', 400));
  }
  
  const encrypted = encryptData(text);
  const hash = crypto.createHash('sha256').update(text).digest('hex');
  
  res.status(200).json({
    success: true,
    data: {
      encrypted,
      hash,
      originalLength: text.length,
      encryptedLength: encrypted.length
    }
  });
});

// @desc    Decrypt text (demo endpoint)
// @route   POST /api/data/decrypt-text
// @access  Private
const decryptText = catchAsync(async (req, res, next) => {
  const { encryptedText } = req.body;
  
  if (!encryptedText || typeof encryptedText !== 'string') {
    return next(new AppError('Encrypted text is required', 400));
  }
  
  try {
    const decrypted = decryptData(encryptedText);
    
    res.status(200).json({
      success: true,
      data: {
        decrypted,
        isJSON: isJSON(decrypted)
      }
    });
  } catch (error) {
    return next(new AppError('Failed to decrypt text. Invalid encryption.', 400));
  }
});

// Helper function to check if string is JSON
const isJSON = (str) => {
  try {
    JSON.parse(str);
    return true;
  } catch (error) {
    return false;
  }
};

// @desc    Get encryption status
// @route   GET /api/data/encryption-status
// @access  Private
const getEncryptionStatus = catchAsync(async (req, res, next) => {
  const status = {
    algorithm: 'AES-256-GCM',
    keyLength: 256,
    ivLength: 96,
    encryptionEnabled: !!process.env.ENCRYPTION_KEY,
    keyAvailable: !!process.env.ENCRYPTION_KEY,
    testEncryption: 'functional'
  };
  
  // Test encryption/decryption
  try {
    const testData = { test: 'encryption', timestamp: new Date().toISOString() };
    const encrypted = encryptData(JSON.stringify(testData));
    const decrypted = JSON.parse(decryptData(encrypted));
    
    status.testEncryption = JSON.stringify(testData) === JSON.stringify(decrypted) 
      ? 'functional' 
      : 'failed';
  } catch (error) {
    status.testEncryption = 'failed';
    status.testError = error.message;
  }
  
  res.status(200).json({
    success: true,
    data: status
  });
});

module.exports = {
  createData,
  getAllData,
  getData,
  updateData,
  deleteData,
  verifyDataIntegrity,
  encryptText,
  decryptText,
  getEncryptionStatus
};