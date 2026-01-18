const mongoose = require('mongoose');
const constants = require('../config/constants');

const auditLogSchema = new mongoose.Schema({
  // User information
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  
  email: String,
  role: String,
  ipAddress: String,
  userAgent: String,
  
  // Action details
  action: {
    type: String,
    enum: Object.values(constants.AUDIT_ACTIONS),
    required: true
  },
  
  resource: String,
  resourceId: mongoose.Schema.Types.ObjectId,
  
  // Request details
  method: String,
  endpoint: String,
  statusCode: Number,
  
  // Changes made
  beforeState: mongoose.Schema.Types.Mixed,
  afterState: mongoose.Schema.Types.Mixed,
  changes: mongoose.Schema.Types.Mixed,
  
  // Metadata
  metadata: mongoose.Schema.Types.Mixed,
  
  // Security context
  sessionId: String,
  isSuspicious: {
    type: Boolean,
    default: false
  },
  
  // Timing
  requestTime: Date,
  responseTime: Date,
  duration: Number, // in milliseconds
  
  // Location
  location: {
    country: String,
    region: String,
    city: String,
    coordinates: {
      type: [Number], // [longitude, latitude]
      index: '2dsphere'
    }
  },
  
  // Error details
  error: {
    message: String,
    stack: String,
    code: String
  },
  
  createdAt: {
    type: Date,
    default: Date.now,
    index: true,
    expires: '90d' // Auto-delete after 90 days
  }
});

// Indexes for efficient querying
auditLogSchema.index({ userId: 1, createdAt: -1 });
auditLogSchema.index({ action: 1, createdAt: -1 });
auditLogSchema.index({ ipAddress: 1, createdAt: -1 });
auditLogSchema.index({ isSuspicious: 1, createdAt: -1 });
auditLogSchema.index({ 'location.coordinates': '2dsphere' });

// Pre-save middleware to calculate duration
auditLogSchema.pre('save', function(next) {
  if (this.requestTime && this.responseTime) {
    this.duration = this.responseTime - this.requestTime;
  }
  next();
});

// Static method to log an action
auditLogSchema.statics.log = async function(data) {
  try {
    const auditLog = new this(data);
    return await auditLog.save();
  } catch (error) {
    console.error('Failed to save audit log:', error);
    // Don't throw error to avoid breaking the main flow
  }
};

// Method to mark as suspicious
auditLogSchema.methods.markSuspicious = function() {
  this.isSuspicious = true;
  return this.save();
};

const AuditLog = mongoose.model('AuditLog', auditLogSchema);

module.exports = AuditLog;