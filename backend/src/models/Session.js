const mongoose = require('mongoose');

const sessionSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  
  accessToken: {
    type: String,
    required: true,
    index: true
  },
  
  refreshToken: {
    type: String,
    required: true,
    index: true
  },
  
  userAgent: String,
  
  ipAddress: String,
  
  deviceInfo: {
    browser: String,
    os: String,
    device: String,
    platform: String
  },
  
  location: {
    country: String,
    region: String,
    city: String,
    timezone: String
  },
  
  isActive: {
    type: Boolean,
    default: true
  },
  
  expiresAt: {
    type: Date,
    required: true,
    index: { expires: '7d' } // Auto-delete after 7 days
  },
  
  revokedAt: Date,
  
  revokedReason: {
    type: String,
    enum: ['logout', 'password_change', 'suspicious', 'admin', 'system']
  },
  
  createdAt: {
    type: Date,
    default: Date.now,
    index: true
  },
  
  lastActivity: {
    type: Date,
    default: Date.now
  }
});

// Update last activity timestamp
sessionSchema.methods.updateActivity = function() {
  this.lastActivity = Date.now();
  return this.save();
};

// Revoke session
sessionSchema.methods.revoke = function(reason = 'logout') {
  this.isActive = false;
  this.revokedAt = Date.now();
  this.revokedReason = reason;
  return this.save();
};

// Check if session is expired
sessionSchema.methods.isExpired = function() {
  return Date.now() > this.expiresAt;
};

// Check if session should be considered active
sessionSchema.virtual('isValid').get(function() {
  return this.isActive && !this.isExpired();
});

// Static method to clean up old sessions
sessionSchema.statics.cleanup = async function() {
  const cutoffDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000); // 30 days ago
  return this.deleteMany({ 
    $or: [
      { expiresAt: { $lt: new Date() } },
      { createdAt: { $lt: cutoffDate } }
    ]
  });
};

const Session = mongoose.model('Session', sessionSchema);

module.exports = Session;