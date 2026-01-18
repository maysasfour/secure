const mongoose = require('mongoose');
const User = require('./User');

const adminSchema = new mongoose.Schema({
  // Admin-specific fields
  adminLevel: {
    type: String,
    enum: ['super', 'department', 'academic', 'support'],
    default: 'department'
  },
  
  permissions: [{
    type: String,
    enum: [
      'manage_users', 
      'manage_courses', 
      'manage_grades', 
      'view_analytics',
      'system_config',
      'audit_logs'
    ]
  }],
  
  assignedDepartments: [String],
  
  canCreateAdmins: {
    type: Boolean,
    default: false
  },
  
  lastSystemAccess: Date,
  
  // Additional contact info
  officeLocation: String,
  officeHours: String,
  emergencyContact: String,
  
  // System access tracking
  ipWhitelist: [String],
  accessRestricted: {
    type: Boolean,
    default: false
  },
  
  // Two-factor authentication
  twoFactorEnabled: {
    type: Boolean,
    default: false
  },
  twoFactorSecret: String,
  backupCodes: [String]
});

// Inherit from User model
const Admin = User.discriminator('Admin', adminSchema);

module.exports = Admin;