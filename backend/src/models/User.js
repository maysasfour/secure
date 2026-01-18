const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const validator = require('validator');
const crypto = require('crypto');
const constants = require('../config/constants');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    trim: true,
    validate: [validator.isEmail, 'Please provide a valid email']
  },
  
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [constants.SECURITY.PASSWORD_MIN_LENGTH, 
      `Password must be at least ${constants.SECURITY.PASSWORD_MIN_LENGTH} characters`],
    select: false
  },
  
  name: {
    type: String,
    required: [true, 'Name is required'],
    trim: true,
    maxlength: [50, 'Name cannot exceed 50 characters']
  },
  
  studentId: {
    type: String,
    unique: true,
    sparse: true,
    trim: true,
    uppercase: true
  },
  
  role: {
    type: String,
    enum: Object.values(constants.ROLES),
    default: constants.ROLES.STUDENT
  },
  
  dateOfBirth: {
    type: Date,
    required: [true, 'Date of birth is required']
  },
  
  phone: {
    type: String,
    validate: {
      validator: function(v) {
        return /^[\+]?[1-9][\d]{0,15}$/.test(v);
      },
      message: props => `${props.value} is not a valid phone number!`
    }
  },
  
  // Security fields
  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  
  loginAttempts: {
    type: Number,
    default: 0,
    select: false
  },
  
  lockUntil: {
    type: Date,
    select: false
  },
  
  isActive: {
    type: Boolean,
    default: true
  },
  
  isVerified: {
    type: Boolean,
    default: false
  },
  
  verificationToken: String,
  verificationExpires: Date,
  
  // Profile fields
  profileImage: String,
  department: String,
  semester: Number,
  enrolledCourses: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Course'
  }],
  
  // Timestamps
  lastLogin: Date,
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
}, {
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes
userSchema.index({ email: 1 }, { unique: true });
userSchema.index({ studentId: 1 }, { unique: true, sparse: true });
userSchema.index({ role: 1 });
userSchema.index({ createdAt: -1 });

// Pre-save middleware to hash password
userSchema.pre('save', async function(next) {
  // Only run this function if password was modified
  if (!this.isModified('password')) return next();
  
  try {
    // Hash the password with cost of 12
    this.password = await bcrypt.hash(this.password, constants.SECURITY.BCRYPT_ROUNDS);
    
    // Delete passwordResetToken fields if password is being set (not reset)
    this.passwordResetToken = undefined;
    this.passwordResetExpires = undefined;
    
    next();
  } catch (error) {
    next(error);
  }
});

// Update updatedAt on save
userSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

// Check if account is locked
userSchema.virtual('isLocked').get(function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Increment login attempts
userSchema.methods.incrementLoginAttempts = function() {
  // If we have a previous lock that has expired, restart at 1
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.updateOne({
      $set: { loginAttempts: 1 },
      $unset: { lockUntil: 1 }
    });
  }
  
  // Otherwise increment
  const updates = { $inc: { loginAttempts: 1 } };
  
  // Lock the account if we've reached max attempts and it's not locked already
  if (this.loginAttempts + 1 >= constants.SECURITY.MAX_LOGIN_ATTEMPTS && !this.isLocked) {
    updates.$set = { 
      lockUntil: Date.now() + constants.SECURITY.LOCKOUT_TIME 
    };
  }
  
  return this.updateOne(updates);
};

// Reset login attempts on successful login
userSchema.methods.resetLoginAttempts = function() {
  return this.updateOne({
    $set: { loginAttempts: 0 },
    $unset: { lockUntil: 1 }
  });
};

// Check if password was changed after token was issued
userSchema.methods.changedPasswordAfter = function(JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10
    );
    return JWTTimestamp < changedTimestamp;
  }
  return false;
};

// Generate password reset token
userSchema.methods.createPasswordResetToken = function() {
  const resetToken = crypto.randomBytes(32).toString('hex');
  
  this.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');
  
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
  
  return resetToken;
};

// Generate email verification token
userSchema.methods.createVerificationToken = function() {
  const verificationToken = crypto.randomBytes(32).toString('hex');
  
  this.verificationToken = crypto
    .createHash('sha256')
    .update(verificationToken)
    .digest('hex');
  
  this.verificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
  
  return verificationToken;
};

// Compare password
userSchema.methods.comparePassword = async function(candidatePassword, userPassword) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

const User = mongoose.model('User', userSchema);

module.exports = User;