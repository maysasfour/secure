const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const { encryptSensitiveData, decryptSensitiveData } = require('../utils/encryption');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Please add a name'],
    trim: true
  },
  email: {
    type: String,
    required: [true, 'Please add an email'],
    unique: true,
    lowercase: true,
    match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please add a valid email']
  },
  password: {
    type: String,
    required: [true, 'Please add a password'],
    minlength: 8,
    select: false // Ensures password isn't returned in standard queries
  },
  role: {
    type: String,
    enum: ['student', 'admin'],
    default: 'student'
  },
  // Sensitive data encrypted at rest
  nationalId: {
    type: String,
    set: encryptSensitiveData,
    get: decryptSensitiveData
  },
  passwordChangedAt: Date
}, {
  timestamps: true,
  toJSON: { getters: true }, // Ensures decryption happens when sending data to frontend
  toObject: { getters: true }
});

// Password Hashing Middleware
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  const salt = await bcrypt.genSalt(12);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

module.exports = mongoose.model('User', userSchema);