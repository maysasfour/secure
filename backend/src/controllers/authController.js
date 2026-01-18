const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Session = require('../models/Session');
const AuditLog = require('../models/AuditLog');
const emailService = require('../services/emailService');
const { generateToken, generateRefreshToken } = require('../utils/token');
const { catchAsync, AppError } = require('../middleware/errorHandler');
const constants = require('../config/constants');
const logger = require('../utils/logger');


const createSession = async (user, req) => {
  const accessToken = generateToken(user._id, user.role);
  const refreshToken = generateRefreshToken(user._id);

  const userAgent = req.get('user-agent') || '';
  const deviceInfo = parseUserAgent(userAgent);
  
  const session = await Session.create({
    userId: user._id,
    accessToken,
    refreshToken,
    userAgent,
    ipAddress: req.ip,
    deviceInfo,
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
  });
  
  return { accessToken, refreshToken, session };
};


const parseUserAgent = (userAgent) => {
  const deviceInfo = {
    browser: 'Unknown',
    os: 'Unknown',
    device: 'Unknown',
    platform: 'Unknown'
  };
  

  if (userAgent.includes('Chrome')) deviceInfo.browser = 'Chrome';
  else if (userAgent.includes('Firefox')) deviceInfo.browser = 'Firefox';
  else if (userAgent.includes('Safari')) deviceInfo.browser = 'Safari';
  else if (userAgent.includes('Edge')) deviceInfo.browser = 'Edge';
  
  if (userAgent.includes('Windows')) deviceInfo.os = 'Windows';
  else if (userAgent.includes('Mac')) deviceInfo.os = 'Mac OS';
  else if (userAgent.includes('Linux')) deviceInfo.os = 'Linux';
  else if (userAgent.includes('Android')) deviceInfo.os = 'Android';
  else if (userAgent.includes('iOS')) deviceInfo.os = 'iOS';
  
  if (userAgent.includes('Mobile')) deviceInfo.device = 'Mobile';
  else if (userAgent.includes('Tablet')) deviceInfo.device = 'Tablet';
  else deviceInfo.device = 'Desktop';
  
  return deviceInfo;
};

const register = catchAsync(async (req, res, next) => {
  const { email, password, name, dateOfBirth, phone, studentId, department } = req.body;
  

  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return next(new AppError('Email already registered', 400));
  }
  

  const user = await User.create({
    email,
    password,
    name,
    dateOfBirth,
    phone,
    studentId,
    department,
    role: constants.ROLES.STUDENT
  });
  

  const verificationToken = user.createVerificationToken();
  await user.save({ validateBeforeSave: false });
  
  const verificationUrl = `${req.protocol}://${req.get('host')}/api/auth/verify-email/${verificationToken}`;
  
  try {
    await emailService.sendVerificationEmail({
      email: user.email,
      name: user.name,
      verificationUrl
    });
    
    logger.info(`Verification email sent to ${user.email}`);
  } catch (error) {
    logger.error('Failed to send verification email:', error);

  }
  

  const { accessToken, refreshToken } = await createSession(user, req);

  await AuditLog.log({
    userId: user._id,
    email: user.email,
    action: constants.AUDIT_ACTIONS.CREATE,
    resource: 'User',
    resourceId: user._id,
    method: 'POST',
    endpoint: req.originalUrl,
    ipAddress: req.ip,
    userAgent: req.get('user-agent'),
    afterState: {
      email: user.email,
      role: user.role,
      isVerified: user.isVerified
    }
  });
  
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
  });
  
  user.password = undefined;
  
  res.status(201).json({
    success: true,
    message: constants.MESSAGES.SUCCESS.REGISTER,
    data: {
      user,
      accessToken,
      expiresIn: constants.TOKEN_EXPIRY.ACCESS_TOKEN
    }
  });
});


const login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;
 
  if (!email || !password) {
    return next(new AppError('Please provide email and password', 400));
  }
  
  const user = await User.findOne({ email }).select('+password +loginAttempts +lockUntil');
  
  if (!user) {
    return next(new AppError('Invalid email or password', 401));
  }
  
  if (user.isLocked) {
    await AuditLog.log({
      email,
      action: constants.AUDIT_ACTIONS.FAILED_LOGIN,
      resource: 'Auth',
      method: 'POST',
      endpoint: req.originalUrl,
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      error: {
        message: 'Account locked due to too many failed attempts'
      }
    });
    
    return next(new AppError(constants.MESSAGES.ERROR.ACCOUNT_LOCKED, 401));
  }
  

  const isPasswordCorrect = await user.comparePassword(password, user.password);
  
  if (!isPasswordCorrect) {

    await user.incrementLoginAttempts();
    
    await AuditLog.log({
      email,
      action: constants.AUDIT_ACTIONS.FAILED_LOGIN,
      resource: 'Auth',
      method: 'POST',
      endpoint: req.originalUrl,
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      error: {
        message: 'Invalid password'
      }
    });
    
    return next(new AppError('Invalid email or password', 401));
  }
  
  
  await user.resetLoginAttempts();

  user.lastLogin = Date.now();
  await user.save({ validateBeforeSave: false });

  const { accessToken, refreshToken, session } = await createSession(user, req);
  
  await AuditLog.log({
    userId: user._id,
    email: user.email,
    action: constants.AUDIT_ACTIONS.LOGIN,
    resource: 'Auth',
    method: 'POST',
    endpoint: req.originalUrl,
    ipAddress: req.ip,
    userAgent: req.get('user-agent'),
    sessionId: session._id
  });
  

  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
  });
  

  user.password = undefined;
  
  res.status(200).json({
    success: true,
    message: constants.MESSAGES.SUCCESS.LOGIN,
    data: {
      user,
      accessToken,
      expiresIn: constants.TOKEN_EXPIRY.ACCESS_TOKEN
    }
  });
});


const logout = catchAsync(async (req, res, next) => {

  const token = req.headers.authorization?.split(' ')[1] || req.cookies.accessToken;
  
  if (token) {

    await Session.findOneAndUpdate(
      { accessToken: token },
      { 
        isActive: false, 
        revokedAt: new Date(),
        revokedReason: 'logout' 
      }
    );
    

    await AuditLog.log({
      userId: req.user._id,
      email: req.user.email,
      action: constants.AUDIT_ACTIONS.LOGOUT,
      resource: 'Auth',
      method: 'POST',
      endpoint: req.originalUrl,
      ipAddress: req.ip,
      userAgent: req.get('user-agent')
    });
  }
  
  res.clearCookie('refreshToken');
  res.clearCookie('accessToken');
  
  res.status(200).json({
    success: true,
    message: constants.MESSAGES.SUCCESS.LOGOUT
  });
});


const refreshToken = catchAsync(async (req, res, next) => {
  const refreshToken = req.cookies.refreshToken || req.body.refreshToken;
  
  if (!refreshToken) {
    return next(new AppError('Refresh token is required', 400));
  }
  
  try {

    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

    const session = await Session.findOne({
      refreshToken,
      isActive: true,
      expiresAt: { $gt: new Date() }
    });
    
    if (!session) {
      return next(new AppError('Invalid or expired refresh token', 401));
    }

    const user = await User.findById(decoded.id);
    if (!user) {
      return next(new AppError('User no longer exists', 401));
    }
   
    if (user.changedPasswordAfter(decoded.iat)) {

      await Session.updateMany(
        { userId: user._id },
        { 
          isActive: false, 
          revokedAt: new Date(),
          revokedReason: 'password_change' 
        }
      );
      
      return next(new AppError('Password was changed recently. Please login again.', 401));
    }
    

    const newAccessToken = generateToken(user._id, user.role);
    

    session.accessToken = newAccessToken;
    session.lastActivity = new Date();
    await session.save();
    
    res.status(200).json({
      success: true,
      data: {
        accessToken: newAccessToken,
        expiresIn: constants.TOKEN_EXPIRY.ACCESS_TOKEN
      }
    });
    
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return next(new AppError('Invalid refresh token', 401));
    }
    if (error.name === 'TokenExpiredError') {
      return next(new AppError('Refresh token expired', 401));
    }
    next(error);
  }
});

const forgotPassword = catchAsync(async (req, res, next) => {
  const { email } = req.body;

  const user = await User.findOne({ email });
  if (!user) {

    return res.status(200).json({
      success: true,
      message: 'If your email is registered, you will receive a password reset link'
    });
  }
  

  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });
  

  const resetURL = `${req.protocol}://${req.get('host')}/api/auth/reset-password/${resetToken}`;
  
  try {
    await emailService.sendPasswordResetEmail({
      email: user.email,
      name: user.name,
      resetURL
    });
    

    await AuditLog.log({
      userId: user._id,
      email: user.email,
      action: 'PASSWORD_RESET_REQUEST',
      resource: 'Auth',
      method: 'POST',
      endpoint: req.originalUrl,
      ipAddress: req.ip,
      userAgent: req.get('user-agent')
    });
    
    res.status(200).json({
      success: true,
      message: 'Password reset link sent to email'
    });
  } catch (error) {
   
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });
    
    logger.error('Error sending password reset email:', error);
    return next(new AppError('There was an error sending the email. Try again later.', 500));
  }
});

const resetPassword = catchAsync(async (req, res, next) => {

  const hashedToken = crypto
    .createHash('sha256')
    .update(req.params.token)
    .digest('hex');
  
  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() }
  });
  
  if (!user) {
    return next(new AppError('Token is invalid or has expired', 400));
  }
  
 
  user.password = req.body.password;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  user.passwordChangedAt = Date.now();
  await user.save();
  

  await Session.updateMany(
    { userId: user._id },
    { 
      isActive: false, 
      revokedAt: new Date(),
      revokedReason: 'password_change' 
    }
  );
  

  const { accessToken, refreshToken } = await createSession(user, req);
  

  await AuditLog.log({
    userId: user._id,
    email: user.email,
    action: 'PASSWORD_RESET',
    resource: 'Auth',
    method: 'PATCH',
    endpoint: req.originalUrl,
    ipAddress: req.ip,
    userAgent: req.get('user-agent')
  });
  

  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
  

  res.status(200).json({
    success: true,
    message: 'Password reset successful',
    data: {
      accessToken,
      expiresIn: constants.TOKEN_EXPIRY.ACCESS_TOKEN
    }
  });
});


const changePassword = catchAsync(async (req, res, next) => {
  const { currentPassword, newPassword } = req.body;
  

  const user = await User.findById(req.user.id).select('+password');
  

  const isPasswordCorrect = await user.comparePassword(currentPassword, user.password);
  
  if (!isPasswordCorrect) {
    return next(new AppError('Your current password is wrong', 401));
  }
  

  user.password = newPassword;
  user.passwordChangedAt = Date.now();
  await user.save();
  

  await Session.updateMany(
    { 
      userId: user._id,
      accessToken: { $ne: req.headers.authorization?.split(' ')[1] }
    },
    { 
      isActive: false, 
      revokedAt: new Date(),
      revokedReason: 'password_change' 
    }
  );

  await AuditLog.log({
    userId: user._id,
    email: user.email,
    action: 'PASSWORD_CHANGE',
    resource: 'Auth',
    method: 'PATCH',
    endpoint: req.originalUrl,
    ipAddress: req.ip,
    userAgent: req.get('user-agent')
  });
  
  const accessToken = generateToken(user._id, user.role);

  await Session.findOneAndUpdate(
    { accessToken: req.headers.authorization?.split(' ')[1] },
    { accessToken }
  );
  
  res.status(200).json({
    success: true,
    message: 'Password changed successfully',
    data: {
      accessToken,
      expiresIn: constants.TOKEN_EXPIRY.ACCESS_TOKEN
    }
  });
});

const getMe = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.user.id);
  
  res.status(200).json({
    success: true,
    data: {
      user
    }
  });
});

const updateMe = catchAsync(async (req, res, next) => {
  
  if (req.body.password || req.body.passwordConfirm) {
    return next(new AppError('This route is not for password updates. Please use /change-password.', 400));
  }
  

  const filteredBody = filterObj(req.body, 'name', 'email', 'phone', 'department');
  

  const updatedUser = await User.findByIdAndUpdate(req.user.id, filteredBody, {
    new: true,
    runValidators: true
  });
  

  await AuditLog.log({
    userId: updatedUser._id,
    email: updatedUser.email,
    action: constants.AUDIT_ACTIONS.UPDATE,
    resource: 'User',
    resourceId: updatedUser._id,
    method: 'PATCH',
    endpoint: req.originalUrl,
    ipAddress: req.ip,
    userAgent: req.get('user-agent'),
    changes: filteredBody
  });
  
  res.status(200).json({
    success: true,
    message: constants.MESSAGES.SUCCESS.UPDATE,
    data: {
      user: updatedUser
    }
  });
});

const deactivateMe = catchAsync(async (req, res, next) => {
  await User.findByIdAndUpdate(req.user.id, { isActive: false });
  

  await Session.updateMany(
    { userId: req.user.id },
    { 
      isActive: false, 
      revokedAt: new Date(),
      revokedReason: 'account_deactivation' 
    }
  );
  

  await AuditLog.log({
    userId: req.user._id,
    email: req.user.email,
    action: 'ACCOUNT_DEACTIVATION',
    resource: 'User',
    resourceId: req.user._id,
    method: 'DELETE',
    endpoint: req.originalUrl,
    ipAddress: req.ip,
    userAgent: req.get('user-agent')
  });

  res.clearCookie('refreshToken');
  res.clearCookie('accessToken');
  
  res.status(200).json({
    success: true,
    message: 'Account deactivated successfully'
  });
});

 const filterObj = (obj, ...allowedFields) => {
  const newObj = {};
  Object.keys(obj).forEach(el => {
    if (allowedFields.includes(el)) newObj[el] = obj[el];
  });
  return newObj;
};



// @desc    Verify reCAPTCHA token
// @route   POST /api/auth/verify-recaptcha
// @access  Public
const verifyRecaptcha = catchAsync(async (req, res, next) => {
  const { token, action } = req.body;
  
  if (!token || !action) {
    return next(new AppError('Token and action are required', 400));
  }
  
  const verification = await recaptchaService.verifyToken(
    token,
    action,
    {
      ipAddress: req.ip
    }
  );
  
  res.status(200).json({
    success: true,
    data: verification
  });
});



module.exports = {
  register,
  login,
  logout,
  refreshToken,
  forgotPassword,
  resetPassword,
  changePassword,
  getMe,
  updateMe,
  deactivateMe,
  verifyRecaptcha
};


