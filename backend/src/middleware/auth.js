const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Session = require('../models/Session');
const AuditLog = require('../models/AuditLog');
const constants = require('../config/constants');

// Protect routes - verify JWT
const protect = async (req, res, next) => {
  let token;
  
  // Check for token in Authorization header
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  }
  
  // Check for token in cookies (for web clients)
  else if (req.cookies && req.cookies.accessToken) {
    token = req.cookies.accessToken;
  }
  
  if (!token) {
    return res.status(401).json({
      success: false,
      error: constants.MESSAGES.ERROR.UNAUTHORIZED
    });
  }
  
  try {
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Check if token is blacklisted or session is valid
    const session = await Session.findOne({
      accessToken: token,
      isActive: true,
      expiresAt: { $gt: new Date() }
    });
    
    if (!session) {
      return res.status(401).json({
        success: false,
        error: 'Session expired or invalid'
      });
    }
    
    // Get user from database
    const user = await User.findById(decoded.id).select('+passwordChangedAt');
    
    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'User no longer exists'
      });
    }
    
    // Check if user changed password after token was issued
    if (user.changedPasswordAfter(decoded.iat)) {
      // Revoke all sessions for this user
      await Session.updateMany(
        { userId: user._id },
        { 
          isActive: false, 
          revokedAt: new Date(),
          revokedReason: 'password_change' 
        }
      );
      
      return res.status(401).json({
        success: false,
        error: 'Password was changed recently. Please login again.'
      });
    }
    
    // Check if user is active
    if (!user.isActive) {
      return res.status(401).json({
        success: false,
        error: 'Account is deactivated'
      });
    }
    
    // Check if account is locked
    if (user.isLocked) {
      return res.status(401).json({
        success: false,
        error: constants.MESSAGES.ERROR.ACCOUNT_LOCKED
      });
    }
    
    // Update session last activity
    session.updateActivity();
    
    // Attach user and session to request
    req.user = user;
    req.session = session;
    
    // Log access for sensitive routes
    if (req.originalUrl.includes('/admin') || req.originalUrl.includes('/profile')) {
      await AuditLog.log({
        userId: user._id,
        email: user.email,
        role: user.role,
        action: constants.AUDIT_ACTIONS.ACCESS,
        resource: req.originalUrl,
        method: req.method,
        endpoint: req.originalUrl,
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        requestTime: new Date()
      });
    }
    
    next();
  } catch (error) {
    // Handle different JWT errors
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        success: false,
        error: constants.MESSAGES.ERROR.TOKEN_INVALID
      });
    }
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        error: constants.MESSAGES.ERROR.TOKEN_EXPIRED
      });
    }
    
    return res.status(401).json({
      success: false,
      error: constants.MESSAGES.ERROR.UNAUTHORIZED
    });
  }
};

// Role-based authorization
const authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: constants.MESSAGES.ERROR.UNAUTHORIZED
      });
    }
    
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        error: constants.MESSAGES.ERROR.FORBIDDEN
      });
    }
    
    next();
  };
};

// Check if user is admin
const isAdmin = (req, res, next) => {
  if (!req.user || req.user.role !== constants.ROLES.ADMIN) {
    return res.status(403).json({
      success: false,
      error: 'Admin access required'
    });
  }
  next();
};

// Check if user is student
const isStudent = (req, res, next) => {
  if (!req.user || req.user.role !== constants.ROLES.STUDENT) {
    return res.status(403).json({
      success: false,
      error: 'Student access required'
    });
  }
  next();
};

// Check ownership (user can only access their own data)
const checkOwnership = (model, paramName = 'id') => {
  return async (req, res, next) => {
    try {
      const resourceId = req.params[paramName];
      const userId = req.user._id;
      
      const resource = await model.findById(resourceId);
      
      if (!resource) {
        return res.status(404).json({
          success: false,
          error: constants.MESSAGES.ERROR.NOT_FOUND
        });
      }
      
      // Admins can access any resource
      if (req.user.role === constants.ROLES.ADMIN) {
        return next();
      }
      
      // Check if user owns the resource
      if (resource.userId && resource.userId.toString() !== userId.toString()) {
        return res.status(403).json({
          success: false,
          error: 'You do not own this resource'
        });
      }
      
      // For resources without userId field, check by other means
      if (resource.user && resource.user.toString() !== userId.toString()) {
        return res.status(403).json({
          success: false,
          error: 'You do not own this resource'
        });
      }
      
      next();
    } catch (error) {
      return res.status(500).json({
        success: false,
        error: constants.MESSAGES.ERROR.SERVER_ERROR
      });
    }
  };
};

module.exports = {
  protect,
  authorize,
  isAdmin,
  isStudent,
  checkOwnership
};