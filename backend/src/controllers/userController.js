const User = require('../models/User');
const Session = require('../models/Session');
const AuditLog = require('../models/AuditLog');
const { catchAsync, AppError } = require('../middleware/errorHandler');
const constants = require('../config/constants');
const logger = require('../utils/logger');

// Helper function to filter sensitive user data
const filterUserData = (user, role = 'user') => {
  const userObject = user.toObject ? user.toObject() : user;
  
  // Fields to always remove
  const sensitiveFields = [
    'password',
    'passwordChangedAt',
    'passwordResetToken',
    'passwordResetExpires',
    'loginAttempts',
    'lockUntil',
    'twoFactorSecret',
    'backupCodes',
    '__v'
  ];
  
  sensitiveFields.forEach(field => delete userObject[field]);
  
  // Remove additional fields based on role
  if (role !== 'admin' && role !== 'self') {
    const protectedFields = [
      'verificationToken',
      'verificationExpires',
      'isActive',
      'isVerified',
      'createdAt',
      'updatedAt'
    ];
    
    protectedFields.forEach(field => delete userObject[field]);
  }
  
  return userObject;
};

// @desc    Get all users (Admin only)
// @route   GET /api/users
// @access  Private/Admin
const getAllUsers = catchAsync(async (req, res, next) => {
  const {
    page = 1,
    limit = 10,
    sort = '-createdAt',
    search = '',
    role = '',
    department = '',
    isActive = ''
  } = req.query;
  
  // Build filter
  const filter = {};
  
  if (search) {
    filter.$or = [
      { name: { $regex: search, $options: 'i' } },
      { email: { $regex: search, $options: 'i' } },
      { studentId: { $regex: search, $options: 'i' } }
    ];
  }
  
  if (role) filter.role = role;
  if (department) filter.department = department;
  if (isActive !== '') filter.isActive = isActive === 'true';
  
  // Calculate pagination
  const skip = (page - 1) * limit;
  
  // Execute query with pagination
  const [users, total] = await Promise.all([
    User.find(filter)
      .sort(sort)
      .skip(skip)
      .limit(parseInt(limit))
      .select('-password -loginAttempts -lockUntil'),
    
    User.countDocuments(filter)
  ]);
  
  // Filter sensitive data
  const filteredUsers = users.map(user => filterUserData(user, req.user.role));
  
  // Pagination metadata
  const pagination = {
    page: parseInt(page),
    limit: parseInt(limit),
    total,
    pages: Math.ceil(total / limit)
  };
  
  // Log access
  await AuditLog.log({
    userId: req.user._id,
    email: req.user.email,
    action: constants.AUDIT_ACTIONS.ACCESS,
    resource: 'Users',
    method: 'GET',
    endpoint: req.originalUrl,
    ipAddress: req.ip,
    userAgent: req.get('user-agent'),
    metadata: { pagination, filter }
  });
  
  res.status(200).json({
    success: true,
    count: filteredUsers.length,
    pagination,
    data: filteredUsers
  });
});

// @desc    Get single user
// @route   GET /api/users/:id
// @access  Private
const getUser = catchAsync(async (req, res, next) => {
  const userId = req.params.id;
  
  // Check if user is accessing their own data or is admin
  const canAccess = req.user._id.toString() === userId || req.user.role === constants.ROLES.ADMIN;
  
  if (!canAccess) {
    return next(new AppError('You do not have permission to access this user', 403));
  }
  
  const user = await User.findById(userId);
  
  if (!user) {
    return next(new AppError('User not found', 404));
  }
  
  // Filter data based on who's accessing
  const role = req.user._id.toString() === userId ? 'self' : req.user.role;
  const filteredUser = filterUserData(user, role);
  
  // Log access
  await AuditLog.log({
    userId: req.user._id,
    email: req.user.email,
    action: constants.AUDIT_ACTIONS.ACCESS,
    resource: 'User',
    resourceId: userId,
    method: 'GET',
    endpoint: req.originalUrl,
    ipAddress: req.ip,
    userAgent: req.get('user-agent')
  });
  
  res.status(200).json({
    success: true,
    data: filteredUser
  });
});

// @desc    Create user (Admin only)
// @route   POST /api/users
// @access  Private/Admin
const createUser = catchAsync(async (req, res, next) => {
  const { email, password, name, role, dateOfBirth, studentId, department } = req.body;
  
  // Check if user already exists
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return next(new AppError('User with this email already exists', 400));
  }
  
  // Validate role
  const validRoles = Object.values(constants.ROLES);
  if (role && !validRoles.includes(role)) {
    return next(new AppError(`Invalid role. Valid roles: ${validRoles.join(', ')}`, 400));
  }
  
  // Create user
  const user = await User.create({
    email,
    password,
    name,
    role: role || constants.ROLES.STUDENT,
    dateOfBirth,
    studentId,
    department,
    isVerified: true // Admin-created users are auto-verified
  });
  
  // Log creation
  await AuditLog.log({
    userId: req.user._id,
    email: req.user.email,
    action: constants.AUDIT_ACTIONS.CREATE,
    resource: 'User',
    resourceId: user._id,
    method: 'POST',
    endpoint: req.originalUrl,
    ipAddress: req.ip,
    userAgent: req.get('user-agent'),
    afterState: filterUserData(user, 'admin')
  });
  
  // Filter sensitive data
  const filteredUser = filterUserData(user, 'admin');
  
  res.status(201).json({
    success: true,
    message: 'User created successfully',
    data: filteredUser
  });
});

// @desc    Update user
// @route   PATCH /api/users/:id
// @access  Private
const updateUser = catchAsync(async (req, res, next) => {
  const userId = req.params.id;
  
  // Check permissions
  const canUpdate = req.user._id.toString() === userId || req.user.role === constants.ROLES.ADMIN;
  
  if (!canUpdate) {
    return next(new AppError('You do not have permission to update this user', 403));
  }
  
  // Non-admins cannot update certain fields
  if (req.user.role !== constants.ROLES.ADMIN) {
    const restrictedFields = ['role', 'isActive', 'isVerified', 'loginAttempts', 'lockUntil'];
    restrictedFields.forEach(field => {
      if (req.body[field] !== undefined) {
        delete req.body[field];
      }
    });
  }
  
  // Get current user data for audit log
  const currentUser = await User.findById(userId);
  
  // Update user
  const updatedUser = await User.findByIdAndUpdate(
    userId,
    req.body,
    {
      new: true,
      runValidators: true
    }
  );
  
  if (!updatedUser) {
    return next(new AppError('User not found', 404));
  }
  
  // Log update
  await AuditLog.log({
    userId: req.user._id,
    email: req.user.email,
    action: constants.AUDIT_ACTIONS.UPDATE,
    resource: 'User',
    resourceId: userId,
    method: 'PATCH',
    endpoint: req.originalUrl,
    ipAddress: req.ip,
    userAgent: req.get('user-agent'),
    beforeState: filterUserData(currentUser, 'admin'),
    afterState: filterUserData(updatedUser, 'admin'),
    changes: req.body
  });
  
  // Filter sensitive data based on who's viewing
  const role = req.user._id.toString() === userId ? 'self' : req.user.role;
  const filteredUser = filterUserData(updatedUser, role);
  
  res.status(200).json({
    success: true,
    message: 'User updated successfully',
    data: filteredUser
  });
});

// @desc    Delete user (Admin only)
// @route   DELETE /api/users/:id
// @access  Private/Admin
const deleteUser = catchAsync(async (req, res, next) => {
  const userId = req.params.id;
  
  // Prevent self-deletion
  if (req.user._id.toString() === userId) {
    return next(new AppError('You cannot delete your own account', 400));
  }
  
  const user = await User.findById(userId);
  
  if (!user) {
    return next(new AppError('User not found', 404));
  }
  
  // Get user data for audit log
  const userData = filterUserData(user, 'admin');
  
  // Soft delete (deactivate) instead of hard delete
  user.isActive = false;
  await user.save();
  
  // Revoke all user sessions
  await Session.updateMany(
    { userId },
    { 
      isActive: false, 
      revokedAt: new Date(),
      revokedReason: 'account_deleted' 
    }
  );
  
  // Log deletion
  await AuditLog.log({
    userId: req.user._id,
    email: req.user.email,
    action: constants.AUDIT_ACTIONS.DELETE,
    resource: 'User',
    resourceId: userId,
    method: 'DELETE',
    endpoint: req.originalUrl,
    ipAddress: req.ip,
    userAgent: req.get('user-agent'),
    beforeState: userData
  });
  
  res.status(200).json({
    success: true,
    message: 'User deactivated successfully'
  });
});

// @desc    Get user sessions
// @route   GET /api/users/:id/sessions
// @access  Private/Admin or Self
const getUserSessions = catchAsync(async (req, res, next) => {
  const userId = req.params.id;
  
  // Check permissions
  const canAccess = req.user._id.toString() === userId || req.user.role === constants.ROLES.ADMIN;
  
  if (!canAccess) {
    return next(new AppError('You do not have permission to access these sessions', 403));
  }
  
  const sessions = await Session.find({ userId })
    .sort('-createdAt')
    .limit(10);
  
  // Filter sensitive session data
  const filteredSessions = sessions.map(session => {
    const sessionObj = session.toObject();
    delete sessionObj.accessToken;
    delete sessionObj.refreshToken;
    delete sessionObj.__v;
    return sessionObj;
  });
  
  // Log access
  await AuditLog.log({
    userId: req.user._id,
    email: req.user.email,
    action: constants.AUDIT_ACTIONS.ACCESS,
    resource: 'User Sessions',
    resourceId: userId,
    method: 'GET',
    endpoint: req.originalUrl,
    ipAddress: req.ip,
    userAgent: req.get('user-agent')
  });
  
  res.status(200).json({
    success: true,
    count: filteredSessions.length,
    data: filteredSessions
  });
});

// @desc    Revoke user session
// @route   DELETE /api/users/:userId/sessions/:sessionId
// @access  Private/Admin or Self
const revokeUserSession = catchAsync(async (req, res, next) => {
  const { userId, sessionId } = req.params;
  
  // Check permissions
  const canAccess = req.user._id.toString() === userId || req.user.role === constants.ROLES.ADMIN;
  
  if (!canAccess) {
    return next(new AppError('You do not have permission to revoke this session', 403));
  }
  
  const session = await Session.findOne({
    _id: sessionId,
    userId
  });
  
  if (!session) {
    return next(new AppError('Session not found', 404));
  }
  
  // Revoke session
  session.isActive = false;
  session.revokedAt = new Date();
  session.revokedReason = req.user._id.toString() === userId ? 'self' : 'admin';
  await session.save();
  
  // Log revocation
  await AuditLog.log({
    userId: req.user._id,
    email: req.user.email,
    action: 'SESSION_REVOKE',
    resource: 'Session',
    resourceId: sessionId,
    method: 'DELETE',
    endpoint: req.originalUrl,
    ipAddress: req.ip,
    userAgent: req.get('user-agent')
  });
  
  res.status(200).json({
    success: true,
    message: 'Session revoked successfully'
  });
});

// @desc    Revoke all user sessions except current
// @route   DELETE /api/users/:id/sessions
// @access  Private/Admin or Self
const revokeAllUserSessions = catchAsync(async (req, res, next) => {
  const userId = req.params.id;
  
  // Check permissions
  const canAccess = req.user._id.toString() === userId || req.user.role === constants.ROLES.ADMIN;
  
  if (!canAccess) {
    return next(new AppError('You do not have permission to revoke these sessions', 403));
  }
  
  // Get current session token
  const currentToken = req.headers.authorization?.split(' ')[1];
  
  // Build filter
  const filter = { userId, isActive: true };
  if (currentToken) {
    filter.accessToken = { $ne: currentToken };
  }
  
  // Revoke all other sessions
  const result = await Session.updateMany(
    filter,
    { 
      isActive: false, 
      revokedAt: new Date(),
      revokedReason: 'admin_revoke' 
    }
  );
  
  // Log revocation
  await AuditLog.log({
    userId: req.user._id,
    email: req.user.email,
    action: 'BULK_SESSION_REVOKE',
    resource: 'User Sessions',
    resourceId: userId,
    method: 'DELETE',
    endpoint: req.originalUrl,
    ipAddress: req.ip,
    userAgent: req.get('user-agent'),
    metadata: { sessionsRevoked: result.modifiedCount }
  });
  
  res.status(200).json({
    success: true,
    message: `${result.modifiedCount} session(s) revoked successfully`
  });
});

// @desc    Get user audit logs (Admin only)
// @route   GET /api/users/:id/audit-logs
// @access  Private/Admin
const getUserAuditLogs = catchAsync(async (req, res, next) => {
  const userId = req.params.id;
  
  const {
    page = 1,
    limit = 20,
    startDate,
    endDate,
    action
  } = req.query;
  
  // Build filter
  const filter = { userId };
  
  if (startDate || endDate) {
    filter.createdAt = {};
    if (startDate) filter.createdAt.$gte = new Date(startDate);
    if (endDate) filter.createdAt.$lte = new Date(endDate);
  }
  
  if (action) filter.action = action;
  
  // Calculate pagination
  const skip = (page - 1) * limit;
  
  // Execute query
  const [logs, total] = await Promise.all([
    AuditLog.find(filter)
      .sort('-createdAt')
      .skip(skip)
      .limit(parseInt(limit))
      .select('-__v'),
    
    AuditLog.countDocuments(filter)
  ]);
  
  // Pagination metadata
  const pagination = {
    page: parseInt(page),
    limit: parseInt(limit),
    total,
    pages: Math.ceil(total / limit)
  };
  
  // Log access
  await AuditLog.log({
    userId: req.user._id,
    email: req.user.email,
    action: constants.AUDIT_ACTIONS.ACCESS,
    resource: 'User Audit Logs',
    resourceId: userId,
    method: 'GET',
    endpoint: req.originalUrl,
    ipAddress: req.ip,
    userAgent: req.get('user-agent')
  });
  
  res.status(200).json({
    success: true,
    count: logs.length,
    pagination,
    data: logs
  });
});

// @desc    Get user statistics
// @route   GET /api/users/stats
// @access  Private/Admin
const getUserStats = catchAsync(async (req, res, next) => {
  const stats = await User.aggregate([
    {
      $facet: {
        totalUsers: [
          { $count: 'count' }
        ],
        usersByRole: [
          { $group: { _id: '$role', count: { $sum: 1 } } }
        ],
        usersByStatus: [
          { $group: { _id: '$isActive', count: { $sum: 1 } } }
        ],
        usersByVerification: [
          { $group: { _id: '$isVerified', count: { $sum: 1 } } }
        ],
        usersByDepartment: [
          { $match: { department: { $exists: true, $ne: '' } } },
          { $group: { _id: '$department', count: { $sum: 1 } } },
          { $sort: { count: -1 } },
          { $limit: 10 }
        ],
        registrationTrend: [
          {
            $group: {
              _id: {
                $dateToString: { format: '%Y-%m', date: '$createdAt' }
              },
              count: { $sum: 1 }
            }
          },
          { $sort: { _id: 1 } },
          { $limit: 12 }
        ],
        recentUsers: [
          { $sort: { createdAt: -1 } },
          { $limit: 5 },
          {
            $project: {
              name: 1,
              email: 1,
              role: 1,
              department: 1,
              createdAt: 1
            }
          }
        ]
      }
    }
  ]);
  
  // Format response
  const result = {
    totalUsers: stats[0].totalUsers[0]?.count || 0,
    usersByRole: stats[0].usersByRole,
    usersByStatus: stats[0].usersByStatus.map(s => ({
      status: s._id ? 'Active' : 'Inactive',
      count: s.count
    })),
    usersByVerification: stats[0].usersByVerification.map(v => ({
      verified: v._id ? 'Verified' : 'Unverified',
      count: v.count
    })),
    topDepartments: stats[0].usersByDepartment,
    registrationTrend: stats[0].registrationTrend,
    recentUsers: stats[0].recentUsers
  };
  
  // Log access
  await AuditLog.log({
    userId: req.user._id,
    email: req.user.email,
    action: constants.AUDIT_ACTIONS.ACCESS,
    resource: 'User Statistics',
    method: 'GET',
    endpoint: req.originalUrl,
    ipAddress: req.ip,
    userAgent: req.get('user-agent')
  });
  
  res.status(200).json({
    success: true,
    data: result
  });
});

module.exports = {
  getAllUsers,
  getUser,
  createUser,
  updateUser,
  deleteUser,
  getUserSessions,
  revokeUserSession,
  revokeAllUserSessions,
  getUserAuditLogs,
  getUserStats
};