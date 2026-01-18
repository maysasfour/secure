const User = require('../models/User');
const Admin = require('../models/Admin');
const Session = require('../models/Session');
const AuditLog = require('../models/AuditLog');
const { catchAsync, AppError } = require('../middleware/errorHandler');
const constants = require('../config/constants');
const logger = require('../utils/logger');

const getDashboardStats = catchAsync(async (req, res, next) => {
  const [
    totalUsers,
    activeUsers,
    newUsersToday,
    totalSessions,
    activeSessions,
    auditLogsToday,
    failedLoginsToday
  ] = await Promise.all([
   
    User.countDocuments(),
    
    Session.distinct('userId', {
      lastActivity: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
    }).then(ids => ids.length),
  
    User.countDocuments({
      createdAt: { $gte: new Date().setHours(0, 0, 0, 0) }
    }),
    
 
    Session.countDocuments(),
    

    Session.countDocuments({ 
      isActive: true,
      expiresAt: { $gt: new Date() }
    }),
    
  
    AuditLog.countDocuments({
      createdAt: { $gte: new Date().setHours(0, 0, 0, 0) }
    }),
    
 
    AuditLog.countDocuments({
      action: constants.AUDIT_ACTIONS.FAILED_LOGIN,
      createdAt: { $gte: new Date().setHours(0, 0, 0, 0) }
    })
  ]);
  
 
  const recentSecurityEvents = await AuditLog.find({
    $or: [
      { action: constants.AUDIT_ACTIONS.FAILED_LOGIN },
      { isSuspicious: true },
      { action: 'SECURITY_EVENT' }
    ]
  })
  .sort('-createdAt')
  .limit(10)
  .select('action createdAt ipAddress userAgent metadata');

  const systemHealth = {
    database: 'connected',
    memoryUsage: process.memoryUsage(),
    uptime: process.uptime(),
    nodeVersion: process.version,
    environment: process.env.NODE_ENV
  };
  
  const stats = {
    users: {
      total: totalUsers,
      active: activeUsers,
      newToday: newUsersToday
    },
    sessions: {
      total: totalSessions,
      active: activeSessions
    },
    security: {
      auditLogsToday,
      failedLoginsToday,
      recentEvents: recentSecurityEvents
    },
    system: systemHealth
  };
  
 
  await AuditLog.log({
    userId: req.user._id,
    email: req.user.email,
    action: constants.AUDIT_ACTIONS.ACCESS,
    resource: 'Admin Dashboard',
    method: 'GET',
    endpoint: req.originalUrl,
    ipAddress: req.ip,
    userAgent: req.get('user-agent')
  });
  
  res.status(200).json({
    success: true,
    data: stats
  });
});


const getAllAuditLogs = catchAsync(async (req, res, next) => {
  const {
    page = 1,
    limit = 50,
    startDate,
    endDate,
    userId,
    email,
    action,
    ipAddress,
    isSuspicious,
    resource,
    method
  } = req.query;
  

  const filter = {};
  
  if (startDate || endDate) {
    filter.createdAt = {};
    if (startDate) filter.createdAt.$gte = new Date(startDate);
    if (endDate) filter.createdAt.$lte = new Date(endDate);
  }
  

  if (userId) filter.userId = userId;
  if (email) filter.email = { $regex: email, $options: 'i' };
  if (action) filter.action = action;
  if (ipAddress) filter.ipAddress = ipAddress;
  if (isSuspicious !== undefined) filter.isSuspicious = isSuspicious === 'true';
  if (resource) filter.resource = { $regex: resource, $options: 'i' };
  if (method) filter.method = method;

  const skip = (page - 1) * limit;

  const [logs, total] = await Promise.all([
    AuditLog.find(filter)
      .sort('-createdAt')
      .skip(skip)
      .limit(parseInt(limit))
      .populate('userId', 'name email role')
      .select('-__v'),
    
    AuditLog.countDocuments(filter)
  ]);
  

  const pagination = {
    page: parseInt(page),
    limit: parseInt(limit),
    total,
    pages: Math.ceil(total / limit)
  };
  

  const filterSummary = {
    dateRange: { startDate, endDate },
    filtersApplied: Object.keys(req.query).length - 3
  };
  
 
  await AuditLog.log({
    userId: req.user._id,
    email: req.user.email,
    action: constants.AUDIT_ACTIONS.ACCESS,
    resource: 'Audit Logs',
    method: 'GET',
    endpoint: req.originalUrl,
    ipAddress: req.ip,
    userAgent: req.get('user-agent'),
    metadata: { filterSummary, pagination }
  });
  
  res.status(200).json({
    success: true,
    count: logs.length,
    pagination,
    filters: filterSummary,
    data: logs
  });
});

const getSecurityInsights = catchAsync(async (req, res, next) => {
  const { days = 7 } = req.query;
  
  const startDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
  
 
  const insights = await AuditLog.aggregate([
    {
      $match: {
        createdAt: { $gte: startDate },
        $or: [
          { action: constants.AUDIT_ACTIONS.FAILED_LOGIN },
          { isSuspicious: true },
          { statusCode: { $gte: 400 } }
        ]
      }
    },
    {
      $facet: {
     
        threatTypes: [
          {
            $group: {
              _id: {
                $cond: [
                  { $eq: ['$action', constants.AUDIT_ACTIONS.FAILED_LOGIN] },
                  'Failed Login',
                  { $ifNull: ['$metadata.threatType', 'Other'] }
                ]
              },
              count: { $sum: 1 }
            }
          },
          { $sort: { count: -1 } }
        ],
        
        topSuspiciousIPs: [
          { $match: { ipAddress: { $exists: true, $ne: null } } },
          {
            $group: {
              _id: '$ipAddress',
              count: { $sum: 1 },
              lastActivity: { $max: '$createdAt' },
              actions: { $addToSet: '$action' }
            }
          },
          { $sort: { count: -1 } },
          { $limit: 10 }
        ],
       
        activityByHour: [
          {
            $group: {
              _id: { $hour: '$createdAt' },
              count: { $sum: 1 }
            }
          },
          { $sort: { _id: 1 } }
        ],
        
        failedLoginsByUser: [
          { $match: { action: constants.AUDIT_ACTIONS.FAILED_LOGIN } },
          {
            $group: {
              _id: '$email',
              count: { $sum: 1 },
              lastAttempt: { $max: '$createdAt' },
              ips: { $addToSet: '$ipAddress' }
            }
          },
          { $match: { count: { $gt: 3 } } },
          { $sort: { count: -1 } },
          { $limit: 20 }
        ],

        recentEvents: [
          { $sort: { createdAt: -1 } },
          { $limit: 20 },
          {
            $project: {
              action: 1,
              createdAt: 1,
              ipAddress: 1,
              email: 1,
              resource: 1,
              metadata: 1,
              isSuspicious: 1
            }
          }
        ]
      }
    }
  ]);

  const totalEvents = insights[0].recentEvents.length;
  const suspiciousEvents = insights[0].recentEvents.filter(e => e.isSuspicious).length;
  const threatLevel = totalEvents > 0 ? (suspiciousEvents / totalEvents) * 100 : 0;
  
  const result = {
    timeframe: {
      startDate,
      endDate: new Date(),
      days: parseInt(days)
    },
    threatLevel: Math.round(threatLevel),
    threatLevelDescription: threatLevel > 70 ? 'High' : threatLevel > 30 ? 'Medium' : 'Low',
    insights: insights[0],
    recommendations: generateSecurityRecommendations(insights[0])
  };
  
  await AuditLog.log({
    userId: req.user._id,
    email: req.user.email,
    action: constants.AUDIT_ACTIONS.ACCESS,
    resource: 'Security Insights',
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

const generateSecurityRecommendations = (insights) => {
  const recommendations = [];

  const failedLogins = insights.failedLoginsByUser || [];
  failedLogins.forEach(login => {
    if (login.count > 10) {
      recommendations.push({
        type: 'BRUTE_FORCE',
        severity: 'HIGH',
        message: `User ${login._id} has ${login.count} failed login attempts`,
        action: 'Consider locking account or implementing CAPTCHA'
      });
    }
  });
  
  const suspiciousIPs = insights.topSuspiciousIPs || [];
  suspiciousIPs.forEach(ip => {
    if (ip.count > 20) {
      recommendations.push({
        type: 'SUSPICIOUS_IP',
        severity: 'MEDIUM',
        message: `IP ${ip._id} has ${ip.count} suspicious activities`,
        action: 'Consider blocking IP or implementing rate limiting'
      });
    }
  });
  
  const activityByHour = insights.activityByHour || [];
  const nighttimeActivity = activityByHour.filter(hour => 
    hour._id >= 0 && hour._id <= 5 && hour.count > 10
  );
  
  if (nighttimeActivity.length > 0) {
    recommendations.push({
      type: 'UNUSUAL_ACTIVITY_TIME',
      severity: 'LOW',
      message: 'Unusual activity detected during nighttime hours',
      action: 'Monitor for automated attacks'
    });
  }
  
  return recommendations;
};


const getAllSessions = catchAsync(async (req, res, next) => {
  const {
    page = 1,
    limit = 50,
    userId,
    isActive,
    device,
    browser
  } = req.query;

  const filter = {};
  
  if (userId) filter.userId = userId;
  if (isActive !== undefined) filter.isActive = isActive === 'true';
  if (device) filter['deviceInfo.device'] = device;
  if (browser) filter['deviceInfo.browser'] = browser;
  
  const skip = (page - 1) * limit;
  
  const [sessions, total] = await Promise.all([
    Session.find(filter)
      .sort('-lastActivity')
      .skip(skip)
      .limit(parseInt(limit))
      .populate('userId', 'name email role')
      .select('-accessToken -refreshToken -__v'),
    
    Session.countDocuments(filter)
  ]);

  const pagination = {
    page: parseInt(page),
    limit: parseInt(limit),
    total,
    pages: Math.ceil(total / limit)
  };
  
  const activeSessions = sessions.filter(s => s.isActive).length;
  const expiredSessions = sessions.filter(s => s.isExpired).length;
  
  await AuditLog.log({
    userId: req.user._id,
    email: req.user.email,
    action: constants.AUDIT_ACTIONS.ACCESS,
    resource: 'All Sessions',
    method: 'GET',
    endpoint: req.originalUrl,
    ipAddress: req.ip,
    userAgent: req.get('user-agent'),
    metadata: { activeSessions, expiredSessions }
  });
  
  res.status(200).json({
    success: true,
    count: sessions.length,
    pagination,
    stats: {
      active: activeSessions,
      expired: expiredSessions,
      total: sessions.length
    },
    data: sessions
  });
});

const toggleUserLock = catchAsync(async (req, res, next) => {
  const userId = req.params.id;
  const { lock, reason } = req.body;
  
  if (lock === undefined) {
    return next(new AppError('Lock status is required', 400));
  }
  
  const user = await User.findById(userId);
  
  if (!user) {
    return next(new AppError('User not found', 404));
  }

  if (user.role === constants.ROLES.ADMIN && req.user._id.toString() !== userId) {
    return next(new AppError('Cannot lock another admin account', 403));
  }
  
  if (lock) {
    user.lockUntil = new Date(Date.now() + 24 * 60 * 60 * 1000); 
    user.loginAttempts = constants.SECURITY.MAX_LOGIN_ATTEMPTS;
    
    await Session.updateMany(
      { userId, isActive: true },
      { 
        isActive: false, 
        revokedAt: new Date(),
        revokedReason: 'admin_lock' 
      }
    );
  } else {
    user.lockUntil = undefined;
    user.loginAttempts = 0;
  }
  
  await user.save({ validateBeforeSave: false });
  
  await AuditLog.log({
    userId: req.user._id,
    email: req.user.email,
    action: lock ? 'ACCOUNT_LOCKED' : 'ACCOUNT_UNLOCKED',
    resource: 'User',
    resourceId: userId,
    method: 'PATCH',
    endpoint: req.originalUrl,
    ipAddress: req.ip,
    userAgent: req.get('user-agent'),
    metadata: {
      locked: lock,
      reason: reason || 'Administrative action',
      lockUntil: user.lockUntil
    }
  });
  
  res.status(200).json({
    success: true,
    message: `Account ${lock ? 'locked' : 'unlocked'} successfully`,
    data: {
      locked: lock,
      lockUntil: user.lockUntil
    }
  });
});

const forcePasswordReset = catchAsync(async (req, res, next) => {
  const userId = req.params.id;
  
  const user = await User.findById(userId);
  
  if (!user) {
    return next(new AppError('User not found', 404));
  }

  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });
 
  await Session.updateMany(
    { userId, isActive: true },
    { 
      isActive: false, 
      revokedAt: new Date(),
      revokedReason: 'forced_password_reset' 
    }
  );
  
  const resetURL = `${req.protocol}://${req.get('host')}/reset-password/${resetToken}`;
  
  await AuditLog.log({
    userId: req.user._id,
    email: req.user.email,
    action: 'FORCED_PASSWORD_RESET',
    resource: 'User',
    resourceId: userId,
    method: 'POST',
    endpoint: req.originalUrl,
    ipAddress: req.ip,
    userAgent: req.get('user-agent'),
    metadata: { resetURL }
  });
  
  res.status(200).json({
    success: true,
    message: 'Password reset initiated',
    data: {
      resetToken,
      resetURL,
      expiresAt: user.passwordResetExpires
    }
  });
});

const exportAuditLogs = catchAsync(async (req, res, next) => {
  const { format = 'json', startDate, endDate } = req.query;
  

  const filter = {};
  if (startDate || endDate) {
    filter.createdAt = {};
    if (startDate) filter.createdAt.$gte = new Date(startDate);
    if (endDate) filter.createdAt.$lte = new Date(endDate);
  }
  
 
  const logs = await AuditLog.find(filter)
    .sort('createdAt')
    .populate('userId', 'name email')
    .select('-__v');
  
  let data;
  let contentType;
  let filename;
  
  switch (format.toLowerCase()) {
    case 'csv':
      data = convertToCSV(logs);
      contentType = 'text/csv';
      filename = `audit-logs-${Date.now()}.csv`;
      break;
    
    case 'json':
    default:
      data = JSON.stringify(logs, null, 2);
      contentType = 'application/json';
      filename = `audit-logs-${Date.now()}.json`;
  }

  await AuditLog.log({
    userId: req.user._id,
    email: req.user.email,
    action: 'EXPORT_AUDIT_LOGS',
    resource: 'Audit Logs',
    method: 'GET',
    endpoint: req.originalUrl,
    ipAddress: req.ip,
    userAgent: req.get('user-agent'),
    metadata: { format, count: logs.length }
  });

  res.setHeader('Content-Type', contentType);
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send(data);
});

const convertToCSV = (logs) => {
  const headers = [
    'Timestamp', 'Action', 'User ID', 'User Email', 'IP Address',
    'Resource', 'Method', 'Status Code', 'Is Suspicious'
  ];
  
  const rows = logs.map(log => [
    log.createdAt.toISOString(),
    log.action,
    log.userId?._id || 'N/A',
    log.email || 'N/A',
    log.ipAddress || 'N/A',
    log.resource || 'N/A',
    log.method || 'N/A',
    log.statusCode || 'N/A',
    log.isSuspicious ? 'Yes' : 'No'
  ]);
  
  return [headers, ...rows].map(row => row.join(',')).join('\n');
};

module.exports = {
  getDashboardStats,
  getAllAuditLogs,
  getSecurityInsights,
  getAllSessions,
  toggleUserLock,
  forcePasswordReset,
  exportAuditLogs
};