const AuditLog = require('../models/AuditLog');
const logger = require('../utils/logger');

class AuditService {
  /**
   * Log user action
   * @param {Object} data - Audit log data
   * @returns {Promise<Object>} - Created audit log
   */
  async logAction(data) {
    try {
      const auditLog = new AuditLog({
        userId: data.userId,
        email: data.email,
        role: data.role,
        action: data.action,
        resource: data.resource,
        resourceId: data.resourceId,
        method: data.method,
        endpoint: data.endpoint,
        ipAddress: data.ipAddress,
        userAgent: data.userAgent,
        statusCode: data.statusCode,
        beforeState: data.beforeState,
        afterState: data.afterState,
        changes: data.changes,
        metadata: data.metadata,
        requestTime: data.requestTime,
        responseTime: data.responseTime,
        isSuspicious: data.isSuspicious || false
      });

      await auditLog.save();
      return auditLog;
    } catch (error) {
      logger.error('Failed to save audit log:', error);
      // Don't throw to avoid breaking main flow
      return null;
    }
  }

  /**
   * Log security event
   * @param {Object} event - Security event data
   * @returns {Promise<Object>} - Created audit log
   */
  async logSecurityEvent(event) {
    return this.logAction({
      userId: event.userId,
      email: event.email,
      role: event.role,
      action: 'SECURITY_EVENT',
      resource: event.resource || 'Security',
      resourceId: event.resourceId,
      method: event.method,
      endpoint: event.endpoint,
      ipAddress: event.ipAddress,
      userAgent: event.userAgent,
      statusCode: event.statusCode,
      metadata: {
        eventType: event.eventType,
        severity: event.severity,
        details: event.details
      },
      isSuspicious: true
    });
  }

  /**
   * Log failed login attempt
   * @param {Object} data - Login attempt data
   * @returns {Promise<Object>} - Created audit log
   */
  async logFailedLogin(data) {
    return this.logAction({
      userId: data.userId,
      email: data.email,
      role: data.role,
      action: 'FAILED_LOGIN',
      resource: 'Auth',
      method: 'POST',
      endpoint: data.endpoint || '/api/auth/login',
      ipAddress: data.ipAddress,
      userAgent: data.userAgent,
      statusCode: 401,
      metadata: {
        reason: data.reason,
        attempts: data.attempts,
        lockout: data.lockout
      },
      isSuspicious: true
    });
  }

  /**
   * Log suspicious activity
   * @param {Object} data - Suspicious activity data
   * @returns {Promise<Object>} - Created audit log
   */
  async logSuspiciousActivity(data) {
    return this.logSecurityEvent({
      eventType: 'SUSPICIOUS_ACTIVITY',
      severity: 'HIGH',
      userId: data.userId,
      email: data.email,
      ipAddress: data.ipAddress,
      endpoint: data.endpoint,
      details: data.details
    });
  }

  /**
   * Log data access
   * @param {Object} data - Data access data
   * @returns {Promise<Object>} - Created audit log
   */
  async logDataAccess(data) {
    return this.logAction({
      userId: data.userId,
      email: data.email,
      role: data.role,
      action: 'DATA_ACCESS',
      resource: data.resource,
      resourceId: data.resourceId,
      method: data.method,
      endpoint: data.endpoint,
      ipAddress: data.ipAddress,
      userAgent: data.userAgent,
      metadata: {
        dataType: data.dataType,
        accessLevel: data.accessLevel
      }
    });
  }

  /**
   * Log configuration change
   * @param {Object} data - Configuration change data
   * @returns {Promise<Object>} - Created audit log
   */
  async logConfigChange(data) {
    return this.logAction({
      userId: data.userId,
      email: data.email,
      role: data.role,
      action: 'CONFIG_CHANGE',
      resource: 'Configuration',
      method: data.method,
      endpoint: data.endpoint,
      ipAddress: data.ipAddress,
      userAgent: data.userAgent,
      beforeState: data.beforeState,
      afterState: data.afterState,
      changes: data.changes,
      metadata: {
        configSection: data.configSection,
        changeType: data.changeType
      }
    });
  }

  /**
   * Get user activity log
   * @param {string} userId - User ID
   * @param {Object} options - Query options
   * @returns {Promise<Array>} - Activity logs
   */
  async getUserActivity(userId, options = {}) {
    const {
      limit = 50,
      skip = 0,
      startDate,
      endDate,
      actions = []
    } = options;

    const query = { userId };

    if (startDate || endDate) {
      query.createdAt = {};
      if (startDate) query.createdAt.$gte = new Date(startDate);
      if (endDate) query.createdAt.$lte = new Date(endDate);
    }

    if (actions.length > 0) {
      query.action = { $in: actions };
    }

    return AuditLog.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .select('-__v');
  }

  /**
   * Get system activity log
   * @param {Object} options - Query options
   * @returns {Promise<Array>} - System logs
   */
  async getSystemActivity(options = {}) {
    const {
      limit = 100,
      skip = 0,
      startDate,
      endDate,
      minSeverity
    } = options;

    const query = {};

    if (startDate || endDate) {
      query.createdAt = {};
      if (startDate) query.createdAt.$gte = new Date(startDate);
      if (endDate) query.createdAt.$lte = new Date(endDate);
    }

    if (minSeverity) {
      query['metadata.severity'] = { $gte: minSeverity };
    }

    return AuditLog.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .select('-__v')
      .populate('userId', 'name email role');
  }

  /**
   * Clean up old audit logs
   * @param {number} days - Days to keep
   * @returns {Promise<Object>} - Deletion result
   */
  async cleanupOldLogs(days = 90) {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - days);

    const result = await AuditLog.deleteMany({
      createdAt: { $lt: cutoffDate }
    });

    logger.info(`Cleaned up ${result.deletedCount} audit logs older than ${days} days`);
    return result;
  }

  /**
   * Export audit logs
   * @param {Object} filter - Filter criteria
   * @param {string} format - Export format
   * @returns {Promise<string>} - Exported data
   */
  async exportLogs(filter = {}, format = 'json') {
    const logs = await AuditLog.find(filter)
      .sort({ createdAt: -1 })
      .populate('userId', 'name email')
      .select('-__v');

    switch (format.toLowerCase()) {
      case 'csv':
        return this.convertToCSV(logs);
      case 'json':
      default:
        return JSON.stringify(logs, null, 2);
    }
  }

  /**
   * Convert logs to CSV
   * @param {Array} logs - Audit logs
   * @returns {string} - CSV data
   */
  convertToCSV(logs) {
    const headers = [
      'Timestamp',
      'Action',
      'User ID',
      'User Email',
      'IP Address',
      'Resource',
      'Method',
      'Status Code',
      'User Agent',
      'Is Suspicious'
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
      log.userAgent?.substring(0, 100) || 'N/A', // Truncate user agent
      log.isSuspicious ? 'Yes' : 'No'
    ]);

    return [headers, ...rows].map(row => row.join(',')).join('\n');
  }

  /**
   * Get statistics
   * @param {Object} options - Query options
   * @returns {Promise<Object>} - Statistics
   */
  async getStatistics(options = {}) {
    const { startDate, endDate } = options;

    const matchStage = {};
    if (startDate || endDate) {
      matchStage.createdAt = {};
      if (startDate) matchStage.createdAt.$gte = new Date(startDate);
      if (endDate) matchStage.createdAt.$lte = new Date(endDate);
    }

    const stats = await AuditLog.aggregate([
      { $match: matchStage },
      {
        $facet: {
          totalActions: [{ $count: 'count' }],
          actionsByType: [
            { $group: { _id: '$action', count: { $sum: 1 } } },
            { $sort: { count: -1 } }
          ],
          suspiciousActivities: [
            { $match: { isSuspicious: true } },
            { $count: 'count' }
          ],
          topUsers: [
            { $match: { userId: { $exists: true } } },
            { $group: { _id: '$userId', count: { $sum: 1 } } },
            { $sort: { count: -1 } },
            { $limit: 10 }
          ],
          topIPs: [
            { $match: { ipAddress: { $exists: true, $ne: null } } },
            { $group: { _id: '$ipAddress', count: { $sum: 1 } } },
            { $sort: { count: -1 } },
            { $limit: 10 }
          ],
          hourlyDistribution: [
            {
              $group: {
                _id: { $hour: '$createdAt' },
                count: { $sum: 1 }
              }
            },
            { $sort: { _id: 1 } }
          ]
        }
      }
    ]);

    return {
      totalActions: stats[0].totalActions[0]?.count || 0,
      actionsByType: stats[0].actionsByType,
      suspiciousActivities: stats[0].suspiciousActivities[0]?.count || 0,
      topUsers: stats[0].topUsers,
      topIPs: stats[0].topIPs,
      hourlyDistribution: stats[0].hourlyDistribution
    };
  }
}

// Create singleton instance
const auditService = new AuditService();

module.exports = auditService;