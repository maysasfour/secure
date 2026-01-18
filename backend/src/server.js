const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const cookieParser = require('cookie-parser');
const compression = require('compression');
const morgan = require('morgan');
const path = require('path');

// Load environment variables
require('dotenv').config();

// Import configurations
const connectDatabase = require('./config/database');
const securityConfig = require('./config/security');
const constants = require('./config/constants');

// Import middleware
const { errorHandler, notFoundHandler } = require('./middleware/errorHandler');

// Import routes
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');
const adminRoutes = require('./routes/adminRoutes');
const apiRoutes = require('./routes/apiRoutes');

// Import utils
const logger = require('./utils/logger');

// Initialize Express app
const app = express();

// Connect to database
connectDatabase();

// Security middleware
app.use(helmet(securityConfig.helmet));
app.use(securityConfig.cors);
app.use(securityConfig.mongoSanitize);
app.use(securityConfig.xss);
app.use(securityConfig.hpp);

// Rate limiting
app.use('/api/auth', securityConfig.rateLimiters.auth);
app.use('/api', securityConfig.rateLimiters.api);

// Body parser
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

// Compression
app.use(compression());

// HTTP request logging
app.use(morgan('combined', { stream: logger.stream }));

// Custom request logging
app.use(logger.logRequest);

// Serve static files in production
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, '../frontend/build')));
}

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api', apiRoutes);

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV,
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

// API documentation endpoint
app.get('/api-docs', (req, res) => {
  res.json({
    name: 'Secure Campus Portal API',
    version: '1.0.0',
    endpoints: {
      auth: {
        login: 'POST /api/auth/login',
        register: 'POST /api/auth/register',
        logout: 'POST /api/auth/logout',
        refreshToken: 'POST /api/auth/refresh-token',
        forgotPassword: 'POST /api/auth/forgot-password',
        resetPassword: 'PATCH /api/auth/reset-password/:token',
        changePassword: 'PATCH /api/auth/change-password',
        getMe: 'GET /api/auth/me',
        updateMe: 'PATCH /api/auth/update-me',
        deactivate: 'DELETE /api/auth/deactivate'
      },
      users: {
        getAllUsers: 'GET /api/users (Admin only)',
        getUser: 'GET /api/users/:id',
        createUser: 'POST /api/users (Admin only)',
        updateUser: 'PATCH /api/users/:id',
        deleteUser: 'DELETE /api/users/:id (Admin only)',
        getUserSessions: 'GET /api/users/:id/sessions',
        revokeUserSession: 'DELETE /api/users/:userId/sessions/:sessionId',
        revokeAllSessions: 'DELETE /api/users/:id/sessions',
        getUserAuditLogs: 'GET /api/users/:id/audit-logs (Admin only)',
        getUserStats: 'GET /api/users/stats (Admin only)'
      },
      admin: {
        dashboard: 'GET /api/admin/dashboard',
        auditLogs: 'GET /api/admin/audit-logs',
        exportAuditLogs: 'GET /api/admin/export-audit-logs',
        securityInsights: 'GET /api/admin/security-insights',
        sessions: 'GET /api/admin/sessions',
        lockUser: 'PATCH /api/admin/users/:id/lock',
        forcePasswordReset: 'POST /api/admin/users/:id/force-password-reset'
      },
      data: {
        createData: 'POST /api/data',
        getAllData: 'GET /api/data',
        getData: 'GET /api/data/:id',
        updateData: 'PUT /api/data/:id',
        deleteData: 'DELETE /api/data/:id',
        verifyData: 'POST /api/data/:id/verify',
        encryptText: 'POST /api/data/encrypt-text',
        decryptText: 'POST /api/data/decrypt-text',
        encryptionStatus: 'GET /api/data/encryption-status'
      }
    }
  });
});

// Serve frontend in production
if (process.env.NODE_ENV === 'production') {
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/build/index.html'));
  });
}

// 404 handler
app.use(notFoundHandler);

// Global error handler
app.use(errorHandler);

// Handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
  logger.error('UNHANDLED REJECTION! 💥 Shutting down...', err);
  process.exit(1);
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  logger.error('UNCAUGHT EXCEPTION! 💥 Shutting down...', err);
  process.exit(1);
});

// Start server
const PORT = process.env.PORT || 5000;
const server = app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT} in ${process.env.NODE_ENV} mode`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received. Shutting down gracefully...');
  server.close(() => {
    logger.info('Process terminated!');
    mongoose.connection.close(false, () => {
      process.exit(0);
    });
  });
});

module.exports = app;