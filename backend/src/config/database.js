const mongoose = require('mongoose');
const logger = require('../utils/logger');


class Database {
  constructor() {
    this.mongoose = mongoose;
    this.isConnected = false;
  }

  async connect() {
    try {
      // Use appropriate URI based on environment
      const mongoURI = process.env.NODE_ENV === 'test' 
        ? process.env.MONGODB_URI_TEST 
        : process.env.MONGODB_URI;

      if (!mongoURI) {
        throw new Error('MongoDB URI is not defined in environment variables');
      }

      // Connection options for better performance and security
      const options = {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        serverSelectionTimeoutMS: 30000, // 30 seconds timeout
        socketTimeoutMS: 45000, // 45 seconds socket timeout
        maxPoolSize: 10, // Maximum number of connections in pool
        minPoolSize: 5, // Minimum number of connections in pool
        maxIdleTimeMS: 30000, // Close idle connections after 30 seconds
        retryWrites: true,
        w: 'majority'
      };

      // Add authentication if username/password exists in URI
      if (mongoURI.includes('@')) {
        logger.info('Connecting to MongoDB Atlas with authentication...');
      } else {
        logger.info('Connecting to local MongoDB...');
      }

      // Connect to MongoDB
      await this.mongoose.connect(mongoURI, options);
      
      this.isConnected = true;
      
      const conn = this.mongoose.connection;
      logger.info(`✅ MongoDB Connected Successfully: ${conn.host}`);
      logger.info(`📊 Database: ${conn.name}`);
      logger.info(`👤 User: ${mongoURI.split('://')[1].split(':')[0]}`);
      
      // Set up event listeners
      this.setupEventListeners();
      
      return conn;
    } catch (error) {
      logger.error('❌ MongoDB Connection Error:', error.message);
      logger.error('Connection URI (masked):', this.maskMongoURI(process.env.MONGODB_URI));
      
      // Retry logic for production
      if (process.env.NODE_ENV === 'production') {
        logger.info('Retrying connection in 5 seconds...');
        setTimeout(() => this.connect(), 5000);
      } else {
        process.exit(1);
      }
    }
  }

  maskMongoURI(uri) {
    if (!uri) return 'Not configured';
    return uri.replace(/\/\/(.*):(.*)@/, '//***:***@');
  }

  setupEventListeners() {
    const conn = this.mongoose.connection;

    // Connection events
    conn.on('connected', () => {
      logger.info('✅ MongoDB connected');
      this.isConnected = true;
    });

    conn.on('error', (err) => {
      logger.error('❌ MongoDB connection error:', err.message);
      this.isConnected = false;
    });

    conn.on('disconnected', () => {
      logger.warn('⚠️ MongoDB disconnected');
      this.isConnected = false;
      
      // Attempt reconnection
      if (process.env.NODE_ENV === 'production') {
        logger.info('Attempting to reconnect to MongoDB...');
        setTimeout(() => this.connect(), 5000);
      }
    });

    conn.on('reconnected', () => {
      logger.info('✅ MongoDB reconnected');
      this.isConnected = true;
    });

    // Mongoose events
    this.mongoose.connection.on('open', () => {
      logger.debug('🔓 Mongoose connection opened');
    });

    this.mongoose.connection.on('close', () => {
      logger.debug('🔒 Mongoose connection closed');
    });

    // Process events for graceful shutdown
    process.on('SIGINT', async () => {
      await this.close();
      process.exit(0);
    });

    process.on('SIGTERM', async () => {
      await this.close();
      process.exit(0);
    });
  }

  async close() {
    try {
      if (this.isConnected) {
        await this.mongoose.connection.close();
        logger.info('✅ MongoDB connection closed gracefully');
        this.isConnected = false;
      }
    } catch (error) {
      logger.error('❌ Error closing MongoDB connection:', error);
    }
  }

  getConnectionStatus() {
    return {
      isConnected: this.isConnected,
      readyState: this.mongoose.connection.readyState,
      host: this.mongoose.connection.host,
      name: this.mongoose.connection.name,
      models: Object.keys(this.mongoose.connection.models),
      collections: Object.keys(this.mongoose.connection.collections)
    };
  }

  // Health check method
  async healthCheck() {
    try {
      // Run a simple command to check database health
      await this.mongoose.connection.db.admin().ping();
      return {
        status: 'healthy',
        database: 'connected',
        responseTime: Date.now()
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        database: 'disconnected',
        error: error.message,
        responseTime: Date.now()
      };
    }
  }

  // Get database statistics
  async getStats() {
    try {
      const adminDb = this.mongoose.connection.db.admin();
      const serverStatus = await adminDb.serverStatus();
      const dbStats = await this.mongoose.connection.db.stats();
      
      return {
        version: serverStatus.version,
        host: serverStatus.host,
        uptime: serverStatus.uptime,
        connections: serverStatus.connections,
        memory: serverStatus.mem,
        network: serverStatus.network,
        database: {
          collections: dbStats.collections,
          objects: dbStats.objects,
          avgObjSize: dbStats.avgObjSize,
          dataSize: dbStats.dataSize,
          storageSize: dbStats.storageSize,
          indexSize: dbStats.indexSize,
          indexes: dbStats.indexes
        }
      };
    } catch (error) {
      logger.error('Error getting database stats:', error);
      return null;
    }
  }
}

// Create and export singleton instance
const database = new Database();

module.exports = database;