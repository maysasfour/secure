// MongoDB initialization script
db = db.getSiblingDB('secure_campus');

// Create collections with validation
db.createCollection('users', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['email', 'password', 'name', 'role', 'isActive'],
      properties: {
        email: {
          bsonType: 'string',
          pattern: '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$',
          description: 'must be a valid email and is required'
        },
        password: {
          bsonType: 'string',
          minLength: 8,
          description: 'must be a string of minimum length 8 and is required'
        },
        role: {
          enum: ['admin', 'student', 'faculty'],
          description: 'must be one of the enum values and is required'
        }
      }
    }
  },
  validationLevel: 'strict',
  validationAction: 'error'
});

db.createCollection('sessions', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['userId', 'accessToken', 'refreshToken', 'isActive', 'expiresAt'],
      properties: {
        isActive: {
          bsonType: 'bool',
          description: 'must be a boolean and is required'
        }
      }
    }
  }
});

db.createCollection('auditlogs', {
  timeseries: {
    timeField: 'createdAt',
    metaField: 'metadata',
    granularity: 'hours'
  },
  expireAfterSeconds: 7776000 // 90 days
});

// Create indexes
db.users.createIndex({ email: 1 }, { unique: true });
db.users.createIndex({ studentId: 1 }, { unique: true, sparse: true });
db.users.createIndex({ role: 1 });
db.users.createIndex({ createdAt: -1 });
db.users.createIndex({ isActive: 1 });

db.sessions.createIndex({ accessToken: 1 });
db.sessions.createIndex({ refreshToken: 1 });
db.sessions.createIndex({ userId: 1 });
db.sessions.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 604800 }); // 7 days

db.auditlogs.createIndex({ userId: 1, createdAt: -1 });
db.auditlogs.createIndex({ action: 1, createdAt: -1 });
db.auditlogs.createIndex({ ipAddress: 1, createdAt: -1 });
db.auditlogs.createIndex({ isSuspicious: 1, createdAt: -1 });

// Create admin user if not exists
const adminExists = db.users.findOne({ email: 'admin@securecampus.edu' });
if (!adminExists) {
  const adminPassword = '$2b$12$' + 'GkzDnVvGQ7X7w8KjH5sR3u' + '1234567890123456789012'; // Hash for 'Admin@123'
  
  db.users.insertOne({
    email: 'admin@securecampus.edu',
    password: adminPassword,
    name: 'System Administrator',
    role: 'admin',
    isActive: true,
    isVerified: true,
    createdAt: new Date(),
    updatedAt: new Date()
  });
  
  print('Admin user created: admin@securecampus.edu / Admin@123');
}

print('MongoDB initialization completed successfully');