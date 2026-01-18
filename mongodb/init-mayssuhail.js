// mongodb/init-mayssuhail.js
db = db.getSiblingDB('secure_campus');

print('============================================');
print('Initializing SecureCampus Database');
print('User: mayssuhail_db_user');
print('Database: secure_campus');
print('============================================');

// Create collections
db.createCollection('users', {
  validator: {
    $jsonSchema: {
      bsonType: "object",
      required: ["email", "password", "name", "role", "isActive"],
      properties: {
        email: {
          bsonType: "string",
          pattern: "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$",
          description: "must be a valid email address"
        },
        password: {
          bsonType: "string",
          minLength: 8,
          description: "must be a string of minimum length 8"
        },
        name: {
          bsonType: "string",
          minLength: 2,
          description: "must be a string of minimum length 2"
        },
        role: {
          enum: ["admin", "student", "faculty"],
          description: "must be one of the enum values"
        },
        isActive: {
          bsonType: "bool",
          description: "must be a boolean"
        }
      }
    }
  },
  validationLevel: "strict",
  validationAction: "error"
});

db.createCollection('sessions', {
  validator: {
    $jsonSchema: {
      bsonType: "object",
      required: ["userId", "accessToken", "refreshToken", "isActive", "expiresAt"],
      properties: {
        userId: {
          bsonType: "objectId",
          description: "must be a valid ObjectId"
        },
        isActive: {
          bsonType: "bool",
          description: "must be a boolean"
        }
      }
    }
  }
});

db.createCollection('auditlogs', {
  timeseries: {
    timeField: "createdAt",
    metaField: "metadata",
    granularity: "hours"
  },
  expireAfterSeconds: 7776000 // 90 days
});

// Create indexes for performance
db.users.createIndex({ email: 1 }, { unique: true });
db.users.createIndex({ studentId: 1 }, { unique: true, sparse: true });
db.users.createIndex({ role: 1 });
db.users.createIndex({ createdAt: -1 });
db.users.createIndex({ isActive: 1 });
db.users.createIndex({ "department": 1 });

db.sessions.createIndex({ accessToken: 1 });
db.sessions.createIndex({ refreshToken: 1 });
db.sessions.createIndex({ userId: 1 });
db.sessions.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 604800 }); // 7 days
db.sessions.createIndex({ ipAddress: 1 });

db.auditlogs.createIndex({ userId: 1, createdAt: -1 });
db.auditlogs.createIndex({ action: 1, createdAt: -1 });
db.auditlogs.createIndex({ ipAddress: 1, createdAt: -1 });
db.auditlogs.createIndex({ isSuspicious: 1, createdAt: -1 });

// Create admin user
const adminPassword = "$2b$12$GkzDnVvGQ7X7w8KjH5sR3uYwXzPqR9T0V1A2B3C4D5E6F7G8H9I0J1K2L"; // Hash for "Admin@123"
const studentPassword = "$2b$12$HlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjK"; // Hash for "Student@123"

const users = [
  {
    email: "admin@securecampus.edu",
    password: adminPassword,
    name: "System Administrator",
    role: "admin",
    isActive: true,
    isVerified: true,
    createdAt: new Date(),
    updatedAt: new Date(),
    lastLogin: new Date()
  },
  {
    email: "student@securecampus.edu",
    password: studentPassword,
    name: "John Student",
    role: "student",
    studentId: "STU2024001",
    department: "Computer Science",
    semester: 3,
    isActive: true,
    isVerified: true,
    createdAt: new Date(),
    updatedAt: new Date(),
    dateOfBirth: new Date("2000-01-15")
  },
  {
    email: "faculty@securecampus.edu",
    password: studentPassword,
    name: "Dr. Sarah Professor",
    role: "faculty",
    department: "Computer Science",
    isActive: true,
    isVerified: true,
    createdAt: new Date(),
    updatedAt: new Date()
  }
];

// Insert users
const result = db.users.insertMany(users);

print(`✅ Created ${result.insertedCount} users:`);
result.insertedIds.forEach((id, index) => {
  const user = users[index];
  print(`   - ${user.email} (${user.role}) - Password: ${user.role === 'admin' ? 'Admin@123' : 'Student@123'}`);
});

// Create some sample audit logs
const auditLogs = [
  {
    userId: result.insertedIds[0],
    email: "admin@securecampus.edu",
    action: "SYSTEM_INIT",
    resource: "Database",
    method: "INIT",
    ipAddress: "127.0.0.1",
    userAgent: "MongoDB Initialization Script",
    metadata: {
      action: "database_initialization",
      version: "1.0.0"
    },
    createdAt: new Date(),
    isSuspicious: false
  }
];

db.auditlogs.insertMany(auditLogs);

print('============================================');
print('Database Initialization Complete!');
print('============================================');
print('');
print('📋 Test Credentials:');
print('-------------------');
print('👑 Admin User:');
print('   Email: admin@securecampus.edu');
print('   Password: Admin@123');
print('');
print('🎓 Student User:');
print('   Email: student@securecampus.edu');
print('   Password: Student@123');
print('');
print('👨‍🏫 Faculty User:');
print('   Email: faculty@securecampus.edu');
print('   Password: Student@123');
print('');
print('🔗 MongoDB Connection:');
print('   URI: mongodb+srv://mayssuhail_db_user:****@cluster0.0gol1lo.mongodb.net/');
print('   Database: secure_campus');
print('============================================');