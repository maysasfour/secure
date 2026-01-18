const constants = {

  ROLES: {
    ADMIN: 'admin',
    STUDENT: 'student',
    FACULTY: 'faculty'
  },
  

  TOKEN_EXPIRY: {
    ACCESS_TOKEN: '15m',
    REFRESH_TOKEN: '7d',
    RESET_TOKEN: '10m'
  },
  

  SECURITY: {
    BCRYPT_ROUNDS: 12,
    PASSWORD_MIN_LENGTH: 8,
    MAX_LOGIN_ATTEMPTS: 5,
    LOCKOUT_TIME: 15 * 60 * 1000,
    SESSION_TIMEOUT: 24 * 60 * 60 * 1000
  },
 
  RATE_LIMITS: {
    AUTH: { windowMs: 15 * 60 * 1000, max: 5 },
    API: { windowMs: 60 * 1000, max: 100 },
    REGISTER: { windowMs: 60 * 60 * 1000, max: 3 }
  },
  

  FILE: {
    MAX_SIZE: 5 * 1024 * 1024,
    ALLOWED_TYPES: ['image/jpeg', 'image/png', 'application/pdf'],
    UPLOAD_PATH: 'uploads/'
  },
  

  AUDIT_ACTIONS: {
    LOGIN: 'LOGIN',
    LOGOUT: 'LOGOUT',
    CREATE: 'CREATE',
    UPDATE: 'UPDATE',
    DELETE: 'DELETE',
    ACCESS: 'ACCESS',
    FAILED_LOGIN: 'FAILED_LOGIN'
  },
  
 
  MESSAGES: {
    SUCCESS: {
      REGISTER: 'Registration successful. Please verify your email.',
      LOGIN: 'Login successful.',
      LOGOUT: 'Logout successful.',
      UPDATE: 'Update successful.',
      DELETE: 'Delete successful.'
    },
    ERROR: {
      UNAUTHORIZED: 'Unauthorized access.',
      FORBIDDEN: 'You do not have permission to access this resource.',
      NOT_FOUND: 'Resource not found.',
      VALIDATION_ERROR: 'Validation error.',
      SERVER_ERROR: 'Internal server error.',
      INVALID_CREDENTIALS: 'Invalid email or password.',
      ACCOUNT_LOCKED: 'Account is temporarily locked. Try again later.',
      TOKEN_EXPIRED: 'Token has expired.',
      TOKEN_INVALID: 'Invalid token.'
    }
  }
};

module.exports = constants;