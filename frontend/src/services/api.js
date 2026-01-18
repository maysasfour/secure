import axios from 'axios';
import DOMPurify from 'dompurify';

// Create axios instance with default config
const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:5000/api',
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 10000, // 10 seconds
});

// Request interceptor for adding auth token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }

    // Sanitize request data to prevent XSS
    if (config.data) {
      config.data = sanitizeData(config.data);
    }

    // Add CSRF token for non-GET requests
    if (config.method !== 'get' && config.method !== 'GET') {
      const csrfToken = getCsrfToken();
      if (csrfToken) {
        config.headers['X-CSRF-Token'] = csrfToken;
      }
    }

    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor for handling errors
api.interceptors.response.use(
  (response) => {
    // Sanitize response data to prevent XSS
    if (response.data) {
      response.data = sanitizeData(response.data);
    }
    return response;
  },
  async (error) => {
    const originalRequest = error.config;

    // Handle token expiration (401)
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      try {
        // Attempt to refresh token
        const refreshToken = localStorage.getItem('refreshToken');
        if (!refreshToken) {
          throw new Error('No refresh token available');
        }

        const response = await axios.post(
          `${import.meta.env.VITE_API_URL || 'http://localhost:5000/api'}/auth/refresh-token`,
          { refreshToken },
          { withCredentials: true }
        );

        const { accessToken } = response.data.data;
        localStorage.setItem('token', accessToken);
        api.defaults.headers.common.Authorization = `Bearer ${accessToken}`;
        originalRequest.headers.Authorization = `Bearer ${accessToken}`;

        return api(originalRequest);
      } catch (refreshError) {
        // Refresh failed, clear tokens and redirect to login
        localStorage.removeItem('token');
        localStorage.removeItem('refreshToken');
        delete api.defaults.headers.common.Authorization;
        window.location.href = '/login';
        return Promise.reject(refreshError);
      }
    }

    // Handle other errors
    if (error.response) {
      // Server responded with error
      const { status, data } = error.response;

      switch (status) {
        case 400:
          console.error('Bad Request:', data);
          break;
        case 403:
          console.error('Forbidden:', data);
          window.location.href = '/unauthorized';
          break;
        case 404:
          console.error('Not Found:', data);
          break;
        case 429:
          console.error('Too Many Requests:', data);
          break;
        case 500:
          console.error('Server Error:', data);
          break;
        default:
          console.error('Error:', data);
      }
    } else if (error.request) {
      // Request made but no response
      console.error('No response received:', error.request);
    } else {
      // Error in request setup
      console.error('Request error:', error.message);
    }

    return Promise.reject(error);
  }
);

// Helper function to sanitize data
const sanitizeData = (data) => {
  if (typeof data === 'string') {
    return DOMPurify.sanitize(data);
  }

  if (Array.isArray(data)) {
    return data.map(item => sanitizeData(item));
  }

  if (data !== null && typeof data === 'object') {
    const sanitized = {};
    for (const key in data) {
      sanitized[key] = sanitizeData(data[key]);
    }
    return sanitized;
  }

  return data;
};

// Helper function to get CSRF token
const getCsrfToken = () => {
  return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
};

// Helper function to validate input
export const validateInput = (input, type) => {
  const validators = {
    email: (value) => {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      return emailRegex.test(value);
    },
    password: (value) => {
      return value.length >= 8 &&
        /[A-Z]/.test(value) &&
        /[a-z]/.test(value) &&
        /\d/.test(value) &&
        /[!@#$%^&*(),.?":{}|<>]/.test(value);
    },
    name: (value) => {
      return value.length >= 2 && value.length <= 50;
    },
    phone: (value) => {
      const phoneRegex = /^[\+]?[1-9][\d]{0,15}$/;
      return phoneRegex.test(value);
    },
    studentId: (value) => {
      return /^[A-Z0-9]{6,10}$/i.test(value);
    }
  };

  const validator = validators[type];
  return validator ? validator(input) : true;
};

// Helper function to format error messages
export const formatError = (error) => {
  if (error.response?.data?.errors) {
    return error.response.data.errors.map(err => err.message).join(', ');
  }
  return error.response?.data?.message || error.message || 'An error occurred';
};

// Export API instance
export default api;