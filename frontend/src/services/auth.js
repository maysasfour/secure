import { createContext, useContext, useState, useEffect } from 'react';
import api from './api';
import jwtDecode from 'jwt-decode';

const AuthContext = createContext(null);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    // Check for existing token on mount
    const token = localStorage.getItem('token');
    if (token) {
      // Validate token expiration
      try {
        const decoded = jwtDecode(token);
        const currentTime = Date.now() / 1000;
        
        if (decoded.exp < currentTime) {
          // Token expired, try to refresh
          refreshToken();
        } else {
          // Token valid, set user
          setUser(decoded);
          setLoading(false);
        }
      } catch (error) {
        console.error('Invalid token:', error);
        localStorage.removeItem('token');
        localStorage.removeItem('refreshToken');
        setLoading(false);
      }
    } else {
      setLoading(false);
    }
  }, []);

  const refreshToken = async () => {
    try {
      const refreshToken = localStorage.getItem('refreshToken');
      if (!refreshToken) {
        throw new Error('No refresh token available');
      }

      const response = await api.post('/auth/refresh-token', {
        refreshToken
      });

      const { accessToken } = response.data.data;
      localStorage.setItem('token', accessToken);
      api.defaults.headers.common['Authorization'] = `Bearer ${accessToken}`;
      
      const decoded = jwtDecode(accessToken);
      setUser(decoded);
    } catch (error) {
      console.error('Token refresh failed:', error);
      logout();
    }
  };

  const login = async (email, password) => {
    try {
      setError(null);
      const response = await api.post('/auth/login', {
        email,
        password
      });

      const { user: userData, accessToken } = response.data.data;
      
      // Store tokens
      localStorage.setItem('token', accessToken);
      api.defaults.headers.common['Authorization'] = `Bearer ${accessToken}`;
      
      setUser(userData);
      return { success: true, data: userData };
    } catch (error) {
      setError(error.response?.data?.error || 'Login failed');
      return { success: false, error: error.response?.data?.error || 'Login failed' };
    }
  };

  const register = async (userData) => {
    try {
      setError(null);
      const response = await api.post('/auth/register', userData);

      const { user: newUser, accessToken } = response.data.data;
      
      localStorage.setItem('token', accessToken);
      api.defaults.headers.common['Authorization'] = `Bearer ${accessToken}`;
      
      setUser(newUser);
      return { success: true, data: newUser };
    } catch (error) {
      setError(error.response?.data?.error || 'Registration failed');
      return { success: false, error: error.response?.data?.error || 'Registration failed' };
    }
  };

  const logout = async () => {
    try {
      await api.post('/auth/logout');
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      // Clear local storage
      localStorage.removeItem('token');
      localStorage.removeItem('refreshToken');
      delete api.defaults.headers.common['Authorization'];
      
      // Reset state
      setUser(null);
      setError(null);
    }
  };

  const forgotPassword = async (email) => {
    try {
      setError(null);
      const response = await api.post('/auth/forgot-password', { email });
      return { success: true, message: response.data.message };
    } catch (error) {
      setError(error.response?.data?.error || 'Password reset request failed');
      return { success: false, error: error.response?.data?.error || 'Password reset request failed' };
    }
  };

  const resetPassword = async (token, newPassword) => {
    try {
      setError(null);
      const response = await api.patch(`/auth/reset-password/${token}`, {
        password: newPassword
      });
      return { success: true, message: response.data.message };
    } catch (error) {
      setError(error.response?.data?.error || 'Password reset failed');
      return { success: false, error: error.response?.data?.error || 'Password reset failed' };
    }
  };

  const changePassword = async (currentPassword, newPassword) => {
    try {
      setError(null);
      const response = await api.patch('/auth/change-password', {
        currentPassword,
        newPassword
      });
      return { success: true, message: response.data.message };
    } catch (error) {
      setError(error.response?.data?.error || 'Password change failed');
      return { success: false, error: error.response?.data?.error || 'Password change failed' };
    }
  };

  const updateProfile = async (profileData) => {
    try {
      setError(null);
      const response = await api.patch('/auth/update-me', profileData);
      setUser(response.data.data.user);
      return { success: true, data: response.data.data.user };
    } catch (error) {
      setError(error.response?.data?.error || 'Profile update failed');
      return { success: false, error: error.response?.data?.error || 'Profile update failed' };
    }
  };

  const deactivateAccount = async () => {
    try {
      setError(null);
      await api.delete('/auth/deactivate');
      logout();
      return { success: true, message: 'Account deactivated successfully' };
    } catch (error) {
      setError(error.response?.data?.error || 'Account deactivation failed');
      return { success: false, error: error.response?.data?.error || 'Account deactivation failed' };
    }
  };

  const isAuthenticated = () => {
    return !!user;
  };

  const hasRole = (role) => {
    return user?.role === role;
  };

  const value = {
    user,
    loading,
    error,
    login,
    register,
    logout,
    forgotPassword,
    resetPassword,
    changePassword,
    updateProfile,
    deactivateAccount,
    isAuthenticated,
    hasRole,
    setError
  };

  return (
    <AuthContext.Provider value={value}>
      {!loading && children}
    </AuthContext.Provider>
  );
};