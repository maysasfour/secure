import React, { useEffect, useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { Container } from 'react-bootstrap';
import { HelmetProvider } from 'react-helmet-async';
import { ToastContainer } from 'react-toastify';
import 'bootstrap/dist/css/bootstrap.min.css';
import 'react-toastify/dist/ReactToastify.css';

// Components
import Navbar from './components/Common/Navbar';
import Footer from './components/Common/Footer';
import ProtectedRoute from './components/Common/ProtectedRoute';

// Pages
import Login from './components/Auth/Login';
import Register from './components/Auth/Register';
import ForgotPassword from './components/Auth/ForgotPassword';
import StudentDashboard from './components/Dashboard/StudentDashboard';
import AdminDashboard from './components/Dashboard/AdminDashboard';
import Profile from './components/Dashboard/Profile';

// Services
import { AuthProvider } from './services/auth';
import api from './services/api';

// Styles
import './App.css';

function App() {
  const [loading, setLoading] = useState(true);
  const [user, setUser] = useState(null);

  useEffect(() => {
    // Check if user is already logged in
    const token = localStorage.getItem('token');
    if (token) {
      api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      // Fetch user data
      api.get('/api/auth/me')
        .then(response => {
          setUser(response.data.data.user);
        })
        .catch(() => {
          localStorage.removeItem('token');
          delete api.defaults.headers.common['Authorization'];
        })
        .finally(() => {
          setLoading(false);
        });
    } else {
      setLoading(false);
    }
  }, []);

  const handleLogin = (userData, token) => {
    localStorage.setItem('token', token);
    api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
    setUser(userData);
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    delete api.defaults.headers.common['Authorization'];
    setUser(null);
  };

  if (loading) {
    return (
      <div className="loading-screen">
        <div className="spinner-border text-primary" role="status">
          <span className="visually-hidden">Loading...</span>
        </div>
      </div>
    );
  }

  return (
    <HelmetProvider>
      <AuthProvider value={{ user, handleLogin, handleLogout }}>
        <Router>
          <div className="app-container">
            <Navbar />
            <Container fluid className="main-content">
              <Routes>
                {/* Public routes */}
                <Route path="/login" element={
                  user ? <Navigate to={user.role === 'admin' ? '/admin' : '/dashboard'} /> : <Login onLogin={handleLogin} />
                } />
                <Route path="/register" element={
                  user ? <Navigate to="/dashboard" /> : <Register />
                } />
                <Route path="/forgot-password" element={<ForgotPassword />} />

                {/* Protected routes */}
                <Route path="/dashboard" element={
                  <ProtectedRoute>
                    <StudentDashboard />
                  </ProtectedRoute>
                } />
                <Route path="/admin" element={
                  <ProtectedRoute requiredRole="admin">
                    <AdminDashboard />
                  </ProtectedRoute>
                } />
                <Route path="/profile" element={
                  <ProtectedRoute>
                    <Profile />
                  </ProtectedRoute>
                } />

                {/* Default redirect */}
                <Route path="/" element={
                  user ? (
                    <Navigate to={user.role === 'admin' ? '/admin' : '/dashboard'} />
                  ) : (
                    <Navigate to="/login" />
                  )
                } />

                {/* 404 route */}
                <Route path="*" element={
                  <div className="text-center mt-5">
                    <h1>404 - Page Not Found</h1>
                    <p>The page you are looking for does not exist.</p>
                  </div>
                } />
              </Routes>
            </Container>
            <Footer />
            <ToastContainer
              position="top-right"
              autoClose={5000}
              hideProgressBar={false}
              newestOnTop
              closeOnClick
              rtl={false}
              pauseOnFocusLoss
              draggable
              pauseOnHover
              theme="light"
            />
          </div>
        </Router>
      </AuthProvider>
    </HelmetProvider>
  );
}

export default App;