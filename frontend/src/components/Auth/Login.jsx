import React, { useState, useEffect } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { Form, Button, Card, Container, Row, Col, Alert, Spinner } from 'react-bootstrap';
import { useAuth } from '../../services/auth';
import ReCAPTCHA from 'react-google-recaptcha';
import api from '../../services/api';

const Login = () => {
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    rememberMe: false
  });
  const [errors, setErrors] = useState({});
  const [isLoading, setIsLoading] = useState(false);
  const [captchaToken, setCaptchaToken] = useState('');
  const [showCaptcha, setShowCaptcha] = useState(false);
  const [failedAttempts, setFailedAttempts] = useState(0);

  const { login, error: authError, setError } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  // Check for failed attempts in localStorage
  useEffect(() => {
    const attempts = localStorage.getItem('failedLoginAttempts');
    if (attempts) {
      const count = parseInt(attempts);
      setFailedAttempts(count);
      if (count >= 3) {
        setShowCaptcha(true);
      }
    }
  }, []);

  const validateForm = () => {
    const newErrors = {};

    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!formData.email.trim()) {
      newErrors.email = 'Email is required';
    } else if (!emailRegex.test(formData.email)) {
      newErrors.email = 'Please enter a valid email address';
    }

    // Password validation
    if (!formData.password) {
      newErrors.password = 'Password is required';
    }

    // CAPTCHA validation if required
    if (showCaptcha && !captchaToken) {
      newErrors.captcha = 'Please complete the CAPTCHA';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setErrors({});
    setError(null);

    if (!validateForm()) {
      return;
    }

    setIsLoading(true);

    try {
      // Include CAPTCHA token if required
      const loginData = { ...formData };
      if (showCaptcha) {
        loginData.captchaToken = captchaToken;
      }

      const result = await login(formData.email, formData.password);

      if (result.success) {
        // Reset failed attempts on successful login
        localStorage.removeItem('failedLoginAttempts');
        
        // Store remember me preference
        if (formData.rememberMe) {
          localStorage.setItem('rememberMe', 'true');
        }

        // Redirect to intended page or dashboard
        const from = location.state?.from?.pathname || 
                    (result.data.role === 'admin' ? '/admin' : '/dashboard');
        navigate(from, { replace: true });
      } else {
        // Increment failed attempts
        const newAttempts = failedAttempts + 1;
        setFailedAttempts(newAttempts);
        localStorage.setItem('failedLoginAttempts', newAttempts.toString());

        // Show CAPTCHA after 3 failed attempts
        if (newAttempts >= 3) {
          setShowCaptcha(true);
        }

        // Rate limiting check
        if (result.error?.includes('Too many')) {
          setErrors({
            general: 'Too many login attempts. Please try again in 15 minutes.'
          });
        } else {
          setErrors({ general: result.error });
        }
      }
    } catch (error) {
      console.error('Login error:', error);
      setErrors({
        general: error.response?.data?.error || 'An unexpected error occurred'
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleInputChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }));

    // Clear error for this field when user starts typing
    if (errors[name]) {
      setErrors(prev => ({ ...prev, [name]: '' }));
    }
  };

  const handleForgotPassword = () => {
    navigate('/forgot-password');
  };

  return (
    <Container className="py-5">
      <Row className="justify-content-center">
        <Col md={6} lg={5}>
          <Card className="shadow border-0">
            <Card.Body className="p-4">
              <div className="text-center mb-4">
                <h2 className="fw-bold text-primary">
                  <i className="bi bi-shield-lock me-2"></i>
                  Secure Login
                </h2>
                <p className="text-muted">Sign in to your account</p>
              </div>

              {errors.general && (
                <Alert variant="danger" className="text-center">
                  <i className="bi bi-exclamation-triangle me-2"></i>
                  {errors.general}
                </Alert>
              )}

              {authError && !errors.general && (
                <Alert variant="danger" className="text-center">
                  <i className="bi bi-exclamation-triangle me-2"></i>
                  {authError}
                </Alert>
              )}

              <Form onSubmit={handleSubmit} noValidate>
                <Form.Group className="mb-3">
                  <Form.Label>Email Address</Form.Label>
                  <Form.Control
                    type="email"
                    name="email"
                    value={formData.email}
                    onChange={handleInputChange}
                    isInvalid={!!errors.email}
                    placeholder="Enter your email"
                    autoComplete="email"
                    disabled={isLoading}
                  />
                  <Form.Control.Feedback type="invalid">
                    {errors.email}
                  </Form.Control.Feedback>
                </Form.Group>

                <Form.Group className="mb-3">
                  <Form.Label>Password</Form.Label>
                  <Form.Control
                    type="password"
                    name="password"
                    value={formData.password}
                    onChange={handleInputChange}
                    isInvalid={!!errors.password}
                    placeholder="Enter your password"
                    autoComplete="current-password"
                    disabled={isLoading}
                  />
                  <Form.Control.Feedback type="invalid">
                    {errors.password}
                  </Form.Control.Feedback>
                </Form.Group>

                <Form.Group className="mb-3">
                  <Form.Check
                    type="checkbox"
                    name="rememberMe"
                    label="Remember me"
                    checked={formData.rememberMe}
                    onChange={handleInputChange}
                    disabled={isLoading}
                  />
                </Form.Group>

                {showCaptcha && (
                  <Form.Group className="mb-3">
                    <ReCAPTCHA
                      sitekey={process.env.REACT_APP_RECAPTCHA_SITE_KEY}
                      onChange={(token) => setCaptchaToken(token)}
                      onExpired={() => setCaptchaToken('')}
                    />
                    {errors.captcha && (
                      <div className="text-danger small mt-2">{errors.captcha}</div>
                    )}
                  </Form.Group>
                )}

                <div className="d-grid mb-3">
                  <Button
                    variant="primary"
                    type="submit"
                    disabled={isLoading}
                    size="lg"
                  >
                    {isLoading ? (
                      <>
                        <Spinner
                          as="span"
                          animation="border"
                          size="sm"
                          role="status"
                          aria-hidden="true"
                          className="me-2"
                        />
                        Signing in...
                      </>
                    ) : (
                      'Sign In'
                    )}
                  </Button>
                </div>

                <div className="text-center mb-3">
                  <Button
                    variant="link"
                    onClick={handleForgotPassword}
                    className="text-decoration-none"
                    disabled={isLoading}
                  >
                    Forgot your password?
                  </Button>
                </div>

                <div className="text-center">
                  <p className="mb-0">
                    Don't have an account?{' '}
                    <Link
                      to="/register"
                      className="text-decoration-none fw-semibold"
                    >
                      Sign up here
                    </Link>
                  </p>
                </div>
              </Form>

              <div className="mt-4 pt-3 border-top">
                <div className="text-center">
                  <small className="text-muted">
                    <i className="bi bi-shield-check me-1"></i>
                    Your login is secured with encryption and rate limiting
                  </small>
                </div>
              </div>
            </Card.Body>
          </Card>

          {/* Security Information */}
          <Card className="mt-4 border-0 shadow-sm">
            <Card.Body>
              <h6 className="fw-bold mb-3">
                <i className="bi bi-info-circle me-2"></i>
                Security Information
              </h6>
              <ul className="list-unstyled small mb-0">
                <li className="mb-2">
                  <i className="bi bi-check-circle text-success me-2"></i>
                  All connections are secured with HTTPS/TLS
                </li>
                <li className="mb-2">
                  <i className="bi bi-check-circle text-success me-2"></i>
                  Passwords are hashed using bcrypt
                </li>
                <li className="mb-2">
                  <i className="bi bi-check-circle text-success me-2"></i>
                  Rate limiting protects against brute force attacks
                </li>
                <li className="mb-2">
                  <i className="bi bi-check-circle text-success me-2"></i>
                  CAPTCHA required after multiple failed attempts
                </li>
                <li>
                  <i className="bi bi-check-circle text-success me-2"></i>
                  Session timeout after 15 minutes of inactivity
                </li>
              </ul>
            </Card.Body>
          </Card>
        </Col>
      </Row>
    </Container>
  );
};

export default Login;