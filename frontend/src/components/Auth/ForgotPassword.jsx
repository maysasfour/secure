import React, { useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { 
  Form, 
  Button, 
  Card, 
  Container, 
  Row, 
  Col, 
  Alert, 
  Spinner 
} from 'react-bootstrap';
import { useAuth } from '../../services/auth';
import { validatePassword } from '../../utils/validation';

const ForgotPassword = () => {
  const [step, setStep] = useState(1); // 1: Request reset, 2: Reset password
  const [email, setEmail] = useState('');
  const [resetToken, setResetToken] = useState('');
  const [passwordData, setPasswordData] = useState({
    password: '',
    confirmPassword: ''
  });
  const [passwordStrength, setPasswordStrength] = useState({
    score: 0,
    suggestions: []
  });
  const [errors, setErrors] = useState({});
  const [successMessage, setSuccessMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const { forgotPassword, resetPassword, error: authError, setError } = useAuth();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  // Check for reset token in URL
  React.useEffect(() => {
    const token = searchParams.get('token');
    if (token) {
      setResetToken(token);
      setStep(2);
    }
  }, [searchParams]);

  // Password strength calculation
  React.useEffect(() => {
    if (passwordData.password) {
      const strength = validatePassword(passwordData.password);
      setPasswordStrength(strength);
    } else {
      setPasswordStrength({ score: 0, suggestions: [] });
    }
  }, [passwordData.password]);

  const validateStep1 = () => {
    const newErrors = {};
    
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email.trim()) {
      newErrors.email = 'Email is required';
    } else if (!emailRegex.test(email)) {
      newErrors.email = 'Please enter a valid email address';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const validateStep2 = () => {
    const newErrors = {};

    if (!resetToken) {
      newErrors.general = 'Reset token is missing';
    }

    if (!passwordData.password) {
      newErrors.password = 'Password is required';
    } else if (passwordStrength.score < 60) {
      newErrors.password = 'Password is too weak';
    }

    if (!passwordData.confirmPassword) {
      newErrors.confirmPassword = 'Please confirm your password';
    } else if (passwordData.password !== passwordData.confirmPassword) {
      newErrors.confirmPassword = 'Passwords do not match';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleRequestReset = async (e) => {
    e.preventDefault();
    setErrors({});
    setError(null);
    setSuccessMessage('');

    if (!validateStep1()) {
      return;
    }

    setIsLoading(true);

    try {
      const result = await forgotPassword(email);

      if (result.success) {
        setSuccessMessage(result.message || 'Password reset link sent to your email');
        setEmail('');
      } else {
        setErrors({ general: result.error });
      }
    } catch (error) {
      console.error('Request reset error:', error);
      setErrors({
        general: error.response?.data?.error || 'An unexpected error occurred'
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleResetPassword = async (e) => {
    e.preventDefault();
    setErrors({});
    setError(null);
    setSuccessMessage('');

    if (!validateStep2()) {
      return;
    }

    setIsLoading(true);

    try {
      const result = await resetPassword(resetToken, passwordData.password);

      if (result.success) {
        setSuccessMessage(result.message || 'Password reset successfully!');
        
        // Clear form
        setPasswordData({
          password: '',
          confirmPassword: ''
        });
        
        // Redirect to login after 3 seconds
        setTimeout(() => {
          navigate('/login');
        }, 3000);
      } else {
        setErrors({ general: result.error });
      }
    } catch (error) {
      console.error('Reset password error:', error);
      setErrors({
        general: error.response?.data?.error || 'An unexpected error occurred'
      });
    } finally {
      setIsLoading(false);
    }
  };

  const getPasswordStrengthColor = () => {
    if (passwordStrength.score >= 80) return 'success';
    if (passwordStrength.score >= 60) return 'warning';
    return 'danger';
  };

  const getPasswordStrengthLabel = () => {
    if (passwordStrength.score >= 80) return 'Strong';
    if (passwordStrength.score >= 60) return 'Good';
    if (passwordStrength.score >= 40) return 'Fair';
    if (passwordStrength.score >= 20) return 'Weak';
    return 'Very Weak';
  };

  return (
    <Container className="py-5">
      <Row className="justify-content-center">
        <Col md={6} lg={5}>
          <Card className="shadow border-0">
            <Card.Body className="p-4">
              <div className="text-center mb-4">
                <h2 className="fw-bold text-primary">
                  <i className="bi bi-key me-2"></i>
                  {step === 1 ? 'Reset Password' : 'Create New Password'}
                </h2>
                <p className="text-muted">
                  {step === 1 
                    ? 'Enter your email to receive a reset link' 
                    : 'Create a new secure password'}
                </p>
              </div>

              {successMessage && (
                <Alert variant="success" className="text-center">
                  <i className="bi bi-check-circle me-2"></i>
                  {successMessage}
                </Alert>
              )}

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

              {step === 1 ? (
                <Form onSubmit={handleRequestReset} noValidate>
                  <Form.Group className="mb-4">
                    <Form.Label>Email Address</Form.Label>
                    <Form.Control
                      type="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      isInvalid={!!errors.email}
                      placeholder="Enter your registered email"
                      disabled={isLoading}
                    />
                    <Form.Control.Feedback type="invalid">
                      {errors.email}
                    </Form.Control.Feedback>
                    <Form.Text className="text-muted">
                      We'll send a password reset link to this email
                    </Form.Text>
                  </Form.Group>

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
                          Sending...
                        </>
                      ) : (
                        'Send Reset Link'
                      )}
                    </Button>
                  </div>
                </Form>
              ) : (
                <Form onSubmit={handleResetPassword} noValidate>
                  <Form.Group className="mb-3">
                    <Form.Label>New Password</Form.Label>
                    <Form.Control
                      type="password"
                      name="password"
                      value={passwordData.password}
                      onChange={(e) => setPasswordData({
                        ...passwordData,
                        password: e.target.value
                      })}
                      isInvalid={!!errors.password}
                      placeholder="Create a new strong password"
                      disabled={isLoading}
                    />
                    <Form.Control.Feedback type="invalid">
                      {errors.password}
                    </Form.Control.Feedback>
                    
                    {passwordData.password && (
                      <div className="mt-2">
                        <div className="d-flex justify-content-between mb-1">
                          <small>Password Strength:</small>
                          <small className={`text-${getPasswordStrengthColor()} fw-bold`}>
                            {getPasswordStrengthLabel()}
                          </small>
                        </div>
                        <div className="progress" style={{ height: '5px' }}>
                          <div 
                            className={`progress-bar bg-${getPasswordStrengthColor()}`}
                            style={{ width: `${passwordStrength.score}%` }}
                          />
                        </div>
                        
                        {passwordStrength.suggestions.length > 0 && (
                          <div className="small text-muted mt-2">
                            <strong>Suggestions:</strong>
                            <ul className="mb-0 ps-3">
                              {passwordStrength.suggestions.map((suggestion, index) => (
                                <li key={index}>{suggestion}</li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    )}
                  </Form.Group>

                  <Form.Group className="mb-4">
                    <Form.Label>Confirm New Password</Form.Label>
                    <Form.Control
                      type="password"
                      name="confirmPassword"
                      value={passwordData.confirmPassword}
                      onChange={(e) => setPasswordData({
                        ...passwordData,
                        confirmPassword: e.target.value
                      })}
                      isInvalid={!!errors.confirmPassword}
                      placeholder="Confirm your new password"
                      disabled={isLoading}
                    />
                    <Form.Control.Feedback type="invalid">
                      {errors.confirmPassword}
                    </Form.Control.Feedback>
                  </Form.Group>

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
                          Resetting...
                        </>
                      ) : (
                        'Reset Password'
                      )}
                    </Button>
                  </div>
                </Form>
              )}

              <div className="text-center">
                <p className="mb-0">
                  Remember your password?{' '}
                  <Link
                    to="/login"
                    className="text-decoration-none fw-semibold"
                  >
                    Sign in here
                  </Link>
                </p>
              </div>
            </Card.Body>
          </Card>

          {/* Security Information */}
          <Card className="mt-4 border-0 shadow-sm">
            <Card.Body>
              <h6 className="fw-bold mb-3">
                <i className="bi bi-info-circle me-2"></i>
                Password Reset Security
              </h6>
              <ul className="list-unstyled small mb-0">
                <li className="mb-2">
                  <i className="bi bi-shield-check text-success me-2"></i>
                  Reset links expire after 10 minutes
                </li>
                <li className="mb-2">
                  <i className="bi bi-shield-check text-success me-2"></i>
                  Links can only be used once
                </li>
                <li className="mb-2">
                  <i className="bi bi-shield-check text-success me-2"></i>
                  All active sessions will be terminated
                </li>
                <li>
                  <i className="bi bi-shield-check text-success me-2"></i>
                  Rate limiting prevents abuse
                </li>
              </ul>
            </Card.Body>
          </Card>
        </Col>
      </Row>
    </Container>
  );
};

export default ForgotPassword;