import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { 
  Form, 
  Button, 
  Card, 
  Container, 
  Row, 
  Col, 
  Alert, 
  Spinner,
  ProgressBar 
} from 'react-bootstrap';
import { useAuth } from '../../services/auth';
import { validatePassword } from '../../utils/validation';
import ReCAPTCHA from 'react-google-recaptcha';

const Register = () => {
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    confirmPassword: '',
    name: '',
    dateOfBirth: '',
    studentId: '',
    department: '',
    phone: '',
    agreeToTerms: false
  });
  
  const [errors, setErrors] = useState({});
  const [passwordStrength, setPasswordStrength] = useState({
    score: 0,
    suggestions: []
  });
  const [isLoading, setIsLoading] = useState(false);
  const [captchaToken, setCaptchaToken] = useState('');

  const { register, error: authError, setError } = useAuth();
  const navigate = useNavigate();

  // Password strength calculation
  useEffect(() => {
    if (formData.password) {
      const strength = validatePassword(formData.password);
      setPasswordStrength(strength);
    } else {
      setPasswordStrength({ score: 0, suggestions: [] });
    }
  }, [formData.password]);

  const validateForm = () => {
    const newErrors = {};

    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!formData.email.trim()) {
      newErrors.email = 'Email is required';
    } else if (!emailRegex.test(formData.email)) {
      newErrors.email = 'Please enter a valid email address';
    }

    // Name validation
    if (!formData.name.trim()) {
      newErrors.name = 'Full name is required';
    } else if (formData.name.trim().length < 2) {
      newErrors.name = 'Name must be at least 2 characters';
    }

    // Password validation
    if (!formData.password) {
      newErrors.password = 'Password is required';
    } else if (passwordStrength.score < 60) {
      newErrors.password = 'Password is too weak';
    }

    // Confirm password validation
    if (!formData.confirmPassword) {
      newErrors.confirmPassword = 'Please confirm your password';
    } else if (formData.password !== formData.confirmPassword) {
      newErrors.confirmPassword = 'Passwords do not match';
    }

    // Date of birth validation
    if (!formData.dateOfBirth) {
      newErrors.dateOfBirth = 'Date of birth is required';
    } else {
      const birthDate = new Date(formData.dateOfBirth);
      const today = new Date();
      const age = today.getFullYear() - birthDate.getFullYear();
      
      if (age < 13) {
        newErrors.dateOfBirth = 'You must be at least 13 years old';
      }
    }

    // Student ID validation (optional)
    if (formData.studentId && !/^[A-Z0-9]{6,10}$/i.test(formData.studentId)) {
      newErrors.studentId = 'Student ID must be 6-10 alphanumeric characters';
    }

    // Phone validation (optional)
    if (formData.phone && !/^[\+]?[1-9][\d]{0,15}$/.test(formData.phone)) {
      newErrors.phone = 'Please enter a valid phone number';
    }

    // Terms agreement validation
    if (!formData.agreeToTerms) {
      newErrors.agreeToTerms = 'You must agree to the terms and conditions';
    }

    // CAPTCHA validation
    if (!captchaToken) {
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
      const userData = {
        email: formData.email,
        password: formData.password,
        name: formData.name,
        dateOfBirth: formData.dateOfBirth,
        studentId: formData.studentId || undefined,
        department: formData.department || undefined,
        phone: formData.phone || undefined,
        captchaToken
      };

      const result = await register(userData);

      if (result.success) {
        // Show success message
        alert('Registration successful! Please check your email for verification.');
        
        // Redirect to login
        navigate('/login');
      } else {
        // Handle specific errors
        if (result.error?.includes('already exists')) {
          setErrors({ email: 'This email is already registered' });
        } else if (result.error?.includes('rate limit')) {
          setErrors({ general: 'Too many registration attempts. Please try again later.' });
        } else {
          setErrors({ general: result.error });
        }
      }
    } catch (error) {
      console.error('Registration error:', error);
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
        <Col md={8} lg={6}>
          <Card className="shadow border-0">
            <Card.Body className="p-4">
              <div className="text-center mb-4">
                <h2 className="fw-bold text-primary">
                  <i className="bi bi-person-plus me-2"></i>
                  Create Account
                </h2>
                <p className="text-muted">Join our secure campus portal</p>
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
                <Row>
                  <Col md={6}>
                    <Form.Group className="mb-3">
                      <Form.Label>Full Name *</Form.Label>
                      <Form.Control
                        type="text"
                        name="name"
                        value={formData.name}
                        onChange={handleInputChange}
                        isInvalid={!!errors.name}
                        placeholder="Enter your full name"
                        disabled={isLoading}
                      />
                      <Form.Control.Feedback type="invalid">
                        {errors.name}
                      </Form.Control.Feedback>
                    </Form.Group>
                  </Col>

                  <Col md={6}>
                    <Form.Group className="mb-3">
                      <Form.Label>Email Address *</Form.Label>
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
                  </Col>
                </Row>

                <Row>
                  <Col md={6}>
                    <Form.Group className="mb-3">
                      <Form.Label>Date of Birth *</Form.Label>
                      <Form.Control
                        type="date"
                        name="dateOfBirth"
                        value={formData.dateOfBirth}
                        onChange={handleInputChange}
                        isInvalid={!!errors.dateOfBirth}
                        max={new Date().toISOString().split('T')[0]}
                        disabled={isLoading}
                      />
                      <Form.Control.Feedback type="invalid">
                        {errors.dateOfBirth}
                      </Form.Control.Feedback>
                    </Form.Group>
                  </Col>

                  <Col md={6}>
                    <Form.Group className="mb-3">
                      <Form.Label>Student ID (Optional)</Form.Label>
                      <Form.Control
                        type="text"
                        name="studentId"
                        value={formData.studentId}
                        onChange={handleInputChange}
                        isInvalid={!!errors.studentId}
                        placeholder="Enter student ID"
                        disabled={isLoading}
                      />
                      <Form.Control.Feedback type="invalid">
                        {errors.studentId}
                      </Form.Control.Feedback>
                    </Form.Group>
                  </Col>
                </Row>

                <Row>
                  <Col md={6}>
                    <Form.Group className="mb-3">
                      <Form.Label>Department (Optional)</Form.Label>
                      <Form.Select
                        name="department"
                        value={formData.department}
                        onChange={handleInputChange}
                        disabled={isLoading}
                      >
                        <option value="">Select Department</option>
                        <option value="Computer Science">Computer Science</option>
                        <option value="Engineering">Engineering</option>
                        <option value="Business">Business</option>
                        <option value="Science">Science</option>
                        <option value="Arts">Arts</option>
                        <option value="Medicine">Medicine</option>
                      </Form.Select>
                    </Form.Group>
                  </Col>

                  <Col md={6}>
                    <Form.Group className="mb-3">
                      <Form.Label>Phone Number (Optional)</Form.Label>
                      <Form.Control
                        type="tel"
                        name="phone"
                        value={formData.phone}
                        onChange={handleInputChange}
                        isInvalid={!!errors.phone}
                        placeholder="Enter phone number"
                        disabled={isLoading}
                      />
                      <Form.Control.Feedback type="invalid">
                        {errors.phone}
                      </Form.Control.Feedback>
                    </Form.Group>
                  </Col>
                </Row>

                <Row>
                  <Col md={6}>
                    <Form.Group className="mb-3">
                      <Form.Label>Password *</Form.Label>
                      <Form.Control
                        type="password"
                        name="password"
                        value={formData.password}
                        onChange={handleInputChange}
                        isInvalid={!!errors.password}
                        placeholder="Create a strong password"
                        disabled={isLoading}
                      />
                      <Form.Control.Feedback type="invalid">
                        {errors.password}
                      </Form.Control.Feedback>
                      
                      {formData.password && (
                        <div className="mt-2">
                          <div className="d-flex justify-content-between mb-1">
                            <small>Password Strength:</small>
                            <small className={`text-${getPasswordStrengthColor()} fw-bold`}>
                              {getPasswordStrengthLabel()}
                            </small>
                          </div>
                          <ProgressBar 
                            now={passwordStrength.score} 
                            variant={getPasswordStrengthColor()}
                            className="mb-2"
                          />
                          
                          {passwordStrength.suggestions.length > 0 && (
                            <div className="small text-muted">
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
                  </Col>

                  <Col md={6}>
                    <Form.Group className="mb-3">
                      <Form.Label>Confirm Password *</Form.Label>
                      <Form.Control
                        type="password"
                        name="confirmPassword"
                        value={formData.confirmPassword}
                        onChange={handleInputChange}
                        isInvalid={!!errors.confirmPassword}
                        placeholder="Confirm your password"
                        disabled={isLoading}
                      />
                      <Form.Control.Feedback type="invalid">
                        {errors.confirmPassword}
                      </Form.Control.Feedback>
                    </Form.Group>
                  </Col>
                </Row>

                <div className="mb-3">
                  <ReCAPTCHA
                    sitekey={process.env.REACT_APP_RECAPTCHA_SITE_KEY}
                    onChange={(token) => setCaptchaToken(token)}
                    onExpired={() => setCaptchaToken('')}
                  />
                  {errors.captcha && (
                    <div className="text-danger small mt-2">{errors.captcha}</div>
                  )}
                </div>

                <Form.Group className="mb-4">
                  <Form.Check
                    type="checkbox"
                    name="agreeToTerms"
                    label={
                      <>
                        I agree to the{' '}
                        <Link to="/terms" className="text-decoration-none">
                          Terms of Service
                        </Link>{' '}
                        and{' '}
                        <Link to="/privacy" className="text-decoration-none">
                          Privacy Policy
                        </Link>
                      </>
                    }
                    checked={formData.agreeToTerms}
                    onChange={handleInputChange}
                    isInvalid={!!errors.agreeToTerms}
                    disabled={isLoading}
                  />
                  <Form.Control.Feedback type="invalid">
                    {errors.agreeToTerms}
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
                        Creating Account...
                      </>
                    ) : (
                      'Create Account'
                    )}
                  </Button>
                </div>

                <div className="text-center">
                  <p className="mb-0">
                    Already have an account?{' '}
                    <Link
                      to="/login"
                      className="text-decoration-none fw-semibold"
                    >
                      Sign in here
                    </Link>
                  </p>
                </div>
              </Form>

              <div className="mt-4 pt-3 border-top">
                <div className="text-center">
                  <small className="text-muted">
                    <i className="bi bi-shield-check me-1"></i>
                    Your data is protected with AES-256 encryption
                  </small>
                </div>
              </div>
            </Card.Body>
          </Card>

          {/* Security Features Card */}
          <Card className="mt-4 border-0 shadow-sm">
            <Card.Body>
              <h6 className="fw-bold mb-3">
                <i className="bi bi-shield-check me-2"></i>
                Security Features
              </h6>
              <Row>
                <Col md={6}>
                  <ul className="list-unstyled small mb-3 mb-md-0">
                    <li className="mb-2">
                      <i className="bi bi-check-circle text-success me-2"></i>
                      Password hashing with bcrypt
                    </li>
                    <li className="mb-2">
                      <i className="bi bi-check-circle text-success me-2"></i>
                      Email verification required
                    </li>
                    <li className="mb-2">
                      <i className="bi bi-check-circle text-success me-2"></i>
                      CAPTCHA protection
                    </li>
                  </ul>
                </Col>
                <Col md={6}>
                  <ul className="list-unstyled small">
                    <li className="mb-2">
                      <i className="bi bi-check-circle text-success me-2"></i>
                      Rate limiting on registration
                    </li>
                    <li className="mb-2">
                      <i className="bi bi-check-circle text-success me-2"></i>
                      Input validation & sanitization
                    </li>
                    <li>
                      <i className="bi bi-check-circle text-success me-2"></i>
                      Secure HTTPS connection
                    </li>
                  </ul>
                </Col>
              </Row>
            </Card.Body>
          </Card>
        </Col>
      </Row>
    </Container>
  );
};

export default Register;