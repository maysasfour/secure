import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Navbar as BootstrapNavbar, Nav, Container, NavDropdown, Button, Modal, Form } from 'react-bootstrap';
import { useAuth } from '../../services/auth';
import api from '../../services/api';

const CustomNavbar = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [showLogoutModal, setShowLogoutModal] = useState(false);
  const [showPasswordModal, setShowPasswordModal] = useState(false);
  const [passwordData, setPasswordData] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: ''
  });
  const [passwordErrors, setPasswordErrors] = useState({});

  const handleLogout = async () => {
    await logout();
    navigate('/login');
    setShowLogoutModal(false);
  };

  const handlePasswordChange = async (e) => {
    e.preventDefault();
    
    // Validate passwords
    const errors = {};
    if (!passwordData.currentPassword) errors.currentPassword = 'Current password is required';
    if (!passwordData.newPassword) errors.newPassword = 'New password is required';
    if (passwordData.newPassword.length < 8) errors.newPassword = 'Password must be at least 8 characters';
    if (passwordData.newPassword !== passwordData.confirmPassword) {
      errors.confirmPassword = 'Passwords do not match';
    }

    if (Object.keys(errors).length > 0) {
      setPasswordErrors(errors);
      return;
    }

    try {
      await api.patch('/auth/change-password', {
        currentPassword: passwordData.currentPassword,
        newPassword: passwordData.newPassword
      });

      alert('Password changed successfully');
      setShowPasswordModal(false);
      setPasswordData({
        currentPassword: '',
        newPassword: '',
        confirmPassword: ''
      });
      setPasswordErrors({});
    } catch (error) {
      setPasswordErrors({ general: error.response?.data?.error || 'Password change failed' });
    }
  };

  return (
    <>
      <BootstrapNavbar bg="dark" variant="dark" expand="lg" className="shadow">
        <Container fluid>
          <BootstrapNavbar.Brand as={Link} to="/" className="fw-bold">
            <i className="bi bi-shield-lock me-2"></i>
            Secure Campus Portal
          </BootstrapNavbar.Brand>
          
          <BootstrapNavbar.Toggle aria-controls="navbar-nav" />
          
          <BootstrapNavbar.Collapse id="navbar-nav">
            <Nav className="me-auto">
              {user ? (
                <>
                  {user.role === 'admin' ? (
                    <Nav.Link as={Link} to="/admin">Admin Dashboard</Nav.Link>
                  ) : (
                    <Nav.Link as={Link} to="/dashboard">Student Dashboard</Nav.Link>
                  )}
                  <Nav.Link as={Link} to="/profile">Profile</Nav.Link>
                  <Nav.Link as={Link} to="/data">Secure Data</Nav.Link>
                </>
              ) : (
                <>
                  <Nav.Link as={Link} to="/login">Login</Nav.Link>
                  <Nav.Link as={Link} to="/register">Register</Nav.Link>
                </>
              )}
            </Nav>

            {user && (
              <Nav className="align-items-center">
                <NavDropdown
                  title={
                    <>
                      <i className="bi bi-person-circle me-2"></i>
                      {user.name}
                    </>
                  }
                  align="end"
                >
                  <NavDropdown.Item as={Link} to="/profile">
                    <i className="bi bi-person me-2"></i>
                    My Profile
                  </NavDropdown.Item>
                  
                  <NavDropdown.Item onClick={() => setShowPasswordModal(true)}>
                    <i className="bi bi-key me-2"></i>
                    Change Password
                  </NavDropdown.Item>
                  
                  <NavDropdown.Divider />
                  
                  <NavDropdown.Item 
                    onClick={() => setShowLogoutModal(true)}
                    className="text-danger"
                  >
                    <i className="bi bi-box-arrow-right me-2"></i>
                    Logout
                  </NavDropdown.Item>
                </NavDropdown>
                
                <span className="badge bg-info ms-2">
                  {user.role.toUpperCase()}
                </span>
              </Nav>
            )}
          </BootstrapNavbar.Collapse>
        </Container>
      </BootstrapNavbar>

      {/* Logout Confirmation Modal */}
      <Modal show={showLogoutModal} onHide={() => setShowLogoutModal(false)}>
        <Modal.Header closeButton>
          <Modal.Title>Confirm Logout</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          Are you sure you want to logout? You will need to login again to access your account.
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShowLogoutModal(false)}>
            Cancel
          </Button>
          <Button variant="danger" onClick={handleLogout}>
            Logout
          </Button>
        </Modal.Footer>
      </Modal>

      {/* Change Password Modal */}
      <Modal show={showPasswordModal} onHide={() => setShowPasswordModal(false)}>
        <Form onSubmit={handlePasswordChange}>
          <Modal.Header closeButton>
            <Modal.Title>Change Password</Modal.Title>
          </Modal.Header>
          <Modal.Body>
            {passwordErrors.general && (
              <div className="alert alert-danger">{passwordErrors.general}</div>
            )}
            
            <Form.Group className="mb-3">
              <Form.Label>Current Password</Form.Label>
              <Form.Control
                type="password"
                value={passwordData.currentPassword}
                onChange={(e) => setPasswordData({
                  ...passwordData,
                  currentPassword: e.target.value
                })}
                isInvalid={!!passwordErrors.currentPassword}
              />
              <Form.Control.Feedback type="invalid">
                {passwordErrors.currentPassword}
              </Form.Control.Feedback>
            </Form.Group>

            <Form.Group className="mb-3">
              <Form.Label>New Password</Form.Label>
              <Form.Control
                type="password"
                value={passwordData.newPassword}
                onChange={(e) => setPasswordData({
                  ...passwordData,
                  newPassword: e.target.value
                })}
                isInvalid={!!passwordErrors.newPassword}
              />
              <Form.Control.Feedback type="invalid">
                {passwordErrors.newPassword}
              </Form.Control.Feedback>
              <Form.Text className="text-muted">
                Password must be at least 8 characters with uppercase, lowercase, number, and special character.
              </Form.Text>
            </Form.Group>

            <Form.Group className="mb-3">
              <Form.Label>Confirm New Password</Form.Label>
              <Form.Control
                type="password"
                value={passwordData.confirmPassword}
                onChange={(e) => setPasswordData({
                  ...passwordData,
                  confirmPassword: e.target.value
                })}
                isInvalid={!!passwordErrors.confirmPassword}
              />
              <Form.Control.Feedback type="invalid">
                {passwordErrors.confirmPassword}
              </Form.Control.Feedback>
            </Form.Group>
          </Modal.Body>
          <Modal.Footer>
            <Button variant="secondary" onClick={() => setShowPasswordModal(false)}>
              Cancel
            </Button>
            <Button variant="primary" type="submit">
              Change Password
            </Button>
          </Modal.Footer>
        </Form>
      </Modal>
    </>
  );
};

export default CustomNavbar;