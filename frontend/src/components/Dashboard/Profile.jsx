import React, { useState, useEffect } from 'react';
import {
  Container,
  Row,
  Col,
  Card,
  Form,
  Button,
  Alert,
  Spinner,
  Tab,
  Nav,
  Modal,
  Table,
  Badge
} from 'react-bootstrap';
import { useAuth } from '../../services/auth';
import api from '../../services/api';

const Profile = () => {
  const { user, updateProfile, changePassword, deactivateAccount } = useAuth();
  const [activeTab, setActiveTab] = useState('profile');
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [sessions, setSessions] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  
  // Profile form state
  const [profileData, setProfileData] = useState({
    name: '',
    email: '',
    phone: '',
    department: '',
    studentId: '',
    dateOfBirth: ''
  });
  
  // Password form state
  const [passwordData, setPasswordData] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: ''
  });
  
  // Deactivation state
  const [showDeactivateModal, setShowDeactivateModal] = useState(false);
  const [deactivateReason, setDeactivateReason] = useState('');
  const [deactivating, setDeactivating] = useState(false);

  useEffect(() => {
    if (user) {
      setProfileData({
        name: user.name || '',
        email: user.email || '',
        phone: user.phone || '',
        department: user.department || '',
        studentId: user.studentId || '',
        dateOfBirth: user.dateOfBirth ? new Date(user.dateOfBirth).toISOString().split('T')[0] : ''
      });
      
      if (activeTab === 'sessions') {
        fetchSessions();
      } else if (activeTab === 'audit') {
        fetchAuditLogs();
      }
    }
  }, [user, activeTab]);

  const fetchSessions = async () => {
    try {
      setLoading(true);
      const response = await api.get(`/users/${user._id}/sessions`);
      setSessions(response.data.data);
    } catch (error) {
      console.error('Failed to fetch sessions:', error);
      setError('Failed to load sessions');
    } finally {
      setLoading(false);
    }
  };

  const fetchAuditLogs = async () => {
    try {
      setLoading(true);
      const response = await api.get(`/users/${user._id}/audit-logs?limit=20`);
      setAuditLogs(response.data.data);
    } catch (error) {
      console.error('Failed to fetch audit logs:', error);
      setError('Failed to load audit logs');
    } finally {
      setLoading(false);
    }
  };

  const handleProfileUpdate = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setSaving(true);

    try {
      const result = await updateProfile(profileData);
      if (result.success) {
        setSuccess('Profile updated successfully');
      } else {
        setError(result.error || 'Failed to update profile');
      }
    } catch (error) {
      setError(error.response?.data?.error || 'An unexpected error occurred');
    } finally {
      setSaving(false);
    }
  };

  const handlePasswordChange = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    // Validation
    if (passwordData.newPassword !== passwordData.confirmPassword) {
      setError('New passwords do not match');
      return;
    }

    if (passwordData.newPassword.length < 8) {
      setError('New password must be at least 8 characters');
      return;
    }

    setSaving(true);

    try {
      const result = await changePassword(
        passwordData.currentPassword,
        passwordData.newPassword
      );
      
      if (result.success) {
        setSuccess('Password changed successfully');
        setPasswordData({
          currentPassword: '',
          newPassword: '',
          confirmPassword: ''
        });
      } else {
        setError(result.error || 'Failed to change password');
      }
    } catch (error) {
      setError(error.response?.data?.error || 'An unexpected error occurred');
    } finally {
      setSaving(false);
    }
  };

  const handleRevokeSession = async (sessionId) => {
    if (!window.confirm('Are you sure you want to revoke this session?')) {
      return;
    }

    try {
      await api.delete(`/users/${user._id}/sessions/${sessionId}`);
      setSuccess('Session revoked successfully');
      fetchSessions(); // Refresh sessions
    } catch (error) {
      setError('Failed to revoke session');
    }
  };

  const handleDeactivateAccount = async () => {
    if (!deactivateReason.trim()) {
      setError('Please provide a reason for deactivation');
      return;
    }

    if (!window.confirm('Are you sure? This action cannot be undone.')) {
      return;
    }

    setDeactivating(true);

    try {
      const result = await deactivateAccount();
      if (result.success) {
        alert('Account deactivated successfully');
        window.location.href = '/';
      } else {
        setError(result.error || 'Failed to deactivate account');
      }
    } catch (error) {
      setError('Failed to deactivate account');
    } finally {
      setDeactivating(false);
      setShowDeactivateModal(false);
    }
  };

  const getDeviceIcon = (device) => {
    switch (device?.toLowerCase()) {
      case 'mobile': return 'bi-phone';
      case 'tablet': return 'bi-tablet';
      case 'desktop': return 'bi-pc';
      default: return 'bi-device-unknown';
    }
  };

  const getBrowserIcon = (browser) => {
    switch (browser?.toLowerCase()) {
      case 'chrome': return 'bi-browser-chrome';
      case 'firefox': return 'bi-browser-firefox';
      case 'safari': return 'bi-browser-safari';
      case 'edge': return 'bi-browser-edge';
      default: return 'bi-browser';
    }
  };

  const getOSIcon = (os) => {
    switch (os?.toLowerCase()) {
      case 'windows': return 'bi-windows';
      case 'mac os': return 'bi-apple';
      case 'linux': return 'bi-ubuntu';
      case 'android': return 'bi-android';
      case 'ios': return 'bi-phone';
      default: return 'bi-device-unknown';
    }
  };

  const formatDate = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  if (!user) {
    return (
      <Container className="py-5">
        <div className="d-flex justify-content-center align-items-center" style={{ minHeight: '50vh' }}>
          <Spinner animation="border" role="status">
            <span className="visually-hidden">Loading...</span>
          </Spinner>
        </div>
      </Container>
    );
  }

  return (
    <Container fluid className="py-4">
      <Row className="mb-4">
        <Col>
          <h2 className="fw-bold">
            <i className="bi bi-person-circle me-2"></i>
            My Profile
          </h2>
          <p className="text-muted">Manage your account settings and security</p>
        </Col>
      </Row>

      <Row>
        <Col lg={3} className="mb-4">
          <Card className="border-0 shadow-sm">
            <Card.Body className="text-center">
              <div className="mb-3">
                <div className="bg-primary bg-opacity-10 rounded-circle d-inline-flex align-items-center justify-content-center" 
                     style={{ width: '100px', height: '100px' }}>
                  <i className="bi bi-person" style={{ fontSize: '3rem' }}></i>
                </div>
              </div>
              <h5 className="mb-1">{user.name}</h5>
              <p className="text-muted mb-3">{user.email}</p>
              <Badge bg={user.role === 'admin' ? 'dark' : 'primary'} className="mb-3">
                {user.role.toUpperCase()}
              </Badge>
              
              <div className="mt-4">
                <p className="small text-muted mb-2">
                  <i className="bi bi-shield-check me-1"></i>
                  Account Security
                </p>
                <div className="d-flex justify-content-between small">
                  <span>Email Verified:</span>
                  <Badge bg={user.isVerified ? 'success' : 'warning'}>
                    {user.isVerified ? 'Yes' : 'No'}
                  </Badge>
                </div>
                <div className="d-flex justify-content-between small mt-2">
                  <span>Account Status:</span>
                  <Badge bg={user.isActive ? 'success' : 'danger'}>
                    {user.isActive ? 'Active' : 'Inactive'}
                  </Badge>
                </div>
              </div>
            </Card.Body>
          </Card>

          <Card className="border-0 shadow-sm mt-4">
            <Card.Body>
              <h6 className="fw-bold mb-3">Security Tips</h6>
              <ul className="list-unstyled small mb-0">
                <li className="mb-2">
                  <i className="bi bi-check-circle text-success me-2"></i>
                  Use a strong, unique password
                </li>
                <li className="mb-2">
                  <i className="bi bi-check-circle text-success me-2"></i>
                  Don't share your login credentials
                </li>
                <li className="mb-2">
                  <i className="bi bi-check-circle text-success me-2"></i>
                  Log out from public computers
                </li>
                <li>
                  <i className="bi bi-check-circle text-success me-2"></i>
                  Review active sessions regularly
                </li>
              </ul>
            </Card.Body>
          </Card>
        </Col>

        <Col lg={9}>
          <Card className="border-0 shadow-sm">
            <Card.Body>
              <Tab.Container activeKey={activeTab} onSelect={setActiveTab}>
                <Nav variant="tabs" className="mb-4">
                  <Nav.Item>
                    <Nav.Link eventKey="profile">
                      <i className="bi bi-person me-1"></i>
                      Profile
                    </Nav.Link>
                  </Nav.Item>
                  <Nav.Item>
                    <Nav.Link eventKey="password">
                      <i className="bi bi-key me-1"></i>
                      Password
                    </Nav.Link>
                  </Nav.Item>
                  <Nav.Item>
                    <Nav.Link eventKey="sessions">
                      <i className="bi bi-laptop me-1"></i>
                      Sessions
                    </Nav.Link>
                  </Nav.Item>
                  <Nav.Item>
                    <Nav.Link eventKey="audit">
                      <i className="bi bi-clock-history me-1"></i>
                      Audit Logs
                    </Nav.Link>
                  </Nav.Item>
                  <Nav.Item>
                    <Nav.Link eventKey="security" className="text-danger">
                      <i className="bi bi-exclamation-triangle me-1"></i>
                      Danger Zone
                    </Nav.Link>
                  </Nav.Item>
                </Nav>

                <Tab.Content>
                  {/* Profile Tab */}
                  <Tab.Pane eventKey="profile">
                    {error && <Alert variant="danger">{error}</Alert>}
                    {success && <Alert variant="success">{success}</Alert>}
                    
                    <Form onSubmit={handleProfileUpdate}>
                      <Row>
                        <Col md={6}>
                          <Form.Group className="mb-3">
                            <Form.Label>Full Name</Form.Label>
                            <Form.Control
                              type="text"
                              value={profileData.name}
                              onChange={(e) => setProfileData({
                                ...profileData,
                                name: e.target.value
                              })}
                              required
                            />
                          </Form.Group>
                        </Col>
                        
                        <Col md={6}>
                          <Form.Group className="mb-3">
                            <Form.Label>Email Address</Form.Label>
                            <Form.Control
                              type="email"
                              value={profileData.email}
                              onChange={(e) => setProfileData({
                                ...profileData,
                                email: e.target.value
                              })}
                              required
                              disabled
                            />
                            <Form.Text className="text-muted">
                              Email cannot be changed
                            </Form.Text>
                          </Form.Group>
                        </Col>
                      </Row>

                      <Row>
                        <Col md={6}>
                          <Form.Group className="mb-3">
                            <Form.Label>Phone Number</Form.Label>
                            <Form.Control
                              type="tel"
                              value={profileData.phone}
                              onChange={(e) => setProfileData({
                                ...profileData,
                                phone: e.target.value
                              })}
                            />
                          </Form.Group>
                        </Col>
                        
                        <Col md={6}>
                          <Form.Group className="mb-3">
                            <Form.Label>Date of Birth</Form.Label>
                            <Form.Control
                              type="date"
                              value={profileData.dateOfBirth}
                              onChange={(e) => setProfileData({
                                ...profileData,
                                dateOfBirth: e.target.value
                              })}
                              required
                            />
                          </Form.Group>
                        </Col>
                      </Row>

                      <Row>
                        <Col md={6}>
                          <Form.Group className="mb-3">
                            <Form.Label>Student ID</Form.Label>
                            <Form.Control
                              type="text"
                              value={profileData.studentId}
                              onChange={(e) => setProfileData({
                                ...profileData,
                                studentId: e.target.value
                              })}
                              disabled={!user.role.includes('student')}
                            />
                          </Form.Group>
                        </Col>
                        
                        <Col md={6}>
                          <Form.Group className="mb-3">
                            <Form.Label>Department</Form.Label>
                            <Form.Select
                              value={profileData.department}
                              onChange={(e) => setProfileData({
                                ...profileData,
                                department: e.target.value
                              })}
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
                      </Row>

                      <div className="d-flex justify-content-end">
                        <Button
                          variant="primary"
                          type="submit"
                          disabled={saving}
                        >
                          {saving ? (
                            <>
                              <Spinner
                                as="span"
                                animation="border"
                                size="sm"
                                role="status"
                                aria-hidden="true"
                                className="me-2"
                              />
                              Saving...
                            </>
                          ) : (
                            'Save Changes'
                          )}
                        </Button>
                      </div>
                    </Form>
                  </Tab.Pane>

                  {/* Password Tab */}
                  <Tab.Pane eventKey="password">
                    {error && <Alert variant="danger">{error}</Alert>}
                    {success && <Alert variant="success">{success}</Alert>}
                    
                    <Form onSubmit={handlePasswordChange}>
                      <Row>
                        <Col md={8}>
                          <Form.Group className="mb-3">
                            <Form.Label>Current Password</Form.Label>
                            <Form.Control
                              type="password"
                              value={passwordData.currentPassword}
                              onChange={(e) => setPasswordData({
                                ...passwordData,
                                currentPassword: e.target.value
                              })}
                              required
                            />
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
                              required
                            />
                            <Form.Text className="text-muted">
                              Minimum 8 characters with uppercase, lowercase, number, and special character
                            </Form.Text>
                          </Form.Group>

                          <Form.Group className="mb-4">
                            <Form.Label>Confirm New Password</Form.Label>
                            <Form.Control
                              type="password"
                              value={passwordData.confirmPassword}
                              onChange={(e) => setPasswordData({
                                ...passwordData,
                                confirmPassword: e.target.value
                              })}
                              required
                            />
                          </Form.Group>

                          <div className="d-flex justify-content-end">
                            <Button
                              variant="primary"
                              type="submit"
                              disabled={saving}
                            >
                              {saving ? (
                                <>
                                  <Spinner
                                    as="span"
                                    animation="border"
                                    size="sm"
                                    role="status"
                                    aria-hidden="true"
                                    className="me-2"
                                  />
                                  Changing...
                                </>
                              ) : (
                                'Change Password'
                              )}
                            </Button>
                          </div>
                        </Col>
                        
                        <Col md={4}>
                          <Card className="border-0 bg-light">
                            <Card.Body>
                              <h6 className="fw-bold mb-3">
                                <i className="bi bi-shield-check me-2"></i>
                                Password Requirements
                              </h6>
                              <ul className="list-unstyled small mb-0">
                                <li className="mb-2">
                                  <i className="bi bi-check-circle text-success me-2"></i>
                                  At least 8 characters
                                </li>
                                <li className="mb-2">
                                  <i className="bi bi-check-circle text-success me-2"></i>
                                  One uppercase letter
                                </li>
                                <li className="mb-2">
                                  <i className="bi bi-check-circle text-success me-2"></i>
                                  One lowercase letter
                                </li>
                                <li className="mb-2">
                                  <i className="bi bi-check-circle text-success me-2"></i>
                                  One number
                                </li>
                                <li>
                                  <i className="bi bi-check-circle text-success me-2"></i>
                                  One special character
                                </li>
                              </ul>
                            </Card.Body>
                          </Card>
                        </Col>
                      </Row>
                    </Form>
                  </Tab.Pane>

                  {/* Sessions Tab */}
                  <Tab.Pane eventKey="sessions">
                    {loading ? (
                      <div className="text-center py-5">
                        <Spinner animation="border" role="status">
                          <span className="visually-hidden">Loading sessions...</span>
                        </Spinner>
                      </div>
                    ) : (
                      <>
                        <div className="d-flex justify-content-between align-items-center mb-4">
                          <h6 className="mb-0">Active Sessions ({sessions.length})</h6>
                          <Button
                            variant="outline-danger"
                            size="sm"
                            onClick={() => {
                              if (window.confirm('Revoke all sessions except current?')) {
                                api.delete(`/users/${user._id}/sessions`)
                                  .then(() => {
                                    setSuccess('All other sessions revoked');
                                    fetchSessions();
                                  })
                                  .catch(() => setError('Failed to revoke sessions'));
                              }
                            }}
                          >
                            <i className="bi bi-x-circle me-1"></i>
                            Revoke All Others
                          </Button>
                        </div>
                        
                        {sessions.length === 0 ? (
                          <Alert variant="info">No active sessions found</Alert>
                        ) : (
                          <div className="table-responsive">
                            <Table hover>
                              <thead>
                                <tr>
                                  <th>Device</th>
                                  <th>Browser & OS</th>
                                  <th>IP Address</th>
                                  <th>Last Activity</th>
                                  <th>Status</th>
                                  <th>Actions</th>
                                </tr>
                              </thead>
                              <tbody>
                                {sessions.map((session) => (
                                  <tr key={session._id}>
                                    <td>
                                      <div className="d-flex align-items-center">
                                        <i className={`bi ${getDeviceIcon(session.deviceInfo?.device)} me-2`}></i>
                                        <div>
                                          <div className="small">{session.deviceInfo?.device || 'Unknown'}</div>
                                          <small className="text-muted">
                                            {session.userAgent?.substring(0, 50)}...
                                          </small>
                                        </div>
                                      </div>
                                    </td>
                                    <td>
                                      <div className="d-flex align-items-center">
                                        <i className={`bi ${getBrowserIcon(session.deviceInfo?.browser)} me-2`}></i>
                                        <div>
                                          <div className="small">{session.deviceInfo?.browser || 'Unknown'}</div>
                                          <small className="text-muted">{session.deviceInfo?.os || 'Unknown'}</small>
                                        </div>
                                      </div>
                                    </td>
                                    <td>
                                      <code>{session.ipAddress}</code>
                                    </td>
                                    <td>
                                      <small>{formatDate(session.lastActivity)}</small>
                                    </td>
                                    <td>
                                      {session.isActive ? (
                                        <Badge bg="success">Active</Badge>
                                      ) : (
                                        <Badge bg="secondary">Inactive</Badge>
                                      )}
                                    </td>
                                    <td>
                                      <Button
                                        variant="outline-danger"
                                        size="sm"
                                        onClick={() => handleRevokeSession(session._id)}
                                        disabled={!session.isActive}
                                      >
                                        Revoke
                                      </Button>
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </Table>
                          </div>
                        )}
                      </>
                    )}
                  </Tab.Pane>

                  {/* Audit Logs Tab */}
                  <Tab.Pane eventKey="audit">
                    {loading ? (
                      <div className="text-center py-5">
                        <Spinner animation="border" role="status">
                          <span className="visually-hidden">Loading audit logs...</span>
                        </Spinner>
                      </div>
                    ) : (
                      <>
                        <h6 className="mb-4">Recent Activity ({auditLogs.length})</h6>
                        
                        {auditLogs.length === 0 ? (
                          <Alert variant="info">No audit logs found</Alert>
                        ) : (
                          <div className="table-responsive">
                            <Table hover>
                              <thead>
                                <tr>
                                  <th>Time</th>
                                  <th>Action</th>
                                  <th>Resource</th>
                                  <th>IP Address</th>
                                  <th>Details</th>
                                </tr>
                              </thead>
                              <tbody>
                                {auditLogs.map((log) => (
                                  <tr key={log._id}>
                                    <td>
                                      <small>{formatDate(log.createdAt)}</small>
                                    </td>
                                    <td>
                                      <Badge 
                                        bg={
                                          log.action.includes('FAILED') ? 'danger' :
                                          log.action.includes('ACCESS') ? 'info' :
                                          log.action.includes('CREATE') ? 'success' :
                                          log.action.includes('UPDATE') ? 'warning' :
                                          log.action.includes('DELETE') ? 'dark' : 'secondary'
                                        }
                                      >
                                        {log.action}
                                      </Badge>
                                    </td>
                                    <td>
                                      <small>{log.resource}</small>
                                    </td>
                                    <td>
                                      <code>{log.ipAddress}</code>
                                    </td>
                                    <td>
                                      {log.metadata && (
                                        <Button
                                          variant="outline-info"
                                          size="sm"
                                          onClick={() => {
                                            alert(JSON.stringify(log.metadata, null, 2));
                                          }}
                                        >
                                          View
                                        </Button>
                                      )}
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </Table>
                          </div>
                        )}
                      </>
                    )}
                  </Tab.Pane>

                  {/* Security/Danger Zone Tab */}
                  <Tab.Pane eventKey="security">
                    <Alert variant="danger">
                      <h5 className="alert-heading">
                        <i className="bi bi-exclamation-triangle me-2"></i>
                        Danger Zone
                      </h5>
                      <p>
                        These actions are irreversible. Please proceed with caution.
                      </p>
                    </Alert>

                    <Card className="border-danger">
                      <Card.Body>
                        <h6 className="text-danger mb-3">
                          <i className="bi bi-trash me-2"></i>
                          Deactivate Account
                        </h6>
                        <p className="text-muted mb-4">
                          Deactivating your account will:
                        </p>
                        <ul className="text-muted mb-4">
                          <li>Immediately log you out from all devices</li>
                          <li>Prevent you from logging in again</li>
                          <li>Mark your account as inactive (soft delete)</li>
                          <li>Preserve your data for compliance purposes</li>
                        </ul>
                        
                        <div className="d-flex justify-content-between align-items-center">
                          <Form.Text className="text-muted">
                            This action cannot be undone.
                          </Form.Text>
                          <Button
                            variant="outline-danger"
                            onClick={() => setShowDeactivateModal(true)}
                          >
                            Deactivate Account
                          </Button>
                        </div>
                      </Card.Body>
                    </Card>
                  </Tab.Pane>
                </Tab.Content>
              </Tab.Container>
            </Card.Body>
          </Card>
        </Col>
      </Row>

      {/* Deactivation Modal */}
      <Modal show={showDeactivateModal} onHide={() => setShowDeactivateModal(false)}>
        <Modal.Header closeButton>
          <Modal.Title className="text-danger">
            <i className="bi bi-exclamation-triangle me-2"></i>
            Confirm Account Deactivation
          </Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <Alert variant="danger">
            <strong>Warning:</strong> This action is permanent and cannot be undone.
          </Alert>
          
          <Form.Group className="mb-4">
            <Form.Label>Reason for deactivation</Form.Label>
            <Form.Control
              as="textarea"
              rows={3}
              value={deactivateReason}
              onChange={(e) => setDeactivateReason(e.target.value)}
              placeholder="Please tell us why you're deactivating your account..."
              required
            />
          </Form.Group>
          
          <div className="bg-light p-3 rounded">
            <p className="mb-2">
              <strong>By deactivating your account, you agree that:</strong>
            </p>
            <ul className="small mb-0">
              <li>All your active sessions will be terminated immediately</li>
              <li>You will not be able to log in to your account</li>
              <li>Your account data will be preserved for 30 days</li>
              <li>After 30 days, you cannot recover your account</li>
            </ul>
          </div>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShowDeactivateModal(false)}>
            Cancel
          </Button>
          <Button
            variant="danger"
            onClick={handleDeactivateAccount}
            disabled={deactivating || !deactivateReason.trim()}
          >
            {deactivating ? (
              <>
                <Spinner
                  as="span"
                  animation="border"
                  size="sm"
                  role="status"
                  aria-hidden="true"
                  className="me-2"
                />
                Deactivating...
              </>
            ) : (
              'Yes, Deactivate My Account'
            )}
          </Button>
        </Modal.Footer>
      </Modal>
    </Container>
  );
};

export default Profile;