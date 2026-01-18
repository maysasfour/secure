import React, { useState, useEffect } from 'react';
import { 
  Container, 
  Row, 
  Col, 
  Card, 
  Table, 
  Badge, 
  Button, 
  Spinner,
  Alert,
  Form,
  Dropdown,
  Modal
} from 'react-bootstrap';
import { useAuth } from '../../services/auth';
import api from '../../services/api';
import {
  LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid, 
  Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell
} from 'recharts';
import DatePicker from 'react-datepicker';
import "react-datepicker/dist/react-datepicker.css";

const AdminDashboard = () => {
  const { user } = useAuth();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [dashboardData, setDashboardData] = useState({
    users: [],
    securityEvents: [],
    systemStats: {},
    auditLogs: [],
    recentActivity: []
  });
  const [selectedDateRange, setSelectedDateRange] = useState({
    start: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000), // 7 days ago
    end: new Date()
  });
  const [showUserModal, setShowUserModal] = useState(false);
  const [selectedUser, setSelectedUser] = useState(null);
  const [exporting, setExporting] = useState(false);

  useEffect(() => {
    fetchDashboardData();
  }, [selectedDateRange]);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      setError(null);

      // Fetch users
      const usersResponse = await api.get('/users?limit=10&sort=-createdAt');
      
      // Fetch security insights
      const insightsResponse = await api.get('/admin/security-insights');
      
      // Fetch audit logs
      const logsResponse = await api.get('/admin/audit-logs?limit=20');

      // Mock system stats (in real app, this would come from API)
      const systemStats = {
        totalUsers: 1250,
        activeUsers: 987,
        newUsersToday: 24,
        failedLogins: 12,
        securityAlerts: 3,
        systemUptime: '99.8%',
        avgResponseTime: '142ms'
      };

      setDashboardData({
        users: usersResponse.data.data,
        securityEvents: insightsResponse.data.data.insights.recentEvents || [],
        systemStats,
        auditLogs: logsResponse.data.data,
        recentActivity: logsResponse.data.data.slice(0, 10)
      });
      setLoading(false);
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error);
      setError('Failed to load dashboard data');
      setLoading(false);
    }
  };

  const handleUserAction = async (userId, action, data = null) => {
    try {
      switch(action) {
        case 'lock':
          await api.patch(`/admin/users/${userId}/lock`, { lock: true, reason: 'Administrative action' });
          break;
        case 'unlock':
          await api.patch(`/admin/users/${userId}/lock`, { lock: false });
          break;
        case 'force_reset':
          await api.post(`/admin/users/${userId}/force-password-reset`);
          break;
        case 'view':
          const userResponse = await api.get(`/users/${userId}`);
          setSelectedUser(userResponse.data.data);
          setShowUserModal(true);
          return;
      }
      
      alert(`User ${action.replace('_', ' ')} successful`);
      fetchDashboardData(); // Refresh data
    } catch (error) {
      alert(`Failed to ${action} user: ${error.response?.data?.error || error.message}`);
    }
  };

  const handleExportAuditLogs = async (format = 'json') => {
    try {
      setExporting(true);
      const response = await api.get(`/admin/export-audit-logs?format=${format}`, {
        responseType: 'blob'
      });
      
      // Create download link
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `audit-logs-${Date.now()}.${format}`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      
      alert('Export completed successfully');
    } catch (error) {
      alert('Export failed: ' + (error.response?.data?.error || error.message));
    } finally {
      setExporting(false);
    }
  };

  const getStatusBadge = (status) => {
    switch(status) {
      case 'active': return <Badge bg="success">Active</Badge>;
      case 'locked': return <Badge bg="danger">Locked</Badge>;
      case 'inactive': return <Badge bg="secondary">Inactive</Badge>;
      default: return <Badge bg="warning">Unknown</Badge>;
    }
  };

  const getRoleBadge = (role) => {
    switch(role) {
      case 'admin': return <Badge bg="dark">Admin</Badge>;
      case 'student': return <Badge bg="primary">Student</Badge>;
      case 'faculty': return <Badge bg="info">Faculty</Badge>;
      default: return <Badge bg="secondary">Unknown</Badge>;
    }
  };

  const getSecurityLevelColor = (level) => {
    switch(level?.toLowerCase()) {
      case 'high': return '#dc3545';
      case 'medium': return '#ffc107';
      case 'low': return '#28a745';
      default: return '#6c757d';
    }
  };

  if (loading) {
    return (
      <Container className="py-5">
        <div className="d-flex justify-content-center align-items-center" style={{ minHeight: '50vh' }}>
          <Spinner animation="border" role="status">
            <span className="visually-hidden">Loading dashboard...</span>
          </Spinner>
        </div>
      </Container>
    );
  }

  if (error) {
    return (
      <Container className="py-5">
        <Alert variant="danger">
          <i className="bi bi-exclamation-triangle me-2"></i>
          {error}
        </Alert>
      </Container>
    );
  }

  // Chart data
  const userGrowthData = [
    { date: 'Oct 1', users: 1200 },
    { date: 'Oct 2', users: 1210 },
    { date: 'Oct 3', users: 1225 },
    { date: 'Oct 4', users: 1238 },
    { date: 'Oct 5', users: 1245 },
    { date: 'Oct 6', users: 1250 },
    { date: 'Oct 7', users: 1250 }
  ];

  const securityEventData = dashboardData.securityEvents.slice(0, 5).map(event => ({
    name: event.action,
    count: 1
  }));

  const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884d8'];

  return (
    <Container fluid className="py-4">
      <Row className="mb-4">
        <Col>
          <h2 className="fw-bold">
            <i className="bi bi-shield-check me-2"></i>
            Admin Dashboard
          </h2>
          <p className="text-muted">
            Welcome, {user?.name}. Monitor system security and manage users.
          </p>
        </Col>
        <Col xs="auto">
          <div className="d-flex gap-2">
            <DatePicker
              selected={selectedDateRange.start}
              onChange={(date) => setSelectedDateRange({ ...selectedDateRange, start: date })}
              selectsStart
              startDate={selectedDateRange.start}
              endDate={selectedDateRange.end}
              className="form-control"
              dateFormat="yyyy-MM-dd"
            />
            <DatePicker
              selected={selectedDateRange.end}
              onChange={(date) => setSelectedDateRange({ ...selectedDateRange, end: date })}
              selectsEnd
              startDate={selectedDateRange.start}
              endDate={selectedDateRange.end}
              minDate={selectedDateRange.start}
              className="form-control"
              dateFormat="yyyy-MM-dd"
            />
          </div>
        </Col>
      </Row>

      {/* System Statistics Cards */}
      <Row className="mb-4">
        <Col xl={3} lg={6} md={6} className="mb-4">
          <Card className="border-0 shadow-sm h-100">
            <Card.Body>
              <div className="d-flex justify-content-between align-items-center">
                <div>
                  <h6 className="text-muted mb-2">Total Users</h6>
                  <h2 className="fw-bold text-primary">{dashboardData.systemStats.totalUsers}</h2>
                </div>
                <div className="bg-primary bg-opacity-10 p-3 rounded">
                  <i className="bi bi-people text-primary" style={{ fontSize: '2rem' }}></i>
                </div>
              </div>
              <small className="text-muted">
                <i className="bi bi-arrow-up text-success me-1"></i>
                {dashboardData.systemStats.newUsersToday} new today
              </small>
            </Card.Body>
          </Card>
        </Col>

        <Col xl={3} lg={6} md={6} className="mb-4">
          <Card className="border-0 shadow-sm h-100">
            <Card.Body>
              <div className="d-flex justify-content-between align-items-center">
                <div>
                  <h6 className="text-muted mb-2">Active Users</h6>
                  <h2 className="fw-bold text-success">{dashboardData.systemStats.activeUsers}</h2>
                </div>
                <div className="bg-success bg-opacity-10 p-3 rounded">
                  <i className="bi bi-person-check text-success" style={{ fontSize: '2rem' }}></i>
                </div>
              </div>
              <small className="text-muted">
                Currently logged in or active in last 24h
              </small>
            </Card.Body>
          </Card>
        </Col>

        <Col xl={3} lg={6} md={6} className="mb-4">
          <Card className="border-0 shadow-sm h-100">
            <Card.Body>
              <div className="d-flex justify-content-between align-items-center">
                <div>
                  <h6 className="text-muted mb-2">Security Alerts</h6>
                  <h2 className="fw-bold text-danger">{dashboardData.systemStats.securityAlerts}</h2>
                </div>
                <div className="bg-danger bg-opacity-10 p-3 rounded">
                  <i className="bi bi-shield-exclamation text-danger" style={{ fontSize: '2rem' }}></i>
                </div>
              </div>
              <small className="text-muted">
                <i className="bi bi-exclamation-triangle text-warning me-1"></i>
                {dashboardData.systemStats.failedLogins} failed logins today
              </small>
            </Card.Body>
          </Card>
        </Col>

        <Col xl={3} lg={6} md={6} className="mb-4">
          <Card className="border-0 shadow-sm h-100">
            <Card.Body>
              <div className="d-flex justify-content-between align-items-center">
                <div>
                  <h6 className="text-muted mb-2">System Uptime</h6>
                  <h2 className="fw-bold text-info">{dashboardData.systemStats.systemUptime}</h2>
                </div>
                <div className="bg-info bg-opacity-10 p-3 rounded">
                  <i className="bi bi-server text-info" style={{ fontSize: '2rem' }}></i>
                </div>
              </div>
              <small className="text-muted">
                Avg response: {dashboardData.systemStats.avgResponseTime}
              </small>
            </Card.Body>
          </Card>
        </Col>
      </Row>

      {/* Charts Section */}
      <Row className="mb-4">
        <Col lg={8} className="mb-4">
          <Card className="border-0 shadow-sm h-100">
            <Card.Body>
              <Card.Title className="d-flex justify-content-between align-items-center">
                <span>User Growth</span>
                <Badge bg="light" text="dark">
                  <i className="bi bi-graph-up me-1"></i>
                  Last 7 Days
                </Badge>
              </Card.Title>
              <div style={{ height: '300px' }}>
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={userGrowthData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="date" />
                    <YAxis />
                    <Tooltip />
                    <Legend />
                    <Line 
                      type="monotone" 
                      dataKey="users" 
                      stroke="#8884d8" 
                      activeDot={{ r: 8 }}
                      strokeWidth={2}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </Card.Body>
          </Card>
        </Col>

        <Col lg={4} className="mb-4">
          <Card className="border-0 shadow-sm h-100">
            <Card.Body>
              <Card.Title className="d-flex justify-content-between align-items-center">
                <span>Security Events</span>
                <Badge bg="light" text="dark">
                  <i className="bi bi-pie-chart me-1"></i>
                  Distribution
                </Badge>
              </Card.Title>
              <div style={{ height: '300px' }}>
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={securityEventData}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      label={({ name }) => name}
                      outerRadius={80}
                      fill="#8884d8"
                      dataKey="count"
                    >
                      {securityEventData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </Card.Body>
          </Card>
        </Col>
      </Row>

      {/* Users Management */}
      <Row className="mb-4">
        <Col>
          <Card className="border-0 shadow-sm">
            <Card.Body>
              <Card.Title className="d-flex justify-content-between align-items-center mb-4">
                <span>User Management</span>
                <div className="d-flex gap-2">
                  <Button variant="outline-primary" size="sm">
                    <i className="bi bi-plus me-1"></i>
                    Add User
                  </Button>
                  <Button 
                    variant="outline-success" 
                    size="sm"
                    onClick={() => handleExportAuditLogs('csv')}
                    disabled={exporting}
                  >
                    {exporting ? (
                      <Spinner size="sm" animation="border" className="me-1" />
                    ) : (
                      <i className="bi bi-download me-1"></i>
                    )}
                    Export Logs
                  </Button>
                </div>
              </Card.Title>
              <div className="table-responsive">
                <Table hover>
                  <thead>
                    <tr>
                      <th>User</th>
                      <th>Role</th>
                      <th>Status</th>
                      <th>Last Login</th>
                      <th>Department</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {dashboardData.users.map((user) => (
                      <tr key={user._id}>
                        <td>
                          <div>
                            <strong>{user.name}</strong>
                            <div className="small text-muted">{user.email}</div>
                          </div>
                        </td>
                        <td>{getRoleBadge(user.role)}</td>
                        <td>
                          {user.isLocked ? getStatusBadge('locked') : 
                           user.isActive ? getStatusBadge('active') : 
                           getStatusBadge('inactive')}
                        </td>
                        <td>
                          {user.lastLogin ? (
                            <small className="text-muted">
                              {new Date(user.lastLogin).toLocaleDateString()}
                            </small>
                          ) : (
                            <Badge bg="secondary">Never</Badge>
                          )}
                        </td>
                        <td>{user.department || 'N/A'}</td>
                        <td>
                          <Dropdown>
                            <Dropdown.Toggle variant="light" size="sm" id="dropdown-basic">
                              <i className="bi bi-gear"></i>
                            </Dropdown.Toggle>
                            <Dropdown.Menu>
                              <Dropdown.Item onClick={() => handleUserAction(user._id, 'view')}>
                                <i className="bi bi-eye me-2"></i>
                                View Details
                              </Dropdown.Item>
                              <Dropdown.Item onClick={() => handleUserAction(user._id, 'force_reset')}>
                                <i className="bi bi-key me-2"></i>
                                Force Password Reset
                              </Dropdown.Item>
                              {user.isLocked ? (
                                <Dropdown.Item onClick={() => handleUserAction(user._id, 'unlock')}>
                                  <i className="bi bi-unlock me-2"></i>
                                  Unlock Account
                                </Dropdown.Item>
                              ) : (
                                <Dropdown.Item 
                                  onClick={() => handleUserAction(user._id, 'lock')}
                                  className="text-danger"
                                >
                                  <i className="bi bi-lock me-2"></i>
                                  Lock Account
                                </Dropdown.Item>
                              )}
                            </Dropdown.Menu>
                          </Dropdown>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              </div>
            </Card.Body>
          </Card>
        </Col>
      </Row>

      {/* Recent Security Events */}
      <Row>
        <Col>
          <Card className="border-0 shadow-sm">
            <Card.Body>
              <Card.Title className="d-flex justify-content-between align-items-center mb-4">
                <span>Recent Security Events</span>
                <Badge bg="warning" text="dark">
                  {dashboardData.securityEvents.length} Events
                </Badge>
              </Card.Title>
              <div className="table-responsive">
                <Table hover>
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Event</th>
                      <th>User/IP</th>
                      <th>Severity</th>
                      <th>Details</th>
                    </tr>
                  </thead>
                  <tbody>
                    {dashboardData.securityEvents.map((event, index) => (
                      <tr key={index}>
                        <td>
                          <small className="text-muted">
                            {new Date(event.createdAt).toLocaleTimeString([], { 
                              hour: '2-digit', 
                              minute: '2-digit' 
                            })}
                          </small>
                        </td>
                        <td>
                          <strong>{event.action}</strong>
                          {event.isSuspicious && (
                            <Badge bg="danger" className="ms-2">Suspicious</Badge>
                          )}
                        </td>
                        <td>
                          <div>
                            <div className="small">{event.email || 'Unknown'}</div>
                            <code className="small text-muted">{event.ipAddress}</code>
                          </div>
                        </td>
                        <td>
                          <Badge 
                            style={{ 
                              backgroundColor: getSecurityLevelColor(event.metadata?.severity) 
                            }}
                          >
                            {event.metadata?.severity || 'Low'}
                          </Badge>
                        </td>
                        <td>
                          <Button variant="outline-info" size="sm">
                            Details
                          </Button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              </div>
            </Card.Body>
          </Card>
        </Col>
      </Row>

      {/* User Details Modal */}
      <Modal show={showUserModal} onHide={() => setShowUserModal(false)} size="lg">
        <Modal.Header closeButton>
          <Modal.Title>
            <i className="bi bi-person-badge me-2"></i>
            User Details
          </Modal.Title>
        </Modal.Header>
        <Modal.Body>
          {selectedUser && (
            <Row>
              <Col md={4}>
                <div className="text-center mb-4">
                  <div className="bg-primary bg-opacity-10 rounded-circle d-inline-flex align-items-center justify-content-center mb-3" 
                       style={{ width: '100px', height: '100px' }}>
                    <i className="bi bi-person" style={{ fontSize: '3rem' }}></i>
                  </div>
                  <h5>{selectedUser.name}</h5>
                  <div className="d-flex justify-content-center gap-2 mb-3">
                    {getRoleBadge(selectedUser.role)}
                    {selectedUser.isLocked ? getStatusBadge('locked') : 
                     selectedUser.isActive ? getStatusBadge('active') : 
                     getStatusBadge('inactive')}
                  </div>
                </div>
              </Col>
              <Col md={8}>
                <Table borderless size="sm">
                  <tbody>
                    <tr>
                      <th width="30%">Email:</th>
                      <td>{selectedUser.email}</td>
                    </tr>
                    <tr>
                      <th>Student ID:</th>
                      <td>{selectedUser.studentId || 'N/A'}</td>
                    </tr>
                    <tr>
                      <th>Department:</th>
                      <td>{selectedUser.department || 'N/A'}</td>
                    </tr>
                    <tr>
                      <th>Phone:</th>
                      <td>{selectedUser.phone || 'N/A'}</td>
                    </tr>
                    <tr>
                      <th>Account Created:</th>
                      <td>{new Date(selectedUser.createdAt).toLocaleDateString()}</td>
                    </tr>
                    <tr>
                      <th>Last Login:</th>
                      <td>
                        {selectedUser.lastLogin ? 
                          new Date(selectedUser.lastLogin).toLocaleString() : 
                          'Never'
                        }
                      </td>
                    </tr>
                    <tr>
                      <th>Email Verified:</th>
                      <td>
                        {selectedUser.isVerified ? 
                          <Badge bg="success">Yes</Badge> : 
                          <Badge bg="warning">No</Badge>
                        }
                      </td>
                    </tr>
                    <tr>
                      <th>Login Attempts:</th>
                      <td>
                        {selectedUser.loginAttempts > 0 ? (
                          <Badge bg="danger">{selectedUser.loginAttempts} failed</Badge>
                        ) : (
                          <Badge bg="success">None</Badge>
                        )}
                      </td>
                    </tr>
                  </tbody>
                </Table>
              </Col>
            </Row>
          )}
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShowUserModal(false)}>
            Close
          </Button>
          <Button variant="primary">
            <i className="bi bi-pencil me-1"></i>
            Edit User
          </Button>
        </Modal.Footer>
      </Modal>
    </Container>
  );
};

export default AdminDashboard;