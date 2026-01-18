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
  Modal,
  Form
} from 'react-bootstrap';
import { useAuth } from '../../services/auth';
import api from '../../services/api';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  PieChart, Pie, Cell, ResponsiveContainer
} from 'recharts';

const StudentDashboard = () => {
  const { user } = useAuth();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [dashboardData, setDashboardData] = useState({
    grades: [],
    courses: [],
    attendance: [],
    upcomingAssignments: [],
    statistics: {}
  });
  const [showEncryptionModal, setShowEncryptionModal] = useState(false);
  const [encryptionData, setEncryptionData] = useState({
    text: '',
    encrypted: '',
    decrypted: ''
  });
  const [isEncrypting, setIsEncrypting] = useState(false);

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      setError(null);

      // In a real app, these would be actual API calls
      // Mock data for demonstration
      setTimeout(() => {
        const mockData = {
          grades: [
            { course: 'Computer Science 101', grade: 'A', credits: 3, semester: 'Fall 2024' },
            { course: 'Mathematics 201', grade: 'B+', credits: 4, semester: 'Fall 2024' },
            { course: 'Physics 101', grade: 'A-', credits: 3, semester: 'Spring 2024' },
            { course: 'English 101', grade: 'B', credits: 3, semester: 'Spring 2024' },
          ],
          courses: [
            { name: 'Data Structures', code: 'CS201', instructor: 'Dr. Smith', time: 'MWF 10:00' },
            { name: 'Algorithms', code: 'CS301', instructor: 'Dr. Johnson', time: 'TTH 11:00' },
            { name: 'Database Systems', code: 'CS401', instructor: 'Dr. Williams', time: 'MWF 2:00' },
          ],
          attendance: [
            { course: 'Data Structures', present: 18, total: 20, percentage: 90 },
            { course: 'Algorithms', present: 16, total: 18, percentage: 89 },
            { course: 'Database Systems', present: 19, total: 20, percentage: 95 },
          ],
          upcomingAssignments: [
            { course: 'Data Structures', assignment: 'Final Project', dueDate: '2024-12-15', status: 'Pending' },
            { course: 'Algorithms', assignment: 'Midterm Exam', dueDate: '2024-11-20', status: 'Upcoming' },
            { course: 'Database Systems', assignment: 'Lab 5', dueDate: '2024-11-10', status: 'Due Soon' },
          ],
          statistics: {
            gpa: 3.65,
            totalCredits: 45,
            completedCourses: 12,
            attendanceRate: 91.3
          }
        };

        setDashboardData(mockData);
        setLoading(false);
      }, 1000);
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error);
      setError('Failed to load dashboard data');
      setLoading(false);
    }
  };

  const handleEncryptionDemo = async () => {
    if (!encryptionData.text.trim()) {
      alert('Please enter text to encrypt');
      return;
    }

    setIsEncrypting(true);
    try {
      // Encrypt text
      const encryptResponse = await api.post('/data/encrypt-text', {
        text: encryptionData.text
      });

      // Decrypt text
      const decryptResponse = await api.post('/data/decrypt-text', {
        encryptedText: encryptResponse.data.data.encrypted
      });

      setEncryptionData({
        ...encryptionData,
        encrypted: encryptResponse.data.data.encrypted,
        decrypted: decryptResponse.data.data.decrypted
      });
    } catch (error) {
      console.error('Encryption demo failed:', error);
      alert('Encryption demo failed: ' + (error.response?.data?.error || error.message));
    } finally {
      setIsEncrypting(false);
    }
  };

  const getGradeColor = (grade) => {
    switch(grade) {
      case 'A': case 'A-': return 'success';
      case 'B+': case 'B': case 'B-': return 'warning';
      case 'C+': case 'C': case 'C-': return 'info';
      default: return 'danger';
    }
  };

  const getAssignmentStatusColor = (status) => {
    switch(status.toLowerCase()) {
      case 'pending': return 'warning';
      case 'upcoming': return 'info';
      case 'due soon': return 'danger';
      case 'completed': return 'success';
      default: return 'secondary';
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
  const gradeChartData = dashboardData.grades.map(grade => ({
    subject: grade.course.split(' ')[0],
    grade: grade.grade === 'A' ? 4.0 : 
           grade.grade === 'A-' ? 3.7 :
           grade.grade === 'B+' ? 3.3 :
           grade.grade === 'B' ? 3.0 :
           grade.grade === 'B-' ? 2.7 : 2.0
  }));

  const attendanceChartData = dashboardData.attendance.map(course => ({
    name: course.course,
    value: course.percentage
  }));

  const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042'];

  return (
    <Container fluid className="py-4">
      <Row className="mb-4">
        <Col>
          <h2 className="fw-bold">
            <i className="bi bi-house-door me-2"></i>
            Student Dashboard
          </h2>
          <p className="text-muted">
            Welcome back, {user?.name}! Here's your academic overview.
          </p>
        </Col>
      </Row>

      {/* Statistics Cards */}
      <Row className="mb-4">
        <Col xl={3} lg={6} md={6} className="mb-4">
          <Card className="border-0 shadow-sm h-100">
            <Card.Body>
              <div className="d-flex justify-content-between align-items-center">
                <div>
                  <h6 className="text-muted mb-2">Current GPA</h6>
                  <h2 className="fw-bold text-primary">{dashboardData.statistics.gpa}</h2>
                </div>
                <div className="bg-primary bg-opacity-10 p-3 rounded">
                  <i className="bi bi-graph-up text-primary" style={{ fontSize: '2rem' }}></i>
                </div>
              </div>
              <small className="text-muted">Out of 4.0 scale</small>
            </Card.Body>
          </Card>
        </Col>

        <Col xl={3} lg={6} md={6} className="mb-4">
          <Card className="border-0 shadow-sm h-100">
            <Card.Body>
              <div className="d-flex justify-content-between align-items-center">
                <div>
                  <h6 className="text-muted mb-2">Total Credits</h6>
                  <h2 className="fw-bold text-success">{dashboardData.statistics.totalCredits}</h2>
                </div>
                <div className="bg-success bg-opacity-10 p-3 rounded">
                  <i className="bi bi-journal-text text-success" style={{ fontSize: '2rem' }}></i>
                </div>
              </div>
              <small className="text-muted">Credits completed</small>
            </Card.Body>
          </Card>
        </Col>

        <Col xl={3} lg={6} md={6} className="mb-4">
          <Card className="border-0 shadow-sm h-100">
            <Card.Body>
              <div className="d-flex justify-content-between align-items-center">
                <div>
                  <h6 className="text-muted mb-2">Attendance Rate</h6>
                  <h2 className="fw-bold text-info">{dashboardData.statistics.attendanceRate}%</h2>
                </div>
                <div className="bg-info bg-opacity-10 p-3 rounded">
                  <i className="bi bi-calendar-check text-info" style={{ fontSize: '2rem' }}></i>
                </div>
              </div>
              <small className="text-muted">Overall attendance</small>
            </Card.Body>
          </Card>
        </Col>

        <Col xl={3} lg={6} md={6} className="mb-4">
          <Card className="border-0 shadow-sm h-100">
            <Card.Body>
              <div className="d-flex justify-content-between align-items-center">
                <div>
                  <h6 className="text-muted mb-2">Completed Courses</h6>
                  <h2 className="fw-bold text-warning">{dashboardData.statistics.completedCourses}</h2>
                </div>
                <div className="bg-warning bg-opacity-10 p-3 rounded">
                  <i className="bi bi-check-circle text-warning" style={{ fontSize: '2rem' }}></i>
                </div>
              </div>
              <small className="text-muted">Courses passed</small>
            </Card.Body>
          </Card>
        </Col>
      </Row>

      {/* Charts Section */}
      <Row className="mb-4">
        <Col lg={6} className="mb-4">
          <Card className="border-0 shadow-sm h-100">
            <Card.Body>
              <Card.Title className="d-flex justify-content-between align-items-center">
                <span>Grade Distribution</span>
                <Badge bg="light" text="dark">
                  <i className="bi bi-bar-chart me-1"></i>
                  Chart
                </Badge>
              </Card.Title>
              <div style={{ height: '300px' }}>
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={gradeChartData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="subject" />
                    <YAxis domain={[0, 4]} />
                    <Tooltip />
                    <Legend />
                    <Bar dataKey="grade" fill="#8884d8" name="Grade Points" />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </Card.Body>
          </Card>
        </Col>

        <Col lg={6} className="mb-4">
          <Card className="border-0 shadow-sm h-100">
            <Card.Body>
              <Card.Title className="d-flex justify-content-between align-items-center">
                <span>Attendance by Course</span>
                <Badge bg="light" text="dark">
                  <i className="bi bi-pie-chart me-1"></i>
                  Pie Chart
                </Badge>
              </Card.Title>
              <div style={{ height: '300px' }}>
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={attendanceChartData}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                      outerRadius={80}
                      fill="#8884d8"
                      dataKey="value"
                    >
                      {attendanceChartData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip />
                    <Legend />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </Card.Body>
          </Card>
        </Col>
      </Row>

      {/* Grades and Courses */}
      <Row className="mb-4">
        <Col lg={6} className="mb-4">
          <Card className="border-0 shadow-sm h-100">
            <Card.Body>
              <Card.Title className="d-flex justify-content-between align-items-center mb-4">
                <span>Recent Grades</span>
                <Button variant="outline-primary" size="sm">
                  View All
                </Button>
              </Card.Title>
              <div className="table-responsive">
                <Table hover>
                  <thead>
                    <tr>
                      <th>Course</th>
                      <th>Grade</th>
                      <th>Credits</th>
                      <th>Semester</th>
                    </tr>
                  </thead>
                  <tbody>
                    {dashboardData.grades.map((grade, index) => (
                      <tr key={index}>
                        <td>
                          <div className="d-flex align-items-center">
                            <i className="bi bi-book me-2"></i>
                            {grade.course}
                          </div>
                        </td>
                        <td>
                          <Badge bg={getGradeColor(grade.grade)}>
                            {grade.grade}
                          </Badge>
                        </td>
                        <td>{grade.credits}</td>
                        <td>
                          <small className="text-muted">{grade.semester}</small>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              </div>
            </Card.Body>
          </Card>
        </Col>

        <Col lg={6} className="mb-4">
          <Card className="border-0 shadow-sm h-100">
            <Card.Body>
              <Card.Title className="d-flex justify-content-between align-items-center mb-4">
                <span>Current Courses</span>
                <Button variant="outline-primary" size="sm">
                  View All
                </Button>
              </Card.Title>
              <div className="table-responsive">
                <Table hover>
                  <thead>
                    <tr>
                      <th>Course</th>
                      <th>Instructor</th>
                      <th>Schedule</th>
                    </tr>
                  </thead>
                  <tbody>
                    {dashboardData.courses.map((course, index) => (
                      <tr key={index}>
                        <td>
                          <div>
                            <strong>{course.code}</strong>
                            <div className="small text-muted">{course.name}</div>
                          </div>
                        </td>
                        <td>
                          <div className="d-flex align-items-center">
                            <i className="bi bi-person me-2"></i>
                            {course.instructor}
                          </div>
                        </td>
                        <td>
                          <Badge bg="light" text="dark">
                            {course.time}
                          </Badge>
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

      {/* Upcoming Assignments */}
      <Row>
        <Col>
          <Card className="border-0 shadow-sm">
            <Card.Body>
              <Card.Title className="d-flex justify-content-between align-items-center mb-4">
                <span>Upcoming Assignments</span>
                <Button 
                  variant="outline-info" 
                  size="sm"
                  onClick={() => setShowEncryptionModal(true)}
                >
                  <i className="bi bi-lock me-1"></i>
                  Encryption Demo
                </Button>
              </Card.Title>
              <div className="table-responsive">
                <Table hover>
                  <thead>
                    <tr>
                      <th>Course</th>
                      <th>Assignment</th>
                      <th>Due Date</th>
                      <th>Status</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {dashboardData.upcomingAssignments.map((assignment, index) => (
                      <tr key={index}>
                        <td>
                          <div className="d-flex align-items-center">
                            <i className="bi bi-journal me-2"></i>
                            {assignment.course}
                          </div>
                        </td>
                        <td>{assignment.assignment}</td>
                        <td>
                          <Badge bg="light" text="dark">
                            {new Date(assignment.dueDate).toLocaleDateString()}
                          </Badge>
                        </td>
                        <td>
                          <Badge bg={getAssignmentStatusColor(assignment.status)}>
                            {assignment.status}
                          </Badge>
                        </td>
                        <td>
                          <Button variant="outline-primary" size="sm">
                            Submit
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

      {/* Encryption Demo Modal */}
      <Modal show={showEncryptionModal} onHide={() => setShowEncryptionModal(false)} size="lg">
        <Modal.Header closeButton>
          <Modal.Title>
            <i className="bi bi-lock me-2"></i>
            AES-256 Encryption Demo
          </Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <p className="text-muted mb-4">
            This demonstrates the AES-256-GCM encryption used throughout the application.
            Your data is encrypted at rest and in transit.
          </p>

          <Form>
            <Form.Group className="mb-3">
              <Form.Label>Text to Encrypt</Form.Label>
              <Form.Control
                as="textarea"
                rows={3}
                value={encryptionData.text}
                onChange={(e) => setEncryptionData({
                  ...encryptionData,
                  text: e.target.value
                })}
                placeholder="Enter sensitive text to encrypt..."
              />
            </Form.Group>

            <div className="d-grid mb-4">
              <Button
                variant="primary"
                onClick={handleEncryptionDemo}
                disabled={isEncrypting || !encryptionData.text.trim()}
              >
                {isEncrypting ? (
                  <>
                    <Spinner
                      as="span"
                      animation="border"
                      size="sm"
                      role="status"
                      aria-hidden="true"
                      className="me-2"
                    />
                    Encrypting & Decrypting...
                  </>
                ) : (
                  'Encrypt & Decrypt'
                )}
              </Button>
            </div>

            {encryptionData.encrypted && (
              <>
                <Form.Group className="mb-3">
                  <Form.Label>Encrypted Text (Base64)</Form.Label>
                  <Form.Control
                    as="textarea"
                    rows={3}
                    value={encryptionData.encrypted}
                    readOnly
                    className="bg-light"
                  />
                  <Form.Text className="text-muted">
                    This is how your data is stored in the database
                  </Form.Text>
                </Form.Group>

                <Form.Group className="mb-3">
                  <Form.Label>Decrypted Text</Form.Label>
                  <Form.Control
                    as="textarea"
                    rows={3}
                    value={encryptionData.decrypted}
                    readOnly
                    className="bg-light"
                  />
                  <Form.Text className="text-success">
                    <i className="bi bi-check-circle me-1"></i>
                    Successfully decrypted back to original text
                  </Form.Text>
                </Form.Group>
              </>
            )}
          </Form>

          <Alert variant="info" className="mt-4">
            <i className="bi bi-info-circle me-2"></i>
            <strong>Security Note:</strong> This uses AES-256-GCM encryption with 
            authentication tags to ensure data integrity. The encryption key is 
            securely stored and never transmitted.
          </Alert>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShowEncryptionModal(false)}>
            Close
          </Button>
        </Modal.Footer>
      </Modal>
    </Container>
  );
};

export default StudentDashboard;