# STRIDE Threat Modeling Report

## Application Name: SecureCampus Portal

## Team Members: Mays Asfour 202320044 / 

## Application Overview
SecureCampus Portal is a web application for university students and administrators. It includes authentication, role-based access control, student data management, and administrative functions.

## System Components
1. **Frontend**: React.js application
2. **Backend**: Node.js/Express REST API
3. **Database**: MongoDB with sensitive data encryption
4. **Authentication Service**: JWT-based with refresh tokens
5. **File Storage**: Encrypted student document storage

## Data Flow Diagram
[Include DFD image or description here]

## Threat Identification Table

| Threat Category | Description | Potential Impact | Mitigation Strategies |
|----------------|-------------|------------------|-----------------------|
| **Spoofing** | Attacker uses stolen credentials to impersonate legitimate user | Unauthorized data access, grade manipulation | MFA, strong password policies, account lockout, JWT with signatures |
| **Tampering** | Unauthorized modification of data in transit or at rest | Data integrity loss, grade tampering | HTTPS/TLS, input validation, digital signatures, database constraints |
| **Repudiation** | User denies performing an action | Accountability loss, legal disputes | Comprehensive audit logs, timestamps, signed actions, non-repudiation controls |
| **Information Disclosure** | Sensitive data exposure to unauthorized parties | Privacy violations, identity theft | Encryption at rest & in transit, access controls, data masking, proper error handling |
| **Denial of Service** | Service disruption through resource exhaustion | Application unavailability | Rate limiting, WAF, load balancing, resource monitoring |
| **Elevation of Privilege** | User gains unauthorized higher privileges | System compromise, data breach | RBAC, principle of least privilege, input validation, regular audits |

## Detailed Threat Analysis

### 1. Spoofing Threats
- **Threat**: Credential theft via phishing
- **Impact**: Unauthorized access to student records
- **Mitigation**: 
  - Implement MFA (SMS/authenticator app)
  - Password complexity requirements
  - Account lockout after 5 failed attempts
  - Security awareness training

### 2. Tampering Threats
- **Threat**: Man-in-the-middle attacks altering requests
- **Impact**: Grade manipulation, unauthorized data changes
- **Mitigation**:
  - Enforce HTTPS everywhere
  - Use CSRF tokens
  - Input validation and sanitization
  - Database integrity constraints

### 3. Repudiation Threats
- **Threat**: Student denies submitting assignment
- **Impact**: Academic integrity issues
- **Mitigation**:
  - Comprehensive audit trails
  - Digital signatures for submissions
  - Immutable logging system

### 4. Information Disclosure Threats
- **Threat**: API endpoint exposing sensitive student data
- **Impact**: Privacy violation, regulatory penalties
- **Mitigation**:
  - Field-level encryption
  - Proper access controls
  - Data minimization principle
  - Secure error messages

### 5. Denial of Service Threats
- **Threat**: Botnet attack on login endpoint
- **Impact**: Service unavailability during exams
- **Mitigation**:
  - Rate limiting per IP/user
  - CAPTCHA for suspicious activities
  - DDoS protection service
  - Auto-scaling infrastructure

### 6. Elevation of Privilege Threats
- **Threat**: Student accesses admin functions via IDOR
- **Impact**: System-wide compromise
- **Mitigation**:
  - Proper session management
  - Regular vulnerability scanning
  - Secure coding practices
  - Penetration testing

## Risk Prioritization
1. **High Priority**: Spoofing, Elevation of Privilege
2. **Medium Priority**: Tampering, Information Disclosure
3. **Low Priority**: Repudiation, Denial of Service

## Monitoring & Response
- Real-time security monitoring
- Automated alerting for suspicious activities
- Incident response plan
- Regular security audits