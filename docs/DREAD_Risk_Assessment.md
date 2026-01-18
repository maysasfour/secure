# DREAD Risk Assessment Report

## Application Name: SecureCampus Portal
## Assessment Date: 17/1/2026
## Assessor: Mays Asfour

## DREAD Scoring Methodology
Each threat is scored from 1-10 in five categories:
- **Damage Potential (D)**: How bad would an attack be?
- **Reproducibility (R)**: How easy is it to reproduce the attack?
- **Exploitability (E)**: How easy is it to launch the attack?
- **Affected Users (A)**: How many users would be affected?
- **Discoverability (D)**: How easy is it to find the vulnerability?

**Risk Levels:**
- **High**: 30-50 points (Immediate action required)
- **Medium**: 20-29 points (Address in next release)
- **Low**: 1-19 points (Monitor and address when possible)

## Risk Assessment Matrix

| Threat | D | R | E | A | D | Total | Risk Level |
|--------|---|---|---|---|---|-------|------------|
| SQL Injection | 9 | 8 | 8 | 9 | 8 | **42** | High |
| Cross-Site Scripting (XSS) | 8 | 7 | 7 | 8 | 7 | **37** | High |
| Session Hijacking | 7 | 6 | 6 | 7 | 6 | **32** | High |
| CSRF Attacks | 6 | 5 | 5 | 6 | 5 | **27** | Medium |
| Insecure Direct Object References | 7 | 6 | 6 | 5 | 6 | **30** | High |
| Brute Force Attacks | 4 | 3 | 2 | 4 | 3 | **16** | Low |
| Information Leakage | 5 | 4 | 4 | 6 | 5 | **24** | Medium |
| API Abuse | 3 | 2 | 3 | 4 | 3 | **15** | Low |
| File Upload Vulnerabilities | 6 | 5 | 5 | 5 | 4 | **25** | Medium |
| Privilege Escalation | 8 | 7 | 6 | 7 | 7 | **35** | High |

## Detailed Threat Analysis

### 1. SQL Injection (High Risk - 42)
**Description**: Attackers inject malicious SQL through user input
**Impact**: Complete database compromise
**Mitigation**:
- Use parameterized queries with Mongoose
- Implement input validation
- Regular security scanning
- Database permission hardening

### 2. Cross-Site Scripting (High Risk - 37)
**Description**: Malicious scripts injected into web pages
**Impact**: Session theft, defacement
**Mitigation**:
- Output encoding
- CSP headers
- DOMPurify for sanitization
- Regular XSS testing

### 3. Session Hijacking (High Risk - 32)
**Description**: Stealing active user sessions
**Impact**: Account takeover
**Mitigation**:
- Secure cookie settings
- Session timeout
- Token regeneration
- IP binding for sessions

### 4. CSRF Attacks (Medium Risk - 27)
**Description**: Unauthorized actions performed on behalf of user
**Impact**: Unintended data modifications
**Mitigation**:
- Anti-CSRF tokens
- SameSite cookie attribute
- Double submit cookie pattern

### 5. Brute Force Attacks (Low Risk - 16)
**Description**: Automated password guessing
**Impact**: Account compromise
**Mitigation**:
- Account lockout
- CAPTCHA implementation
- Rate limiting
- Strong password policies

## Risk Treatment Strategy

### Immediate Actions (High Risks):
1. Implement Web Application Firewall
2. Conduct penetration testing
3. Enable security headers
4. Set up intrusion detection

### Short-term Actions (Medium Risks):
1. Regular security patching
2. Security training for developers
3. Implement security monitoring
4. Code review for security

### Long-term Actions (Low Risks):
1. Security awareness program
2. Regular vulnerability scanning
3. Incident response planning
4. Compliance auditing

## Residual Risk Acceptance
- Low risks accepted with monitoring
- Medium risks addressed in next sprint
- High risks must be mitigated before production