# SecureCampus Portal 🏫🔒

![Security Shield](https://img.shields.io/badge/Security-Level%20A-green)
![Node.js](https://img.shields.io/badge/Node.js-18.x-blue)
![React](https://img.shields.io/badge/React-18.x-blue)
![MongoDB](https://img.shields.io/badge/MongoDB-6.x-green)
![Docker](https://img.shields.io/badge/Docker-✓-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)

A secure web application demonstrating comprehensive security practices for university student and administrator portals. This project was developed as part of the Application Security and Secure Code course.

## 📋 Table of Contents

- [Features](#features)
- [Security Implementations](#security-implementations)
- [Technology Stack](#technology-stack)
- [Architecture](#architecture)
- [Installation](#installation)
- [Deployment](#deployment)
- [Security Scanning](#security-scanning)
- [API Documentation](#api-documentation)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)

## ✨ Features

### 🔐 Security Features
- ✅ **JWT-based authentication** with refresh tokens
- ✅ **Role-based access control** (Admin/Student/Faculty)
- ✅ **Password hashing** using bcrypt with 12 rounds
- ✅ **AES-256 encryption** for sensitive data at rest
- ✅ **Input validation** and sanitization
- ✅ **Rate limiting** and CAPTCHA protection
- ✅ **Security headers** (Helmet.js, CSP, CORS)
- ✅ **Comprehensive audit logging**
- ✅ **Session management** with secure cookies
- ✅ **STRIDE threat modeling** and **DREAD risk assessment**

### 🎯 Functional Features
- **User Registration & Login** with email verification
- **Student Dashboard** with grades, courses, and attendance
- **Admin Dashboard** with user management and security insights
- **Profile Management** with password change and session control
- **Secure Data Management** with encryption demo
- **Audit Log Viewer** for security monitoring
- **Responsive Design** with Bootstrap 5

## 🛡️ Security Implementations

### Authentication & Authorization
- JWT tokens with 15-minute expiry and refresh tokens
- Multi-factor authentication support
- Account lockout after 5 failed attempts
- Session timeout after 24 hours of inactivity

### Data Protection
- **AES-256-GCM encryption** for sensitive fields
- **HTTPS/TLS 1.2+** for all communications
- **Input validation** using express-validator
- **Output sanitization** with DOMPurify
- **Parameterized queries** to prevent SQL injection

### Application Security
- **Security headers** (Helmet.js)
- **Content Security Policy** (CSP)
- **Cross-Origin Resource Sharing** (CORS) with whitelist
- **Rate limiting** per IP and user
- **CAPTCHA integration** for critical endpoints

### Monitoring & Auditing
- Comprehensive audit trail for all security-relevant actions
- Real-time security event monitoring
- Suspicious activity detection and alerting
- 90-day log retention with integrity checks

## 🛠️ Technology Stack

### Frontend
- **React 18** with hooks and context API
- **Bootstrap 5** for responsive design
- **Axios** for HTTP requests
- **React Router v6** for navigation
- **Recharts** for data visualization
- **DOMPurify** for output sanitization

### Backend
- **Node.js 18** with Express.js
- **MongoDB 6** with Mongoose ODM
- **JWT** for authentication
- **Bcrypt** for password hashing
- **Crypto-js** for encryption
- **Express-validator** for input validation
- **Helmet.js** for security headers

### Security Tools
- **GitHub CodeQL** for static analysis
- **SonarQube** for code quality
- **Snyk** for dependency scanning
- **OWASP Dependency Check**
- **ESLint Security Plugin**

## 🏗️ Architecture

┌─────────────────────────────────────────────────────────────┐
│ Frontend │
│ (React SPA on Nginx) │
└──────────────────────────────┬──────────────────────────────┘
│ HTTPS
┌──────────────────────────────▼──────────────────────────────┐
│ Backend API │
│ (Node.js/Express) │
└──────────────────────────────┬──────────────────────────────┘
│
┌──────────────┼──────────────┐
▼ ▼ ▼
┌──────────────┐┌──────────────┐┌──────────────┐
│ MongoDB ││ Redis ││ Audit Logs │
│ Database ││ Cache ││ (Files) │
└──────────────┘└──────────────┘└──────────────┘


## 🚀 Installation

### Prerequisites
- Node.js 18.x or higher
- MongoDB 6.x or higher
- Docker and Docker Compose (optional)
- Git

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/secure-campus-portal.git
cd secure-campus-portal