#!/bin/bash

echo "🔒 Setting up Google reCAPTCHA Enterprise for SecureCampus Portal"
echo "================================================================"

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js first."
    exit 1
fi

# Check if npm is installed
if ! command -v npm &> /dev/null; then
    echo "❌ npm is not installed. Please install npm first."
    exit 1
fi

echo "✅ Node.js and npm are installed"

# Install required packages
echo "📦 Installing required packages..."
cd backend
npm install @google-cloud/recaptcha-enterprise

echo ""
echo "📋 Configuration Summary:"
echo "========================="
echo "Project ID: secret-timing-397615"
echo "Site Key: 6LfPqE4sAAAAACBKer-6qKwg5xFXSRDtDRSyjdSp"
echo ""
echo "📝 Next Steps:"
echo "1. Enable reCAPTCHA Enterprise API in Google Cloud Console:"
echo "   https://console.cloud.google.com/apis/library/recaptchaenterprise.googleapis.com"
echo ""
echo "2. Create a service account with reCAPTCHA Enterprise Admin role"
echo ""
echo "3. Download service account key and save as backend/service-account-key.json"
echo ""
echo "4. Update backend/.env with:"
echo "   ENABLE_RECAPTCHA=true"
echo "   GOOGLE_CLOUD_PROJECT_ID=secret-timing-397615"
echo "   RECAPTCHA_SITE_KEY=6LfPqE4sAAAAACBKer-6qKwg5xFXSRDtDRSyjdSp"
echo "   RECAPTCHA_THRESHOLD=0.5"
echo "   GOOGLE_APPLICATION_CREDENTIALS=./service-account-key.json"
echo ""
echo "5. Update frontend/.env with:"
echo "   REACT_APP_RECAPTCHA_SITE_KEY=6LfPqE4sAAAAACBKer-6qKwg5xFXSRDtDRSyjdSp"
echo ""
echo "6. Restart the application:"
echo "   docker-compose down && docker-compose up --build -d"
echo ""
echo "✅ reCAPTCHA Enterprise setup instructions completed!"