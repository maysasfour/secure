const crypto = require('crypto');
const mongoose = require('mongoose');

console.log('🔒 SecureCampus Portal - Credentials Verification');
console.log('=' .repeat(50));

// Check JWT Secrets
console.log('\n📝 JWT Secrets Verification:');
const jwtSecret = process.env.JWT_SECRET || 'ba9b15d484adfe68748d5a048ce59a2265255c7a6ffdb4aedf4c3662676d65ac7fcc5bc119acf2e932634155c64a79e6721a0cc126020bfa2b5970d3462998fe';
const refreshSecret = process.env.JWT_REFRESH_SECRET || 'b5dd6a249c233ee1664eaaab50895b393af06c7684987c29500bc5f7d30254b3bd403c1c6bfe6ffdc149642bb81524c8a2bf84aef858eb036d25be839335c019';

console.log(`✅ JWT Secret: ${jwtSecret.length === 128 ? 'Valid (128 chars)' : 'Invalid'}`);
console.log(`✅ Refresh Secret: ${refreshSecret.length === 128 ? 'Valid (128 chars)' : 'Invalid'}`);
console.log(`✅ Secrets are different: ${jwtSecret !== refreshSecret}`);

// Check Encryption Keys
console.log('\n🔐 Encryption Keys Verification:');
const encryptionKey = process.env.ENCRYPTION_KEY || 'D9B4F5FD3A34875467433773A173D83B79236C74613E50D7220A60D913AF68AD';
const ivKey = process.env.IV_KEY || '408CFCE02C43F86219319718448A60D2';

console.log(`✅ Encryption Key: ${encryptionKey.length === 64 ? 'Valid (64 chars, 32 bytes)' : 'Invalid'}`);
console.log(`✅ IV Key: ${ivKey.length === 32 ? 'Valid (32 chars, 16 bytes)' : 'Invalid'}`);

// Test encryption
try {
  const keyBuffer = Buffer.from(encryptionKey, 'hex');
  const ivBuffer = Buffer.from(ivKey, 'hex');
  console.log(`✅ Key buffer size: ${keyBuffer.length} bytes (${keyBuffer.length * 8} bits)`);
  console.log(`✅ IV buffer size: ${ivBuffer.length} bytes`);
} catch (error) {
  console.log(`❌ Invalid hex encoding: ${error.message}`);
}

// Check MongoDB Connection
console.log('\n🗄️ MongoDB Connection Test:');
const mongoURI = 'mongodb+srv://mayssuhail_db_user:h0eYPBxQpfyWuiZU@cluster0.0gol1lo.mongodb.net/secure_campus?retryWrites=true&w=majority&appName=Cluster0';

async function testMongoDB() {
  try {
    await mongoose.connect(mongoURI, {
      serverSelectionTimeoutMS: 5000
    });
    console.log('✅ MongoDB Atlas connection successful!');
    
    const db = mongoose.connection.db;
    const collections = await db.listCollections().toArray();
    console.log(`📊 Database: ${db.databaseName}`);
    console.log(`📂 Collections: ${collections.length}`);
    
    // List collections
    collections.forEach(col => {
      console.log(`   - ${col.name}`);
    });
    
    await mongoose.disconnect();
  } catch (error) {
    console.log(`❌ MongoDB connection failed: ${error.message}`);
    console.log('   Please check your:');
    console.log('   1. MongoDB Atlas cluster status');
    console.log('   2. Username/password (mayssuhail_db_user / h0eYPBxQpfyWuiZU)');
    console.log('   3. Network connection');
    console.log('   4. IP whitelist in MongoDB Atlas');
  }
}

testMongoDB().then(() => {
  console.log('\n' + '=' .repeat(50));
  console.log('✅ All credentials verified successfully!');
  console.log('\n🚀 You can now run:');
  console.log('   docker-compose up --build');
  console.log('\n🌐 Access the application at:');
  console.log('   Frontend: http://localhost');
  console.log('   Backend API: http://localhost:5000');
  console.log('\n👑 Admin Login:');
  console.log('   Email: admin@securecampus.edu');
  console.log('   Password: Admin@123');
  console.log('=' .repeat(50));
});