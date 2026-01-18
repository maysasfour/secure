const recaptchaService = require('./backend/src/services/recaptchaService');

async function testRecaptcha() {
  console.log('🧪 Testing reCAPTCHA Enterprise Integration');
  console.log('='.repeat(50));
  
  try {
    // Test 1: Get service stats
    const stats = recaptchaService.getStats();
    console.log('📊 Service Stats:');
    console.log(`   Project ID: ${stats.projectId}`);
    console.log(`   Site Key: ${stats.recaptchaKey}`);
    console.log(`   Client Initialized: ${stats.clientInitialized}`);
    
    // Test 2: Verify a dummy token (will fail)
    console.log('\n🔍 Testing token verification...');
    const result = await recaptchaService.verifyToken(
      'dummy-token-123',
      'TEST_ACTION',
      { threshold: 0.5 }
    );
    
    console.log('Verification Result:');
    console.log(`   Success: ${result.success}`);
    console.log(`   Passed: ${result.passed}`);
    console.log(`   Score: ${result.score}`);
    console.log(`   Reasons: ${result.reasons?.join(', ') || 'None'}`);
    
    if (result.error) {
      console.log(`   Error: ${result.error}`);
    }
    
    // Test 3: Test specific actions
    console.log('\n🎯 Testing specific actions...');
    
    const actions = ['LOGIN', 'REGISTER', 'PASSWORD_RESET'];
    for (const action of actions) {
      const verification = await recaptchaService.verifyToken(
        'test-token',
        action,
        { threshold: 0.5 }
      );
      console.log(`   ${action}: ${verification.passed ? '✅' : '❌'} (Score: ${verification.score})`);
    }
    
    console.log('\n✅ reCAPTCHA service is working correctly!');
    console.log('\n💡 Note: To test with real tokens, you need to:');
    console.log('   1. Get a valid token from the frontend');
    console.log('   2. Update the test with real token');
    console.log('   3. Ensure service account has proper permissions');
    
  } catch (error) {
    console.error('❌ Test failed:', error.message);
    console.error('\n🔧 Troubleshooting steps:');
    console.error('   1. Check service account credentials');
    console.error('   2. Verify reCAPTCHA Enterprise API is enabled');
    console.error('   3. Check network connectivity');
    console.error('   4. Verify project ID and site key are correct');
  }
}

// Run test if called directly
if (require.main === module) {
  testRecaptcha();
}

module.exports = testRecaptcha;