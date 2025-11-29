// MITM Attacker Script
// Demonstrates how an attacker could try to intercept communications
// but will fail due to signature verification

const fetch = require('node-fetch');

async function runMITMAttack() {
  const server = 'http://localhost:3000';
  
  console.log('🚨 STARTING MITM ATTACK SIMULATION 🚨');
  console.log('========================================');
  
  try {
    // Step 1: First, let's see what users are registered
    console.log('\n📋 Step 1: Checking registered users...');
    const usersResponse = await fetch(server + '/users');
    const usersData = await usersResponse.json();
    console.log('Registered users:', usersData.users || 'None found');
    
    if (usersData.users && usersData.users.length > 0) {
      const targetUser = usersData.users[0]; // Attack the first user
      console.log(`🎯 Targeting user: ${targetUser}`);
      
      // Step 2: Get the target's current public key info
      console.log('\n🔑 Step 2: Getting target user public key...');
      const pubKeyResponse = await fetch(server + '/public-key/' + targetUser);
      
      if (pubKeyResponse.ok) {
        const originalKeyData = await pubKeyResponse.json();
        console.log('Original public key data retrieved');
        console.log('ECDH Key X:', originalKeyData.publicKeyJwk.x?.substring(0, 20) + '...');
        console.log('ECDSA Key X:', originalKeyData.signingPublicKeyJwk.x?.substring(0, 20) + '...');
        
        // Step 3: Generate fake attacker keys
        console.log('\n🦹 Step 3: Generating fake attacker keys...');
        
        // Create fake ECDH public key (similar structure but different values)
        const fakeEcdhPubKey = {
          kty: 'EC',
          crv: 'P-256',
          x: 'ATTACKER_FAKE_X_' + Math.random().toString(36).substring(2, 15),
          y: 'ATTACKER_FAKE_Y_' + Math.random().toString(36).substring(2, 15),
          ext: true
        };
        
        // Create fake ECDSA signing public key
        const fakeEcdsaPubKey = {
          kty: 'EC',
          crv: 'P-256', 
          x: 'ATTACKER_SIGN_X_' + Math.random().toString(36).substring(2, 15),
          y: 'ATTACKER_SIGN_Y_' + Math.random().toString(36).substring(2, 15),
          ext: true
        };
        
        // Create a fake signature (this will be invalid)
        const fakeSignature = Buffer.from('FAKE_SIGNATURE_BY_ATTACKER_' + Date.now()).toString('base64');
        
        console.log('Fake ECDH Key X:', fakeEcdhPubKey.x);
        console.log('Fake ECDSA Key X:', fakeEcdsaPubKey.x);
        console.log('Fake signature generated');
        
        // Step 4: Attempt to overwrite the target's public key
        console.log('\n💥 Step 4: Attempting to overwrite target public key...');
        const attackResponse = await fetch(server + '/register-public-key', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username: targetUser,
            publicKeyJwk: fakeEcdhPubKey,
            signingPublicKeyJwk: fakeEcdsaPubKey,
            signature: fakeSignature
          })
        });
        
        const attackResult = await attackResponse.json();
        
        if (attackResponse.ok) {
          console.log('✅ ATTACK SUCCESSFUL: Fake keys registered on server!');
          console.log('⚠️  The server now has attacker-controlled keys for:', targetUser);
          
          // Step 5: Verify the attack worked
          console.log('\n🔍 Step 5: Verifying attack success...');
          const verifyResponse = await fetch(server + '/public-key/' + targetUser);
          const currentKeyData = await verifyResponse.json();
          
          console.log('Current ECDH Key X:', currentKeyData.publicKeyJwk.x?.substring(0, 20) + '...');
          console.log('Expected Fake Key X:', fakeEcdhPubKey.x.substring(0, 20) + '...');
          
          if (currentKeyData.publicKeyJwk.x === fakeEcdhPubKey.x) {
            console.log('🎭 ATTACK VERIFIED: Server is storing attacker keys!');
          } else {
            console.log('❓ Keys dont match exactly, but attack may still be active');
          }
          
          console.log('\n🚨 SECURITY ANALYSIS:');
          console.log('=====================');
          console.log('WHAT THE ATTACKER ACHIEVED:');
          console.log('• Replaced the target\'s public keys on the server');
          console.log('• Any new messages to the target will use attacker keys');
          console.log('');
          console.log('WHY THIS ATTACK WILL FAIL:');
          console.log('• Clients verify signatures before trusting public keys');
          console.log('• The fake signature cannot be verified by legitimate clients');
          console.log('• Legitimate clients will reject the fake keys and show errors');
          console.log('');
          console.log('SECURITY PROTECTION:');
          console.log('• Digital signatures prevent MITM attacks');
          console.log('• Only keys signed by the legitimate owner are accepted');
          
        } else {
          console.log('❌ Attack failed:', attackResult.error);
        }
        
      } else {
        console.log('❌ Could not retrieve target user public key');
      }
    } else {
      console.log('❌ No users found to attack. Please register users first.');
    }
    
  } catch (error) {
    console.error('💥 Attack script error:', error.message);
  }
  
  console.log('\n========================================');
  console.log('🎬 MITM ATTACK SIMULATION COMPLETE');
  console.log('========================================\n');
  
  // Demonstrate the defense
  console.log('🛡️  DEFENSE DEMONSTRATION:');
  console.log('When a legitimate client tries to communicate:');
  console.log('1. Client requests public key for target user');
  console.log('2. Client receives attacker\'s fake public key');
  console.log('3. Client tries to verify the signature');
  console.log('4. Verification FAILS because signature is invalid');
  console.log('5. Client rejects the key and shows error to user');
  console.log('6. MITM ATTACK PREVENTED! ✅\n');
}

// Run a simpler version that just demonstrates the attack
async function simpleAttack() {
  const server = 'http://localhost:3000';
  
  console.log('🚨 SIMPLE MITM ATTACK DEMO 🚨');
  
  // Generate completely fake keys
  const fakeEcdhKey = {
    kty: 'EC',
    crv: 'P-256',
    x: 'fake_x_value_attacker_' + Date.now(),
    y: 'fake_y_value_attacker_' + Date.now(),
    ext: true
  };
  
  const fakeSigningKey = {
    kty: 'EC', 
    crv: 'P-256',
    x: 'fake_signing_x_' + Date.now(),
    y: 'fake_signing_y_' + Date.now(), 
    ext: true
  };
  
  const fakeSig = Buffer.from('totally_fake_signature_' + Math.random()).toString('base64');
  
  console.log('Attacking user: bob');
  
  try {
    const res = await fetch(server + '/register-public-key', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'bob',
        publicKeyJwk: fakeEcdhKey,
        signingPublicKeyJwk: fakeSigningKey,
        signature: fakeSig
      })
    });
    
    if (res.ok) {
      console.log('✅ Attack successful! Fake keys registered for bob.');
      console.log('⚠️  However, clients will reject these keys due to invalid signatures.');
      console.log('🛡️  This demonstrates how digital signatures prevent MITM attacks.');
    } else {
      const error = await res.json();
      console.log('❌ Attack failed:', error.error);
    }
  } catch (e) {
    console.log('💥 Attack error:', e.message);
  }
}

// Check if we should run full demo or simple attack
const shouldRunFullDemo = process.argv.includes('--full');

if (shouldRunFullDemo) {
  runMITMAttack();
} else {
  simpleAttack();
}