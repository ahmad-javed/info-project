// Attacker script demonstrates that overwriting the victim's publicKey on the server
// is not enough if clients verify signatures. This script will register an attacker
// key for 'bob', but it cannot provide a valid signature by Bob, so any honest client
// verifying the signature will reject the fake key.
const fetch = require('node-fetch');

async function run(){
  const server = 'http://localhost:3000';
  
  // Generate fake keys (these won't have valid signatures)
  const fakePub = { 
    kty: 'EC', 
    crv: 'P-256', 
    x: 'FAKE_X_ATTACKER_MITM', 
    y: 'FAKE_Y_ATTACKER_MITM', 
    ext: true 
  };
  
  const fakeSigningPub = { 
    kty: 'EC', 
    crv: 'P-256', 
    x: 'FAKE2_X_ATTACKER_MITM', 
    y: 'FAKE2_Y_ATTACKER_MITM', 
    ext: true 
  };
  
  const fakeSig = Buffer.from('fake-signature-by-attacker').toString('base64');
  
  console.log('🚨 MITM ATTACKER: Attempting to overwrite bob\'s public key...');
  
  // Overwrite bob's entry with attacker's keys/signature
  const res = await fetch(server + '/register-public-key', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: 'bob',
      publicKeyJwk: fakePub,
      signingPublicKeyJwk: fakeSigningPub,
      signature: fakeSig
    })
  });
  
  const result = await res.json();
  
  if (res.ok) {
    console.log('✅ Attacker successfully wrote fake entries for bob.');
    console.log('⚠️  However, honest clients should reject this due to invalid signature verification.');
  } else {
    console.log('❌ Attack failed:', result.error);
  }
  
  console.log('Server response status:', res.status);
}

run().catch(e => console.error('Attack error:', e));