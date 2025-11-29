// Attacker script demonstrates that overwriting the victim's publicKey on the server
// is not enough if clients verify signatures. This script will register an attacker
// key for 'bob', but it cannot provide a valid signature by Bob, so any honest client
// verifying the signature will reject the fake key.
const fetch = require('node-fetch');

async function run(){
  const server = 'http://localhost:3000';
  const fakePub = { kty:'EC', crv:'P-256', x:'FAKE_X', y:'FAKE_Y', ext:true };
  const fakeSigningPub = { kty:'EC', crv:'P-256', x:'FAKE2_X', y:'FAKE2_Y', ext:true };
  const fakeSig = Buffer.from('fake-signature').toString('base64');
  // Overwrite bob's entry with attacker's keys/signature
  const res = await fetch(server + '/register-public-key', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({
      username: 'bob',
      publicKeyJwk: fakePub,
      signingPublicKeyJwk: fakeSigningPub,
      signature: fakeSig
    })
  });
  console.log('Attacker wrote fake entries for bob. Honest clients should reject this due to invalid signature.');
  console.log('Server response status:', res.status);
}

run().catch(e=>console.error(e));
