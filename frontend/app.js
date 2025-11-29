// Complete client-side logic:
// - Create account: generate ECDH + ECDSA keypairs, export public keys, sign public key JWK using ECDSA,
//   encrypt both private JWKs using a password-derived AES-GCM key (PBKDF2) and store in localStorage.
// - Login: decrypt private keys using password.
// - Register: POST publicKeyJwk, signingPublicKeyJwk, signature to server.
// - Send: derive shared secret (ECDH), HKDF it to AES-GCM key, encrypt message, send ciphertext + iv + seq + timestamp.
// - Fetch: fetch messages, verify sender's public key signature using signingPublicKeyJwk before decrypting.

const server = 'http://localhost:3000';
const logEl = document.getElementById('log');

function log(...args){ logEl.textContent += '\n' + args.map(a=>typeof a === 'string' ? a : JSON.stringify(a)).join(' '); }

// Utilities
function buf2b64(b){ return btoa(String.fromCharCode(...new Uint8Array(b))); }
function b642buf(s){ return Uint8Array.from(atob(s), c=>c.charCodeAt(0)); }
function str2ab(s){ return new TextEncoder().encode(s); }
function ab2str(ab){ return new TextDecoder().decode(ab); }

// PBKDF2: derive AES-GCM 256-bit key from password + salt
async function deriveKeyFromPassword(password, salt, iterations=200000){
  const pwKey = await crypto.subtle.importKey('raw', str2ab(password), {name:'PBKDF2'}, false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    {name:'PBKDF2', salt, iterations, hash:'SHA-256'},
    pwKey,
    {name:'AES-GCM', length:256},
    false,
    ['encrypt','decrypt']
  );
  return key;
}

// Encrypt arbitrary JSON with AES-GCM using derived key
async function encryptJSON(key, obj){
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const pt = str2ab(JSON.stringify(obj));
  const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, pt);
  return { iv: buf2b64(iv), ct: buf2b64(ct) };
}

// Decrypt JSON
async function decryptJSON(key, ivB64, ctB64){
  const iv = b642buf(ivB64);
  const ct = b642buf(ctB64);
  const pt = await crypto.subtle.decrypt({name:'AES-GCM', iv}, key, ct);
  return JSON.parse(ab2str(pt));
}

// Create account: generate keys and register
async function createAccount(){
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  if(!username || !password){ alert('enter username and password'); return; }

  log('Generating keys for', username);

  // ECDH keypair (P-256)
  const ecdh = await crypto.subtle.generateKey({name:'ECDH', namedCurve:'P-256'}, true, ['deriveKey','deriveBits']);
  // ECDSA keypair for signing public keys
  const ecdsa = await crypto.subtle.generateKey({name:'ECDSA', namedCurve:'P-256'}, true, ['sign','verify']);

  const pubEcdh = await crypto.subtle.exportKey('jwk', ecdh.publicKey);
  const pubEcdsa = await crypto.subtle.exportKey('jwk', ecdsa.publicKey);
  const privEcdh = await crypto.subtle.exportKey('jwk', ecdh.privateKey);
  const privEcdsa = await crypto.subtle.exportKey('jwk', ecdsa.privateKey);

  // Sign the ECDH public JWK (stringified) using ECDSA private key
  const encoder = new TextEncoder();
  const data = encoder.encode(JSON.stringify(pubEcdh));
  const signature = await crypto.subtle.sign({name:'ECDSA', hash:'SHA-256'}, ecdsa.privateKey, data);
  const sigB64 = buf2b64(signature);

  // Derive storage key from password
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const storageKey = await deriveKeyFromPassword(password, salt);

  // Encrypt private JWKs and store with salt+iv
  const storeObj = {
    privEcdh, privEcdsa
  };
  const enc = await encryptJSON(storageKey, storeObj);

  const blob = { salt: buf2b64(salt), iv: enc.iv, ct: enc.ct };
  localStorage.setItem(username + ':priv_enc', JSON.stringify(blob));

  // Register public keys + signature on server
  const res = await fetch(server + '/register-public-key', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({
      username,
      publicKeyJwk: pubEcdh,
      signingPublicKeyJwk: pubEcdsa,
      signature: sigB64
    })
  });
  const rj = await res.json();
  log('Registered:', rj);
}

// Login: decrypt private keys
async function login(){
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  if(!username || !password) return alert('enter username and password');
  const blobStr = localStorage.getItem(username + ':priv_enc');
  if(!blobStr) return alert('no keys for user; create account first');
  const blob = JSON.parse(blobStr);
  const salt = b642buf(blob.salt);
  const storageKey = await deriveKeyFromPassword(password, salt);
  try{
    const storeObj = await decryptJSON(storageKey, blob.iv, blob.ct);
    // import private keys into CryptoKey objects and keep in memory
    const privEcdh = await crypto.subtle.importKey('jwk', storeObj.privEcdh, {name:'ECDH', namedCurve:'P-256'}, true, ['deriveKey','deriveBits']);
    const privEcdsa = await crypto.subtle.importKey('jwk', storeObj.privEcdsa, {name:'ECDSA', namedCurve:'P-256'}, true, ['sign','verify']);
    // store in-memory for this session
    window._me = { username, privEcdh, privEcdsa };
    log('Logged in as', username);
  }catch(e){
    console.error(e);
    alert('Failed to decrypt keys: wrong password?');
  }
}

// Fetch public key info and verify signature
async function getVerifiedPublicKey(username){
  const r = await fetch(server + '/public-key/' + encodeURIComponent(username));
  if(!r.ok) throw new Error('user not found');
  const j = await r.json();
  const pubEcdh = j.publicKeyJwk;
  const pubEcdsa = j.signingPublicKeyJwk;
  const sig = j.signature;
  // import signing public key
  const spk = await crypto.subtle.importKey('jwk', pubEcdsa, {name:'ECDSA', namedCurve:'P-256'}, true, ['verify']);
  const data = new TextEncoder().encode(JSON.stringify(pubEcdh));
  const valid = await crypto.subtle.verify({name:'ECDSA', hash:'SHA-256'}, spk, Uint8Array.from(atob(sig), c=>c.charCodeAt(0)), data);
  if(!valid) throw new Error('invalid public-key signature for ' + username);
  // import ECDH public key for deriving shared secret
  const pubKey = await crypto.subtle.importKey('jwk', pubEcdh, {name:'ECDH', namedCurve:'P-256'}, true, []);
  return pubKey;
}

// Derive AES-GCM key using ECDH -> HKDF
async function deriveAesKey(privEcdh, theirPubKey){
  // derive raw shared secret bits
  const shared = await crypto.subtle.deriveBits({name:'ECDH', public:theirPubKey}, privEcdh, 256);
  // import as raw key for HKDF
  const rawKey = await crypto.subtle.importKey('raw', shared, {name:'HKDF'}, false, ['deriveKey']);
  // derive AES-GCM key using HKDF-SHA256 with random salt for each message (send salt to receiver)
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const aesKey = await crypto.subtle.deriveKey(
    {name:'HKDF', hash:'SHA-256', salt, info: new Uint8Array([])},
    rawKey,
    {name:'AES-GCM', length:256},
    false,
    ['encrypt','decrypt']
  );
  return { aesKey, salt };
}

// Send encrypted message
async function sendMessage(){
  if(!window._me) return alert('login first');
  const from = window._me.username;
  const to = document.getElementById('to').value;
  const seq = Number(document.getElementById('seq').value) || 1;
  const plaintext = document.getElementById('plaintext').value;
  const theirPub = await getVerifiedPublicKey(to);
  const { aesKey, salt } = await deriveAesKey(window._me.privEcdh, theirPub);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv}, aesKey, str2ab(plaintext));
  const payload = {
    from, to,
    ciphertext: buf2b64(ct),
    iv: buf2b64(iv),
    timestamp: Date.now(),
    seq: seq,
    hkdf_salt: buf2b64(salt) // send salt so receiver can derive same key
  };
  const r = await fetch(server + '/send-message', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
  const j = await r.json();
  log('Send response:', j);
}

// Fetch messages and decrypt (verifies sender signature before attempting decrypt)
async function fetchMessages(){
  if(!window._me) return alert('login first');
  const me = window._me.username;
  const r = await fetch(server + '/messages/' + encodeURIComponent(me));
  const j = await r.json();
  log('Messages fetched:', j);
  for(const m of j.messages){
    try{
      // verify sender public key signature
      const theirPub = await getVerifiedPublicKey(m.from);
      // derive key using our private ECDH and theirPub
      const salt = b642buf(m.hkdf_salt);
      // derive raw shared bits
      const shared = await crypto.subtle.deriveBits({name:'ECDH', public:theirPub}, window._me.privEcdh, 256);
      const rawKey = await crypto.subtle.importKey('raw', shared, {name:'HKDF'}, false, ['deriveKey']);
      const aesKey = await crypto.subtle.deriveKey({name:'HKDF', hash:'SHA-256', salt, info: new Uint8Array([])}, rawKey, {name:'AES-GCM', length:256}, false, ['decrypt']);
      const ct = b642buf(m.ciphertext);
      const iv = b642buf(m.iv);
      const plain = await crypto.subtle.decrypt({name:'AES-GCM', iv}, aesKey, ct);
      const text = ab2str(plain);
      log('From', m.from, 'Seq', m.seq, 'Message:', text);
    }catch(e){
      log('Failed to decrypt or verify from', m.from, 'error', e.toString());
    }
  }
}

document.getElementById('create').onclick = createAccount;
document.getElementById('login').onclick = login;
document.getElementById('send').onclick = sendMessage;
document.getElementById('fetchMsgs').onclick = fetchMessages;
