const server = 'http://localhost:3000';
const logEl = document.getElementById('log');

function log(...args){
  logEl.textContent += '\n' + args.map(a=>typeof a === 'string' ? a : JSON.stringify(a)).join(' ');
}

// Utilities
function buf2b64(b){ return btoa(String.fromCharCode(...new Uint8Array(b))); }
function b642buf(s){ return Uint8Array.from(atob(s), c=>c.charCodeAt(0)); }
function str2ab(s){ return new TextEncoder().encode(s); }
function ab2str(ab){ return new TextDecoder().decode(ab); }

// DEBUG FUNCTION
function debugStorage() {
  console.log("=== STORAGE DEBUG ===");
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    console.log("Key:", key, "Length:", localStorage.getItem(key)?.length);
    if (key.includes(':priv_enc')) {
      try {
        const data = JSON.parse(localStorage.getItem(key));
        console.log("  Salt:", data.salt?.substring(0, 20) + "...");
        console.log("  IV:", data.iv?.substring(0, 20) + "...");
        console.log("  CT:", data.ct?.substring(0, 20) + "...");
      } catch (e) {
        console.log("  Invalid JSON");
      }
    }
  }
}

// Call this in browser console to debug
window.debugStorage = debugStorage;

// IMPROVED POPUP FUNCTION
function popup(msg, color = "#4BB543") {
  // Remove any existing popups first
  const existingPopups = document.querySelectorAll('.popup');
  existingPopups.forEach(popup => popup.remove());
  
  const p = document.createElement('div');
  p.textContent = msg;
  p.className = color === "#D9534F" ? 'popup error' : 'popup';
  p.style.background = color;
  
  document.body.appendChild(p);
  
  // Auto remove after 3 seconds
  setTimeout(() => {
    if (p.parentNode) {
      p.parentNode.removeChild(p);
    }
  }, 3000);
}

// Get crypto subtle with fallback
function getCrypto() {
  if (window.crypto && window.crypto.subtle) {
    return window.crypto.subtle;
  } else {
    throw new Error("Web Crypto API is not available in this browser. Please use Chrome, Firefox, or Edge.");
  }
}

// Get crypto for random values
function getRandomCrypto() {
  if (window.crypto && window.crypto.getRandomValues) {
    return window.crypto;
  } else {
    throw new Error("Web Crypto API is not available for random values.");
  }
}

// PBKDF2 derive AES-GCM key from password
async function deriveKeyFromPassword(password, salt, iterations=200000){
  console.log("Deriving key from password...");
  console.log("Password length:", password.length);
  console.log("Salt length:", salt.length);
  
  const subtle = getCrypto();
  
  const pwKey = await subtle.importKey(
    'raw', 
    str2ab(password), 
    {name:'PBKDF2'}, 
    false, 
    ['deriveKey']
  );
  
  const key = await subtle.deriveKey(
    {
      name:'PBKDF2', 
      salt: salt, 
      iterations: iterations, 
      hash:'SHA-256'
    },
    pwKey,
    {name:'AES-GCM', length:256},
    false,
    ['encrypt','decrypt']
  );
  
  console.log("Key derived successfully");
  return key;
}

// Encrypt JSON
async function encryptJSON(key, obj){
  const subtle = getCrypto();
  const crypto = getRandomCrypto();
  
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const pt = str2ab(JSON.stringify(obj));
  const ct = await subtle.encrypt({name:'AES-GCM', iv}, key, pt);
  return { iv: buf2b64(iv), ct: buf2b64(ct) };
}

// Decrypt JSON
async function decryptJSON(key, ivB64, ctB64){
  const subtle = getCrypto();
  
  const iv = b642buf(ivB64);
  const ct = b642buf(ctB64);
  const pt = await subtle.decrypt({name:'AES-GCM', iv}, key, ct);
  return JSON.parse(ab2str(pt));
}

// --------------------- VALIDATION ---------------------
function validateRegistration(username, password){
  if(!username || username.trim().length < 3) return "Username must be at least 3 characters.";
  if(!password || password.length < 6) return "Password must be at least 6 characters.";
  if(password.includes(" ")) return "Password cannot contain spaces.";
  return null;
}

// --------------------- CREATE ACCOUNT ---------------------
async function createAccount() {
  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value;

  console.log("=== ACCOUNT CREATION START ===");
  console.log("Username:", username);
  console.log("Password length:", password.length);

  const error = validateRegistration(username, password);
  if (error) { 
    console.log("Validation error:", error);
    popup(error, "#D9534F"); 
    return; 
  }

  // Check if account already exists
  if (localStorage.getItem(username + ':priv_enc')) {
    console.log("Account already exists in localStorage");
    popup("Account already exists locally!", "#D9534F");
    return;
  }

  log("Generating keys for", username);

  try {
    // Check crypto availability first
    const subtle = getCrypto();
    const crypto = getRandomCrypto();
    
    console.log("Step 1: Generating ECDH key pair...");
    const ecdh = await subtle.generateKey(
      { 
        name: 'ECDH', 
        namedCurve: 'P-256' 
      }, 
      true, // extractable
      ['deriveKey', 'deriveBits'] // key usages
    );
    console.log("ECDH keys generated");
    
    console.log("Step 2: Generating ECDSA key pair...");
    const ecdsa = await subtle.generateKey(
      { 
        name: 'ECDSA', 
        namedCurve: 'P-256' 
      }, 
      true, // extractable
      ['sign', 'verify'] // key usages
    );
    console.log("ECDSA keys generated");

    // Export keys
    console.log("Step 3: Exporting keys...");
    const pubEcdh = await subtle.exportKey('jwk', ecdh.publicKey);
    const pubEcdsa = await subtle.exportKey('jwk', ecdsa.publicKey);
    
    const privEcdhJwk = await subtle.exportKey('jwk', ecdh.privateKey);
    const privEcdsaJwk = await subtle.exportKey('jwk', ecdsa.privateKey);
    
    console.log("Keys exported");

    // Create signature
    console.log("Step 4: Creating signature...");
    const data = new TextEncoder().encode(JSON.stringify(pubEcdh));
    const signature = await subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' }, ecdsa.privateKey, data);
    const sigB64 = buf2b64(signature);
    console.log("Signature created");

    // Store keys securely locally
    console.log("Step 5: Storing keys locally...");
    const salt = crypto.getRandomValues(new Uint8Array(16));
    console.log("Salt generated:", buf2b64(salt).substring(0, 20) + "...");
    
    const storageKey = await deriveKeyFromPassword(password, salt, 200000);
    console.log("Storage key derived");

    const storeObj = { 
      privEcdh: privEcdhJwk, 
      privEcdsa: privEcdsaJwk 
    };
    console.log("Store object created with private keys");
    
    const enc = await encryptJSON(storageKey, storeObj);
    console.log("Keys encrypted");

    const blob = { salt: buf2b64(salt), iv: enc.iv, ct: enc.ct };
    localStorage.setItem(username + ':priv_enc', JSON.stringify(blob));
    
    console.log("Step 6: Local storage saved");
    console.log("Storage key:", username + ':priv_enc');
    console.log("Blob size:", JSON.stringify(blob).length);
    
    popup(`Account "${username}" created successfully!`);

    // Register with server
    console.log("Step 7: Registering with server...");
    const res = await fetch(server + '/register-public-key', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username,
        publicKeyJwk: pubEcdh,
        signingPublicKeyJwk: pubEcdsa,
        signature: sigB64
      })
    });

    const rj = await res.json();
    if (rj.error) {
      console.log("Server registration error:", rj.error);
      popup("Server error: " + rj.error, "#D9534F");
    } else {
      console.log("Server registration successful");
      popup("Account registered successfully with server!");
    }

    console.log("=== ACCOUNT CREATION COMPLETE ===");

  } catch (e) {
    console.error("Account creation error:", e);
    console.error("Error stack:", e.stack);
    popup("Failed to create account: " + e.message, "#D9534F");
  }
}

// --------------------- LOGIN ---------------------
async function login() {
  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value;

  console.log("=== LOGIN ATTEMPT ===");
  console.log("Username:", username);
  console.log("Password length:", password.length);

  if (!username || !password) {
    popup("Enter username and password", "#D9534F");
    return;
  }

  const blobStr = localStorage.getItem(username + ':priv_enc');
  if (!blobStr) {
    console.log("No account found in localStorage");
    popup("No local account found. Create account first!", "#D9534F");
    return;
  }

  console.log("Account found in localStorage");
  
  try {
    console.log("Step 1: Parsing stored blob...");
    const blob = JSON.parse(blobStr);
    console.log("Blob parsed successfully");
    console.log("Salt length:", blob.salt?.length);
    console.log("IV length:", blob.iv?.length);
    console.log("CT length:", blob.ct?.length);

    const salt = b642buf(blob.salt);
    console.log("Salt converted to buffer");
    
    console.log("Step 2: Deriving storage key...");
    const storageKey = await deriveKeyFromPassword(password, salt, 200000);
    console.log("Storage key derived");
    
    console.log("Step 3: Decrypting keys...");
    const storeObj = await decryptJSON(storageKey, blob.iv, blob.ct);
    console.log("Keys decrypted successfully");
    console.log("Private ECDH key present:", !!storeObj.privEcdh);
    console.log("Private ECDSA key present:", !!storeObj.privEcdsa);

    console.log("Step 4: Importing private keys...");
    const subtle = getCrypto();
    
    const privEcdh = await subtle.importKey(
      'jwk', 
      storeObj.privEcdh, 
      { 
        name: 'ECDH', 
        namedCurve: 'P-256' 
      }, 
      true, // extractable
      ['deriveKey', 'deriveBits'] // MUST match generation usages
    );
    
    const privEcdsa = await subtle.importKey(
      'jwk', 
      storeObj.privEcdsa, 
      { 
        name: 'ECDSA', 
        namedCurve: 'P-256' 
      }, 
      true, // extractable
      ['sign'] // MUST match generation usages
    );

    console.log("Private keys imported successfully");

    window._me = { username, privEcdh, privEcdsa };
    console.log("Login successful!");
    log("Logged in successfully:", username);
    popup(`Logged in as ${username}`);

  } catch (e) {
    console.error("Login error:", e);
    console.error("Error name:", e.name);
    console.error("Error message:", e.message);
    
    if (e.name === 'OperationError') {
      popup("Incorrect password - cannot decrypt account data!", "#D9534F");
    } else {
      popup("Login failed: " + e.message, "#D9534F");
    }
  }
}

// --------------------- GET VERIFIED PUBLIC KEY ---------------------
async function getVerifiedPublicKey(username){
  const r = await fetch(server + '/public-key/' + encodeURIComponent(username));
  if(!r.ok) throw new Error("User not found");

  const j = await r.json();
  const pubEcdh = j.publicKeyJwk;
  const pubEcdsa = j.signingPublicKeyJwk;
  const sig = j.signature;

  const subtle = getCrypto();
  
  const spk = await subtle.importKey(
    'jwk', 
    pubEcdsa, 
    {
      name: 'ECDSA', 
      namedCurve: 'P-256'
    }, 
    true, 
    ['verify'] // Only 'verify' for public key
  );
  
  const data = new TextEncoder().encode(JSON.stringify(pubEcdh));

  const valid = await subtle.verify(
    {name:'ECDSA', hash:'SHA-256'},
    spk,
    Uint8Array.from(atob(sig), c=>c.charCodeAt(0)),
    data
  );

  if(!valid) throw new Error("Invalid signature for " + username);

  return await subtle.importKey(
    'jwk', 
    pubEcdh, 
    {
      name: 'ECDH', 
      namedCurve: 'P-256'
    }, 
    true, 
    [] // Empty array for public key - no operations needed
  );
}

// ------------------ ECDH → HKDF -------------------
async function deriveAesKey(privEcdh, theirPubKey){
  const subtle = getCrypto();
  const crypto = getRandomCrypto();
  
  const shared = await subtle.deriveBits({name:'ECDH', public:theirPubKey}, privEcdh, 256);
  const rawKey = await subtle.importKey('raw', shared, {name:'HKDF'}, false, ['deriveKey']);
  const salt = crypto.getRandomValues(new Uint8Array(16));

  const aesKey = await subtle.deriveKey(
    {name:'HKDF', hash:'SHA-256', salt, info:new Uint8Array([])},
    rawKey,
    {name:'AES-GCM', length:256},
    false,
    ['encrypt','decrypt']
  );

  return { aesKey, salt };
}

// --------------------- SEND MESSAGE ---------------------
async function sendMessage(){
  if(!window._me) return popup("Login first!", "#D9534F");

  const from = window._me.username;
  const to = document.getElementById('to').value.trim();
  const seq = Number(document.getElementById('seq').value) || 1;
  const plaintext = document.getElementById('plaintext').value;

  try {
    const theirPub = await getVerifiedPublicKey(to);
    const { aesKey, salt } = await deriveAesKey(window._me.privEcdh, theirPub);

    const subtle = getCrypto();
    const crypto = getRandomCrypto();
    
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await subtle.encrypt({name:'AES-GCM', iv}, aesKey, str2ab(plaintext));

    const payload = {
      from, to,
      ciphertext: buf2b64(ct),
      iv: buf2b64(iv),
      hkdf_salt: buf2b64(salt),
      timestamp: Date.now(),
      seq
    };

    const r = await fetch(server + '/send-message', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify(payload)
    });

    const j = await r.json();
    if (j.ok) {
      popup("Message sent successfully!");
      log("SendResponse:", j);
    } else {
      popup("Failed to send message: " + j.error, "#D9534F");
    }
  } catch (e) {
    console.error("Send message error:", e);
    popup("Failed to send message: " + e.message, "#D9534F");
  }
}

// --------------------- FETCH MESSAGES ---------------------
async function fetchMessages(){
  if(!window._me) return popup("Login first!", "#D9534F");

  const me = window._me.username;
  try {
    const r = await fetch(server + '/messages/' + encodeURIComponent(me));
    const j = await r.json();

    log("Messages received:", j.messages.length);

    for(const m of j.messages){
      try{
        const theirPub = await getVerifiedPublicKey(m.from);
        const salt = b642buf(m.hkdf_salt);

        const subtle = getCrypto();
        
        const shared = await subtle.deriveBits({name:'ECDH', public:theirPub}, window._me.privEcdh, 256);
        const rawKey = await subtle.importKey('raw', shared, {name:'HKDF'}, false, ['deriveKey']);

        const aesKey = await subtle.deriveKey(
          {name:'HKDF', hash:'SHA-256', salt, info:new Uint8Array([])},
          rawKey,
          {name:'AES-GCM', length:256},
          false,
          ['decrypt']
        );

        const plain = await subtle.decrypt({name:'AES-GCM', iv:b642buf(m.iv)}, aesKey, b642buf(m.ciphertext));
        const msg = ab2str(plain);

        log(`From ${m.from} → Seq ${m.seq} → ${msg}`);

      }catch(e){
        log("Failed to decrypt message from " + m.from + ":", e.toString());
      }
    }
    
    if (j.messages.length === 0) {
      popup("No new messages");
    }
  } catch (e) {
    popup("Failed to fetch messages", "#D9534F");
  }
}

// --------------------- SEND FILE ---------------------
async function sendFile() {
  if (!window._me) {
    popup("Login first!", "#D9534F");
    return;
  }

  const fileInput = document.getElementById('fileInput');
  const to = document.getElementById('fileTo').value.trim();
  
  if (!fileInput.files[0] || !to) {
    popup("Select a file and recipient!", "#D9534F");
    return;
  }

  try {
    const file = fileInput.files[0];
    const theirPub = await getVerifiedPublicKey(to);
    const { aesKey, salt } = await deriveAesKey(window._me.privEcdh, theirPub);

    const reader = new FileReader();
    reader.onload = async function(e) {
      try {
        const fileData = new Uint8Array(e.target.result);
        const subtle = getCrypto();
        const crypto = getRandomCrypto();
        
        const iv = crypto.getRandomValues(new Uint8Array(12));
        
        // Encrypt the file
        const encryptedFile = await subtle.encrypt(
          { name: 'AES-GCM', iv }, aesKey, fileData);
        
        // Prepare file chunks (in this case, just one chunk for simplicity)
        const chunks = [{
          data: buf2b64(encryptedFile),
          iv: buf2b64(iv),
          hkdf_salt: buf2b64(salt),
          index: 0,
          total: 1
        }];

        // Send to server
        const res = await fetch(server + '/upload-file', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            from: window._me.username,
            to: to,
            filename: file.name,
            chunks: chunks
          })
        });

        const result = await res.json();
        if (result.ok) {
          popup(`File "${file.name}" sent successfully!`);
          fileInput.value = ''; // Clear file input
        } else {
          popup("Failed to send file", "#D9534F");
        }
      } catch (error) {
        console.error("File encryption error:", error);
        popup("File encryption failed", "#D9534F");
      }
    };
    
    reader.readAsArrayBuffer(file);
    
  } catch (error) {
    console.error("File send error:", error);
    popup("Failed to send file: " + error.message, "#D9534F");
  }
}

// --------------------- FETCH FILES ---------------------
async function fetchFiles() {
  if (!window._me) {
    popup("Login first!", "#D9534F");
    return;
  }

  try {
    const res = await fetch(server + '/files/' + encodeURIComponent(window._me.username));
    const data = await res.json();
    
    log("Files received:", data.files.length);
    
    for (const file of data.files) {
      try {
        log(`File from ${file.from}: ${file.filename} (${file.chunks.length} chunks)`);
        // Here you would add decryption logic similar to messages
      } catch (error) {
        log(`Failed to process file ${file.filename}:`, error.toString());
      }
    }
    
    if (data.files.length === 0) {
      popup("No files found");
    }
  } catch (error) {
    popup("Failed to fetch files", "#D9534F");
  }
}

// --------------------- CLEAR LOCAL DATA ---------------------
function clearLocalData() {
  const username = document.getElementById('username').value.trim();
  if (username && confirm(`Clear all data for ${username}?`)) {
    localStorage.removeItem(username + ':priv_enc');
    popup("Local data cleared for " + username);
  }
}

// --------------------- BUTTONS ---------------------
document.getElementById('create').onclick = createAccount;
document.getElementById('login').onclick = login;
document.getElementById('send').onclick = sendMessage;
document.getElementById('fetchMsgs').onclick = fetchMessages;
document.getElementById('sendFile').onclick = sendFile;
document.getElementById('fetchFiles').onclick = fetchFiles;

// Add clear button for testing
document.addEventListener('DOMContentLoaded', function() {
  const clearBtn = document.createElement('button');
  clearBtn.textContent = 'Clear Local Data (Debug)';
  clearBtn.onclick = clearLocalData;
  clearBtn.style.background = '#ff4444';
  document.querySelector('.account').appendChild(clearBtn);
});

// Export for debugging
window.debugAccounts = debugStorage;

// Check if Web Crypto is available on page load
document.addEventListener('DOMContentLoaded', function() {
  try {
    getCrypto();
    getRandomCrypto();
    console.log("Web Crypto API is available!");
  } catch (e) {
    console.error("Web Crypto API not available:", e.message);
    popup("Web Crypto API is not available. Please use Chrome, Firefox, or Edge.", "#D9534F");
  }
});