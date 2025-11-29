const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(bodyParser.json());

const LOG_FILE = path.join(__dirname, 'logs.txt');
function logEvent(obj){
  const line = JSON.stringify(Object.assign({ts: new Date().toISOString()}, obj));
  console.log(line);
  fs.appendFileSync(LOG_FILE, line + '\n');
}

// In-memory stores (demo)
let users = {}; // username -> { publicKeyJwk, signingPublicKeyJwk, signature, updated }
let messages = []; // stored ciphertexts
let lastSeq = {}; // key: `${from}->${to}` -> last seq number seen

// Helpers
function seqKey(from,to){ return `${from}->${to}`; }

// Register public key + signing public key + signature
app.post('/register-public-key', (req, res) => {
  const { username, publicKeyJwk, signingPublicKeyJwk, signature } = req.body;
  if(!username || !publicKeyJwk || !signingPublicKeyJwk || !signature){
    logEvent({event:'register_failed', reason:'missing_fields', username});
    return res.status(400).send({error:'missing fields'});
  }
  users[username] = { publicKeyJwk, signingPublicKeyJwk, signature, updated: Date.now() };
  logEvent({event:'register', username});
  res.send({ok:true});
});

// Get public key info for a user
app.get('/public-key/:username', (req, res) => {
  const u = users[req.params.username];
  if(!u){
    return res.status(404).send({error:'not found'});
  }
  res.send({publicKeyJwk: u.publicKeyJwk, signingPublicKeyJwk: u.signingPublicKeyJwk, signature: u.signature});
});

// Send encrypted message with replay protection
app.post('/send-message', (req, res) => {
  const { from, to, ciphertext, iv, timestamp, seq } = req.body;
  if(!from || !to || !ciphertext || !iv || !timestamp || seq === undefined){
    logEvent({event:'send_failed', reason:'missing_fields', from, to});
    return res.status(400).send({error:'missing fields'});
  }

  // Basic timestamp freshness check (allow 5 minutes)
  const now = Date.now();
  if(Math.abs(now - timestamp) > 5 * 60 * 1000){
    logEvent({event:'send_rejected', reason:'stale_timestamp', from, to, timestamp});
    return res.status(400).send({error:'stale timestamp'});
  }

  // Sequence number check per pair
  const key = seqKey(from,to);
  const last = lastSeq[key] || 0;
  if(seq <= last){
    logEvent({event:'send_rejected', reason:'replay_or_old_seq', from, to, seq, last});
    return res.status(400).send({error:'replay or old seq'});
  }

  // Accept message
  lastSeq[key] = seq;
  messages.push({from, to, ciphertext, iv, timestamp, seq, hkdf_salt: req.body.hkdf_salt});
  logEvent({event:'message_stored', from, to, seq, timestamp});
  res.send({ok:true});
});

// Get messages for a user
app.get('/messages/:username', (req, res) => {
  const all = messages.filter(m => m.to === req.params.username);
  res.send({messages: all});
});

app.get('/users', (req, res) => {
  res.send({users});
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log('Backend listening on', port);
  // ensure log file exists
  fs.appendFileSync(LOG_FILE, '--- log started ' + new Date().toISOString() + '\n');
});
