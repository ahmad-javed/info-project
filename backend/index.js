const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));

const LOG_FILE = path.join(__dirname, 'logs.txt');
function logEvent(obj){
  const line = JSON.stringify(Object.assign({ts: new Date().toISOString()}, obj));
  console.log(line);
  fs.appendFileSync(LOG_FILE, line + '\n');
}

// In-memory stores
let users = {}; 
let messages = []; 
let files = []; 
let lastSeq = {}; 

function seqKey(from,to){ return `${from}->${to}`; }

// Register public key + signing public key + signature
app.post('/register-public-key', (req, res) => {
  const { username, publicKeyJwk, signingPublicKeyJwk, signature } = req.body;
  console.log("Register request for:", username);
  
  if(!username || !publicKeyJwk || !signingPublicKeyJwk || !signature){
    logEvent({event:'register_failed', reason:'missing_fields', username});
    return res.status(400).send({error:'missing fields'});
  }
  
  users[username] = { publicKeyJwk, signingPublicKeyJwk, signature, updated: Date.now() };
  logEvent({event:'register', username});
  console.log("User registered successfully:", username);
  res.send({ok:true});
});

// Get public key info for a user
app.get('/public-key/:username', (req, res) => {
  const username = req.params.username;
  console.log("Public key request for:", username);
  
  const u = users[username];
  if(!u) {
    console.log("User not found:", username);
    return res.status(404).send({error:'not found'});
  }
  
  console.log("Returning public key for:", username);
  res.send({
    publicKeyJwk: u.publicKeyJwk, 
    signingPublicKeyJwk: u.signingPublicKeyJwk, 
    signature: u.signature
  });
});

// Send encrypted message with replay protection
app.post('/send-message', (req, res) => {
  const { from, to, ciphertext, iv, timestamp, seq, hkdf_salt } = req.body;
  console.log("Send message from:", from, "to:", to);
  
  if(!from || !to || !ciphertext || !iv || !timestamp || seq === undefined || !hkdf_salt){
    logEvent({event:'send_failed', reason:'missing_fields', from, to});
    return res.status(400).send({error:'missing fields'});
  }

  const now = Date.now();
  if(Math.abs(now - timestamp) > 5 * 60 * 1000){
    logEvent({event:'send_rejected', reason:'stale_timestamp', from, to, timestamp});
    return res.status(400).send({error:'stale timestamp'});
  }

  const key = seqKey(from,to);
  const last = lastSeq[key] || 0;
  if(seq <= last){
    logEvent({event:'send_rejected', reason:'replay_or_old_seq', from, to, seq, last});
    return res.status(400).send({error:'replay or old seq'});
  }

  lastSeq[key] = seq;
  messages.push({from, to, ciphertext, iv, timestamp, seq, hkdf_salt});
  logEvent({event:'message_stored', from, to, seq, timestamp});
  console.log("Message stored successfully. Total messages:", messages.length);
  res.send({ok:true});
});

// Get messages for a user
app.get('/messages/:username', (req, res) => {
  const username = req.params.username;
  console.log("Get messages for:", username);
  
  const all = messages.filter(m => m.to === username);
  console.log("Returning", all.length, "messages for", username);
  res.send({messages: all});
});

// Upload encrypted file
app.post('/upload-file', (req,res) => {
  const { from, to, filename, chunks } = req.body;
  console.log("File upload from:", from, "to:", to, "filename:", filename);
  
  if(!from || !to || !filename || !chunks) {
    logEvent({event:'file_upload_failed', reason:'missing_fields', from, to});
    return res.status(400).send({error:'missing fields'});
  }
  
  files.push({from, to, filename, chunks, ts:Date.now()});
  logEvent({event:'file_uploaded', from, to, filename, chunks_count: chunks.length});
  console.log("File stored successfully. Total files:", files.length);
  res.send({ok:true});
});

// Get files for a user
app.get('/files/:username', (req,res)=>{
  const username = req.params.username;
  console.log("Get files for:", username);
  
  const all = files.filter(f => f.to === username);
  console.log("Returning", all.length, "files for", username);
  res.send({files: all});
});

// Get all users (for debugging)
app.get('/users', (req, res) => { 
  console.log("Get all users request");
  res.send({users: Object.keys(users)}); 
});

// Get server status
app.get('/status', (req, res) => {
  res.send({
    users: Object.keys(users).length,
    messages: messages.length,
    files: files.length,
    uptime: process.uptime()
  });
});

// Clear data endpoint (for testing)
app.post('/clear-data', (req, res) => {
  messages = [];
  files = [];
  lastSeq = {};
  users = {};
  logEvent({event:'data_cleared'});
  console.log("All data cleared");
  res.send({ok:true});
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log('🚀 Backend listening on port', port);
  console.log('📋 Available Endpoints:');
  console.log('  POST /register-public-key');
  console.log('  GET  /public-key/:username');
  console.log('  POST /send-message');
  console.log('  GET  /messages/:username');
  console.log('  POST /upload-file');
  console.log('  GET  /files/:username');
  console.log('  GET  /users');
  console.log('  GET  /status');
  console.log('  POST /clear-data');
  console.log('🔒 Secure E2EE Messaging System Ready!');
  fs.appendFileSync(LOG_FILE, '--- log started ' + new Date().toISOString() + '\n');
});