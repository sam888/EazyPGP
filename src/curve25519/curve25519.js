// @authors: ChatGPT, Samuel Huang
// Created: June-2023
const fs = require('fs');
const nacl = require('tweetnacl');

// Generate Curve25519 key pair for the client
const clientKeyPair = nacl.box.keyPair();
const clientPublicKey = Buffer.from(clientKeyPair.publicKey).toString('base64');
const clientPrivateKey = Buffer.from(clientKeyPair.secretKey).toString('base64');

// Write client public key to PEM file
fs.writeFileSync('client_public.pem', clientPublicKey);

// Write client private key to PEM file
fs.writeFileSync('client_private.pem', clientPrivateKey);

console.log('Client Public Key:', clientPublicKey);
console.log('Client Private Key:', clientPrivateKey);

// Generate Curve25519 key pair for the server
const serverKeyPair = nacl.box.keyPair();
const serverPublicKey = Buffer.from(serverKeyPair.publicKey).toString('base64');
const serverPrivateKey = Buffer.from(serverKeyPair.secretKey).toString('base64');

// Write server public key to PEM file
fs.writeFileSync('server_public.pem', serverPublicKey);

// Write server private key to PEM file
fs.writeFileSync('server_private.pem', serverPrivateKey);

console.log('Server Public Key:', serverPublicKey);
console.log('Server Private Key:', serverPrivateKey);

// Compute the shared secret key between client and server
const clientSharedSecret = nacl.scalarMult(clientKeyPair.secretKey, serverKeyPair.publicKey);
const serverSharedSecret = nacl.scalarMult(serverKeyPair.secretKey, clientKeyPair.publicKey);

const clientSharedSecretHex = Buffer.from(clientSharedSecret).toString('base64');
const serverSharedSecretHex = Buffer.from(serverSharedSecret).toString('base64');

console.log('Shared Secret (Client):', clientSharedSecretHex);
console.log('Shared Secret (Server):', serverSharedSecretHex);


// Data to encrypt
const data = 'This is a secret message';

// Convert data to Uint8Array
const dataBytes = Buffer.from(data, 'utf8');

// Nonce generation (24 bytes)
const nonce = nacl.randomBytes(nacl.box.nonceLength);

// Encryption
const encryptedData = nacl.box(dataBytes, nonce, Buffer.from(serverPublicKey, 'base64'), Buffer.from(clientPrivateKey, 'base64'));
const encryptedMessage = encryptedData ? Buffer.from(encryptedData).toString('base64') : null;

// Simulate receiver receiving base64 encoded text, then convert it to binary form for decryption
const encryptedData2 = Buffer.from(encryptedMessage, 'base64');

// Decryption
const decryptedData = nacl.box.open(encryptedData2, nonce, Buffer.from(clientPublicKey, 'base64'), Buffer.from(serverPrivateKey, 'base64'));
const decryptedMessage = decryptedData ? Buffer.from(decryptedData).toString('utf8') : null;

console.log('Original message:', data);
console.log('Encrypted message:', encryptedMessage);
console.log('Decrypted message:', decryptedMessage);
