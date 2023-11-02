// @authors ChatGPT, Google Bard, Samuel Huang
// Created: June-2023
//
// nacl.sign.keyPair() function is a secure and reliable way to generate a key pair for Ed25519 
// cryptographic operations, and it has been used in a variety of applications, including Signal,
// Monero, and Keybase.
//
// sodium.crypto_sign_keypair() function from the libsodium-wrappers library is specifically designed to 
// generate key pairs for the Ed25519 signature algorithm.
//
// To build: npm install
// To run: node index.js

const fs = require('fs');
const nacl = require('tweetnacl');
const util = require("tweetnacl-util") // encoding & decoding 
const { createHash } = require('crypto');

function generateEd25519Certificate() {

    // Generate key pair
    const { publicKey, secretKey } = nacl.sign.keyPair();

    // Convert keys to PEM format
    const publicKeyPem = convertToPem(publicKey, 'PUBLIC KEY');
    const privateKeyPem = convertToPem(secretKey, 'PRIVATE KEY');

    // Save keys to files
    fs.writeFileSync('public_key.pem', publicKeyPem);
    fs.writeFileSync('private_key.pem', privateKeyPem);

    // Print the generated keys
    console.log('Public Key - Base64 encoded from binary data: ', publicKeyPem);
    console.log("   ...");
    console.log('Private Key - Base64 encoded from binary data: ', privateKeyPem);
    console.log("   ...");
}

function convertToPem(key, type) {
    // const pemHeader = `-----BEGIN ${type}-----\n`;
    // const pemFooter = `\n-----END ${type}-----\n`;
    const base64Key = Buffer.from(key).toString('base64');
    const chunks = base64Key.match(/.{1,64}/g);
    const pemBody = chunks.join('\n');

    // return pemHeader + pemBody + pemFooter;
    return pemBody;
}


generateEd25519Certificate();


// 2nd way of generating Ed25519 key pair. Tested & working
/* 
const sodium = require('libsodium-wrappers');
async function generateEd25519PrivateKey() {
  await sodium.ready;

  // Generate a random seed
  const seed = sodium.randombytes_buf(sodium.crypto_sign_SEEDBYTES);

  // Generate the key pair from the seed
  const { publicKey, privateKey } = sodium.crypto_sign_seed_keypair(seed);

  // Encode the private key as base64
  const privateKeyBase64 = sodium.to_base64(privateKey, sodium.base64_variants.URLSAFE_NO_PADDING);

  // Print the generated private key
  console.log('Private Key:', privateKeyBase64);
}
generateEd25519PrivateKey().catch(console.error);
*/



// Load the private key PEM file
const privateKey = fs.readFileSync('private_key.pem', 'utf8').trim();
console.log('Private key loaded from file private_key.pem: ' + privateKey)
console.log('')
// Convert the private key to a Uint8Array object
const privateKeyBuffer = Buffer.from(privateKey, 'base64');
console.log('Private key length: ' + privateKeyBuffer.length)

const privateKeyUint8 = Uint8Array.from(privateKeyBuffer);
const signer = nacl.sign.keyPair.fromSecretKey(privateKeyUint8);

console.log("   ..." ) ;
const data = 'This is some data to sign.';
console.log('Data to sign: ', data)
const messageBytes = util.decodeUTF8(data);
const signature = nacl.sign.detached(messageBytes, signer.secretKey);
console.log( '')
console.log('Data Signature: ' + signature);

console.log("   ...");
console.log("Loading Public key to verify signature...");
// Load the public key PEM file
const publicKey = fs.readFileSync('public_key.pem', 'utf8').trim();
console.log('Public key loaded from file public_key.pem:', publicKey);
console.log( );
// Convert the public key to a Uint8Array object
const publicKeyBuffer = Buffer.from(publicKey, 'base64');
console.log('Public key length:', publicKeyBuffer.length);
console.log();

const publicKeyUint8 = Uint8Array.from(publicKeyBuffer);

// Verify the signature using public key from a PEM file
const data2 = 'This is some data to sign.';
const messageBytes2 = util.decodeUTF8(data2);
const isVerified = nacl.sign.detached.verify(messageBytes2, signature, publicKeyUint8);

// Verify the signature
// const isVerified = nacl.sign.detached.verify( messageBytes, signature, signer.publicKey );

// Check if the signature is verified
if (isVerified) {
    console.log('Signature verified!');
} else {
    console.log('Signature not verified!');
}
console.log("--------------------------");


// Application of using Ed25519 to sign hash of data (e.g. software release) to prove author's identity

function signData(privateKey, data) {
    const signature = nacl.sign.detached(data, privateKey);
    return signature;
}

function verifySignature(publicKey, data, signature) {
    const isValid = nacl.sign.detached.verify(data, signature, publicKey);
    return isValid;
}

console.log();
const hash = createHash('sha3-512').update( data ).digest();   // Create SHA-3 (512-bit) hash of the data
console.log('Signing data to create Hash...')
console.log( 'Hash: ', hash );
console.log()
console.log('Create Hash Signature by Ed25519 Private key...');
const hashSignature = signData(privateKeyUint8, hash);                              // Sign the hash using the private key
const isSha3_SignatureValid = verifySignature(publicKeyUint8, hash, hashSignature); // Verify the signature using the public key

console.log()
console.log('Verifying Signature of Hash...')
console.log( 'Successful SHA3-256 signature verification: ', isSha3_SignatureValid);
console.log()

