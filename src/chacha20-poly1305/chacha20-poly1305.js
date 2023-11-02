// @authors: CodePal, ChatGPT, Samuel Huang
// Created: 10-June-2023
//
// In the context of ChaCha20, the secret key length is typically 256 bits(32 bytes). ChaCha20 is designed to work with a 256 bit key. 
// However, it can also accept keys of different lengths(128 bits or 192 bits) by truncating or expanding the key material.
//
// Regarding the nonce length for ChaCha20, it is recommended to use a 96 bits nonce(12 bytes). The nonce should be unique for each 
// encryption operation to ensure the security of the cipher. Using a 96 bits nonce provides a balance between security and practicality.
//
// The Poly1305 authenticator uses a 128-bit key and requires a 96-bit nonce to ensure uniqueness for each encryption operation.
//
// Note the authTagLength in the code is used to specify the length of the authentication tag (also known as the MAC or Message 
// Authentication Code) for the ChaCha20-Poly1305 encryption algorithm. The authentication tag is used to verify the integrity 
// and authenticity of the encrypted data.
//
// It is common to output encrypted text in base64 encoding rather than UTF8 encoding. The reason for using base64 encoding is that the 
// output of encryption operations, such as ciphertext, often contains binary data that may not be representable directly as a UTF8 
// string. Base64 encoding allows binary data to be represented using only printable ASCII characters, making it suitable for storage
// and transmission.


const crypto = require('crypto');

function encryptText(text, key) {
  const nonce = crypto.randomBytes(12);

  // Create a cipher object using the key, nonce, and authTagLength
  const cipher = crypto.createCipheriv('chacha20-poly1305', key, nonce, {
    authTagLength: 16
  });

  let encrypted = cipher.update(text, 'utf8', 'base64');
  encrypted += cipher.final('base64');

  const tag = cipher.getAuthTag();
  return { encryptedText: encrypted, nonce: nonce, tag: tag };
}

function decryptText(encryptedText, key, nonce, tag) {
  const decipher = crypto.createDecipheriv('chacha20-poly1305', key, nonce, {
    authTagLength: 16
  });

  decipher.setAuthTag(tag);

  let decrypted = decipher.update(encryptedText, 'base64', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}

// Generate a secret key
const key = crypto.randomBytes(32);

// Encrypt some text
const text = 'Hello, world!';
const encryptedData = encryptText(text, key);

// Uncomment this line then run code to verify MAC authentication is working in decryption
// encryptedData.tag = crypto.randomBytes( 16 );

console.log('Encrypted text: ', encryptedData.encryptedText);
console.log('Nonce: ', encryptedData.nonce.toString('base64'));
console.log('MAC: ', encryptedData.tag.toString('base64'));

// Decrypt the text
const decryptedText = decryptText(
  encryptedData.encryptedText,
  key,
  encryptedData.nonce,
  encryptedData.tag
);

console.log('Decrypted text: ', decryptedText);
