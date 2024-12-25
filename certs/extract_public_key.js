import crypto from 'crypto';
import fs from 'fs';

// Load the certificate (PEM format)
const cert = fs.readFileSync('./self_signed_CA.pem', 'utf-8');

// Extract the public key
const publicKey = crypto.createPublicKey(cert);

// Export the public key in PEM format
console.log(publicKey.export({ type: 'spki', format: 'pem' }));
