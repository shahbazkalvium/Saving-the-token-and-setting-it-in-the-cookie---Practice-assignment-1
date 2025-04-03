const crypto = require('crypto');

const secretKey = 'your-secret-key'; // Replace with a secure key
const algorithm = 'aes-256-cbc';
const ivLength = 16; // Initialization vector length for AES

const encrypt = (payload) => {
  const iv = crypto.randomBytes(ivLength);
  const cipher = crypto.createCipheriv(algorithm, Buffer.from(secretKey, 'utf-8'), iv);
  let encrypted = cipher.update(JSON.stringify(payload), 'utf-8', 'hex');
  encrypted += cipher.final('hex');
  return ${iv.toString('hex')}:${encrypted};
};

const decrypt = (token) => {
  const [ivHex, encryptedData] = token.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const decipher = crypto.createDecipheriv(algorithm, Buffer.from(secretKey, 'utf-8'), iv);
  let decrypted = decipher.update(encryptedData, 'hex', 'utf-8');
  decrypted += decipher.final('utf-8');
  return JSON.parse(decrypted);
};

module.exports = {
  encrypt,
  decrypt
};