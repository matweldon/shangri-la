/**
 * Cryptography utilities for secure password hashing and secret encryption
 * Uses Web Crypto API for all cryptographic operations
 */

/**
 * Generate a random salt for password hashing
 */
export function generateSalt(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(16));
}

/**
 * Generate a random IV for encryption
 */
export function generateIV(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(12));
}

/**
 * Convert Uint8Array to base64 string for storage
 */
export function arrayBufferToBase64(buffer: Uint8Array): string {
  const binary = String.fromCharCode(...buffer);
  return btoa(binary);
}

/**
 * Convert base64 string to Uint8Array
 */
export function base64ToArrayBuffer(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Hash a password using PBKDF2
 * This is used to verify the master password without storing it in plaintext
 */
export async function hashPassword(password: string, salt: Uint8Array): Promise<string> {
  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(password);

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    passwordBuffer,
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const hashBuffer = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt as BufferSource,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    256
  );

  return arrayBufferToBase64(new Uint8Array(hashBuffer));
}

/**
 * Derive an encryption key from a password
 * This is used to encrypt/decrypt secrets
 */
async function deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(password);

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    passwordBuffer,
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt as BufferSource,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    {
      name: 'AES-GCM',
      length: 256
    },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypt plaintext using AES-GCM
 * Returns an object containing the encrypted data, IV, and salt
 */
export async function encrypt(plaintext: string, password: string): Promise<{
  ciphertext: string;
  iv: string;
  salt: string;
}> {
  const encoder = new TextEncoder();
  const plaintextBuffer = encoder.encode(plaintext);

  const salt = generateSalt();
  const iv = generateIV();
  const key = await deriveKey(password, salt);

  const ciphertextBuffer = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv as BufferSource
    },
    key,
    plaintextBuffer
  );

  return {
    ciphertext: arrayBufferToBase64(new Uint8Array(ciphertextBuffer)),
    iv: arrayBufferToBase64(iv),
    salt: arrayBufferToBase64(salt)
  };
}

/**
 * Decrypt ciphertext using AES-GCM
 * Returns the decrypted plaintext or null if decryption fails
 */
export async function decrypt(
  ciphertext: string,
  iv: string,
  salt: string,
  password: string
): Promise<string | null> {
  try {
    const ciphertextBuffer = base64ToArrayBuffer(ciphertext);
    const ivBuffer = base64ToArrayBuffer(iv);
    const saltBuffer = base64ToArrayBuffer(salt);

    const key = await deriveKey(password, saltBuffer);

    const plaintextBuffer = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: ivBuffer as BufferSource
      },
      key,
      ciphertextBuffer as BufferSource
    );

    const decoder = new TextDecoder();
    return decoder.decode(plaintextBuffer);
  } catch (error) {
    // Decryption failed (wrong password or corrupted data)
    return null;
  }
}
