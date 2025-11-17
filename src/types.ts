/**
 * Type definitions for the application
 */

/**
 * Encrypted secret stored in the database
 */
export interface EncryptedSecret {
  id: string;
  description: string;
  ciphertext: string;
  iv: string;
  salt: string;
  createdAt: number;
  order: number;
}

/**
 * User profile containing authentication data
 */
export interface UserProfile {
  userId: string;
  passwordHash: string;
  passwordSalt: string;
  createdAt: number;
}

/**
 * Decrypted secret for display
 */
export interface DecryptedSecret {
  id: string;
  description: string;
  secret: string;
  createdAt: number;
  order: number;
}

/**
 * Storage mode
 */
export type StorageMode = 'local' | 'online';
