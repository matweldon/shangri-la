/**
 * Storage interface for secrets and user data
 */

import { EncryptedSecret, UserProfile } from './types.js';

/**
 * Abstract storage interface that can be implemented by different backends
 */
export interface IStorage {
  /**
   * Initialize the storage (e.g., connect to database)
   */
  initialize(): Promise<void>;

  /**
   * Get user profile
   */
  getUserProfile(userId: string): Promise<UserProfile | null>;

  /**
   * Save user profile
   */
  saveUserProfile(profile: UserProfile): Promise<void>;

  /**
   * Get all secrets for a user
   */
  getSecrets(userId: string): Promise<EncryptedSecret[]>;

  /**
   * Save a secret
   */
  saveSecret(userId: string, secret: EncryptedSecret): Promise<void>;

  /**
   * Delete a secret
   */
  deleteSecret(userId: string, secretId: string): Promise<void>;

  /**
   * Update secret order
   */
  updateSecretOrder(userId: string, secrets: EncryptedSecret[]): Promise<void>;
}
