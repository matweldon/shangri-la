/**
 * Secrets management module
 * Handles creating, retrieving, and managing encrypted secrets
 */

import { IStorage } from './storage.js';
import { EncryptedSecret, DecryptedSecret } from './types.js';
import { encrypt, decrypt } from './crypto.js';

export class SecretsService {
  private storage: IStorage;

  constructor(storage: IStorage) {
    this.storage = storage;
  }

  /**
   * Generate a unique ID for a secret
   */
  private generateId(): string {
    return Date.now().toString(36) + Math.random().toString(36).substring(2);
  }

  /**
   * Get all secrets for a user (encrypted)
   */
  async getSecrets(userId: string): Promise<EncryptedSecret[]> {
    return await this.storage.getSecrets(userId);
  }

  /**
   * Create a new secret
   */
  async createSecret(
    userId: string,
    description: string,
    secret: string,
    password: string
  ): Promise<EncryptedSecret> {
    // Encrypt the secret
    const encrypted = await encrypt(secret, password);

    // Get existing secrets to determine order
    const existingSecrets = await this.storage.getSecrets(userId);
    const maxOrder = existingSecrets.length > 0
      ? Math.max(...existingSecrets.map(s => s.order))
      : -1;

    // Create encrypted secret object
    const encryptedSecret: EncryptedSecret = {
      id: this.generateId(),
      description,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      salt: encrypted.salt,
      createdAt: Date.now(),
      order: maxOrder + 1
    };

    // Save to storage
    await this.storage.saveSecret(userId, encryptedSecret);

    return encryptedSecret;
  }

  /**
   * Decrypt and retrieve a secret
   */
  async decryptSecret(
    encryptedSecret: EncryptedSecret,
    password: string
  ): Promise<DecryptedSecret | null> {
    const decrypted = await decrypt(
      encryptedSecret.ciphertext,
      encryptedSecret.iv,
      encryptedSecret.salt,
      password
    );

    if (decrypted === null) {
      return null;
    }

    return {
      id: encryptedSecret.id,
      description: encryptedSecret.description,
      secret: decrypted,
      createdAt: encryptedSecret.createdAt,
      order: encryptedSecret.order
    };
  }

  /**
   * Delete a secret
   */
  async deleteSecret(userId: string, secretId: string): Promise<void> {
    await this.storage.deleteSecret(userId, secretId);
  }

  /**
   * Update the order of secrets (for drag-and-drop reordering)
   */
  async reorderSecrets(userId: string, secretIds: string[]): Promise<void> {
    // Get all secrets
    const secrets = await this.storage.getSecrets(userId);

    // Create a map of secrets by ID
    const secretMap = new Map(secrets.map(s => [s.id, s]));

    // Reorder secrets based on the provided order
    const reorderedSecrets: EncryptedSecret[] = [];
    secretIds.forEach((id, index) => {
      const secret = secretMap.get(id);
      if (secret) {
        reorderedSecrets.push({
          ...secret,
          order: index
        });
      }
    });

    // Update storage
    await this.storage.updateSecretOrder(userId, reorderedSecrets);
  }

  /**
   * Update a secret's description
   */
  async updateDescription(
    userId: string,
    secretId: string,
    newDescription: string
  ): Promise<void> {
    const secrets = await this.storage.getSecrets(userId);
    const secret = secrets.find(s => s.id === secretId);

    if (!secret) {
      throw new Error('Secret not found');
    }

    const updatedSecret = {
      ...secret,
      description: newDescription
    };

    await this.storage.saveSecret(userId, updatedSecret);
  }
}
