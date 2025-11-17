/**
 * Shared secrets service
 * Handles creation and retrieval of shared, single-use secrets
 */

import { SharedSecret } from './types.js';
import { encrypt, decrypt } from './crypto.js';

/**
 * Storage interface for shared secrets
 * This is implemented by Firestore for online mode
 */
export interface ISharedSecretsStorage {
  /**
   * Save a shared secret
   */
  saveSharedSecret(secret: SharedSecret): Promise<void>;

  /**
   * Get a shared secret by ID
   */
  getSharedSecret(secretId: string): Promise<SharedSecret | null>;

  /**
   * Update view count for a shared secret
   */
  incrementViewCount(secretId: string): Promise<void>;

  /**
   * Delete a shared secret
   */
  deleteSharedSecret(secretId: string): Promise<void>;

  /**
   * Clean up expired secrets
   */
  cleanupExpiredSecrets(): Promise<void>;
}

/**
 * Mock implementation using localStorage (for development)
 */
export class MockSharedSecretsStorage implements ISharedSecretsStorage {
  private readonly STORAGE_KEY = 'mock-shared-secrets';

  private getAll(): SharedSecret[] {
    const data = localStorage.getItem(this.STORAGE_KEY);
    if (!data) {
      return [];
    }
    return JSON.parse(data) as SharedSecret[];
  }

  private saveAll(secrets: SharedSecret[]): void {
    localStorage.setItem(this.STORAGE_KEY, JSON.stringify(secrets));
  }

  async saveSharedSecret(secret: SharedSecret): Promise<void> {
    const secrets = this.getAll();
    secrets.push(secret);
    this.saveAll(secrets);
  }

  async getSharedSecret(secretId: string): Promise<SharedSecret | null> {
    const secrets = this.getAll();
    return secrets.find(s => s.id === secretId) || null;
  }

  async incrementViewCount(secretId: string): Promise<void> {
    const secrets = this.getAll();
    const secret = secrets.find(s => s.id === secretId);
    if (secret) {
      secret.viewCount++;
      this.saveAll(secrets);
    }
  }

  async deleteSharedSecret(secretId: string): Promise<void> {
    const secrets = this.getAll();
    const filtered = secrets.filter(s => s.id !== secretId);
    this.saveAll(filtered);
  }

  async cleanupExpiredSecrets(): Promise<void> {
    const secrets = this.getAll();
    const now = Date.now();
    const filtered = secrets.filter(s => s.expiresAt > now);
    this.saveAll(filtered);
  }
}

/**
 * Real Firestore implementation
 */
export class FirestoreSharedSecretsStorage implements ISharedSecretsStorage {
  private db: any = null;

  constructor() {
    if (typeof firebase !== 'undefined') {
      this.db = firebase.firestore();
    } else {
      throw new Error('Firebase is not loaded');
    }
  }

  async saveSharedSecret(secret: SharedSecret): Promise<void> {
    await this.db.collection('shared-secrets').doc(secret.id).set(secret);
  }

  async getSharedSecret(secretId: string): Promise<SharedSecret | null> {
    const doc = await this.db.collection('shared-secrets').doc(secretId).get();
    if (!doc.exists) {
      return null;
    }
    return doc.data() as SharedSecret;
  }

  async incrementViewCount(secretId: string): Promise<void> {
    const docRef = this.db.collection('shared-secrets').doc(secretId);
    await docRef.update({
      viewCount: firebase.firestore.FieldValue.increment(1)
    });
  }

  async deleteSharedSecret(secretId: string): Promise<void> {
    await this.db.collection('shared-secrets').doc(secretId).delete();
  }

  async cleanupExpiredSecrets(): Promise<void> {
    const now = Date.now();
    const snapshot = await this.db
      .collection('shared-secrets')
      .where('expiresAt', '<=', now)
      .get();

    const batch = this.db.batch();
    snapshot.forEach((doc: any) => {
      batch.delete(doc.ref);
    });

    await batch.commit();
  }
}

/**
 * Shared secrets service
 */
export class SharedSecretsService {
  private storage: ISharedSecretsStorage;

  constructor(storage: ISharedSecretsStorage) {
    this.storage = storage;
  }

  /**
   * Generate a unique ID for a shared secret
   */
  private generateId(): string {
    return Date.now().toString(36) + Math.random().toString(36).substring(2, 15);
  }

  /**
   * Create a shared secret
   */
  async createSharedSecret(
    description: string,
    secret: string,
    password: string,
    expiresInHours: number = 24,
    maxViews: number = 1,
    createdBy?: string
  ): Promise<{ id: string; link: string }> {
    // Encrypt the secret
    const encrypted = await encrypt(secret, password);

    // Create shared secret
    const sharedSecret: SharedSecret = {
      id: this.generateId(),
      description,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      salt: encrypted.salt,
      createdAt: Date.now(),
      createdBy,
      expiresAt: Date.now() + (expiresInHours * 60 * 60 * 1000),
      viewCount: 0,
      maxViews
    };

    // Save to storage
    await this.storage.saveSharedSecret(sharedSecret);

    // Generate link
    const link = `${window.location.origin}${window.location.pathname}#share/${sharedSecret.id}`;

    return { id: sharedSecret.id, link };
  }

  /**
   * Retrieve and decrypt a shared secret
   */
  async retrieveSharedSecret(
    secretId: string,
    password: string
  ): Promise<{ description: string; secret: string } | null> {
    // Get the shared secret
    const sharedSecret = await this.storage.getSharedSecret(secretId);

    if (!sharedSecret) {
      return null;
    }

    // Check if expired
    if (sharedSecret.expiresAt < Date.now()) {
      // Delete expired secret
      await this.storage.deleteSharedSecret(secretId);
      return null;
    }

    // Check if max views reached
    if (sharedSecret.viewCount >= sharedSecret.maxViews) {
      // Delete secret that has been viewed too many times
      await this.storage.deleteSharedSecret(secretId);
      return null;
    }

    // Try to decrypt
    const decrypted = await decrypt(
      sharedSecret.ciphertext,
      sharedSecret.iv,
      sharedSecret.salt,
      password
    );

    if (decrypted === null) {
      return null;
    }

    // Increment view count
    await this.storage.incrementViewCount(secretId);

    // Check if we should delete after viewing
    if (sharedSecret.viewCount + 1 >= sharedSecret.maxViews) {
      await this.storage.deleteSharedSecret(secretId);
    }

    return {
      description: sharedSecret.description,
      secret: decrypted
    };
  }

  /**
   * Clean up expired secrets
   */
  async cleanup(): Promise<void> {
    await this.storage.cleanupExpiredSecrets();
  }
}
