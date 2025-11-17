/**
 * Firestore implementation of the storage interface
 *
 * This implementation uses Firestore with security rules to ensure
 * each user can only access their own data.
 *
 * Required Firestore structure:
 * - users/{userId} - user profile documents
 * - secrets/{userId}/items/{secretId} - secret documents
 *
 * Security Rules:
 * ```
 * rules_version = '2';
 * service cloud.firestore {
 *   match /databases/{database}/documents {
 *     // Users can only read/write their own profile
 *     match /users/{userId} {
 *       allow read, write: if request.auth != null && request.auth.uid == userId;
 *     }
 *
 *     // Users can only read/write their own secrets
 *     match /secrets/{userId}/items/{secretId} {
 *       allow read, write: if request.auth != null && request.auth.uid == userId;
 *     }
 *   }
 * }
 * ```
 */

import { IStorage } from './storage.js';
import { EncryptedSecret, UserProfile } from './types.js';

// Firestore types (these would come from firebase/firestore in a real implementation)
declare const firebase: any;

export class FirestoreImpl implements IStorage {
  private db: any = null;

  async initialize(): Promise<void> {
    // Initialize Firestore
    if (typeof firebase === 'undefined') {
      throw new Error('Firebase is not loaded. Please include Firebase SDK in your HTML.');
    }

    this.db = firebase.firestore();
  }

  async getUserProfile(userId: string): Promise<UserProfile | null> {
    const docRef = this.db.collection('users').doc(userId);
    const doc = await docRef.get();

    if (!doc.exists) {
      return null;
    }

    return doc.data() as UserProfile;
  }

  async saveUserProfile(profile: UserProfile): Promise<void> {
    const docRef = this.db.collection('users').doc(profile.userId);
    await docRef.set(profile);
  }

  async getSecrets(userId: string): Promise<EncryptedSecret[]> {
    const collectionRef = this.db
      .collection('secrets')
      .doc(userId)
      .collection('items')
      .orderBy('order', 'asc');

    const snapshot = await collectionRef.get();
    const secrets: EncryptedSecret[] = [];

    snapshot.forEach((doc: any) => {
      secrets.push(doc.data() as EncryptedSecret);
    });

    return secrets;
  }

  async saveSecret(userId: string, secret: EncryptedSecret): Promise<void> {
    const docRef = this.db
      .collection('secrets')
      .doc(userId)
      .collection('items')
      .doc(secret.id);

    await docRef.set(secret);
  }

  async deleteSecret(userId: string, secretId: string): Promise<void> {
    const docRef = this.db
      .collection('secrets')
      .doc(userId)
      .collection('items')
      .doc(secretId);

    await docRef.delete();
  }

  async updateSecretOrder(userId: string, secrets: EncryptedSecret[]): Promise<void> {
    // Batch update all secrets with new order
    const batch = this.db.batch();

    secrets.forEach((secret, index) => {
      const docRef = this.db
        .collection('secrets')
        .doc(userId)
        .collection('items')
        .doc(secret.id);

      batch.update(docRef, { order: index });
    });

    await batch.commit();
  }
}

/**
 * Mock Firestore implementation using localStorage
 * This mimics Firestore behavior for development/testing without actual Firestore access
 */
export class MockFirestoreImpl implements IStorage {
  private readonly MOCK_USER_KEY = 'mock-firestore:users:';
  private readonly MOCK_SECRETS_KEY = 'mock-firestore:secrets:';

  async initialize(): Promise<void> {
    // No initialization needed for mock
    console.log('Using Mock Firestore (localStorage-based)');
  }

  async getUserProfile(userId: string): Promise<UserProfile | null> {
    const key = this.MOCK_USER_KEY + userId;
    const data = localStorage.getItem(key);
    if (!data) {
      return null;
    }
    return JSON.parse(data) as UserProfile;
  }

  async saveUserProfile(profile: UserProfile): Promise<void> {
    const key = this.MOCK_USER_KEY + profile.userId;
    localStorage.setItem(key, JSON.stringify(profile));
  }

  async getSecrets(userId: string): Promise<EncryptedSecret[]> {
    const key = this.MOCK_SECRETS_KEY + userId;
    const data = localStorage.getItem(key);
    if (!data) {
      return [];
    }
    const secrets = JSON.parse(data) as EncryptedSecret[];
    return secrets.sort((a, b) => a.order - b.order);
  }

  async saveSecret(userId: string, secret: EncryptedSecret): Promise<void> {
    const secrets = await this.getSecrets(userId);
    const existingIndex = secrets.findIndex(s => s.id === secret.id);

    if (existingIndex >= 0) {
      secrets[existingIndex] = secret;
    } else {
      secrets.push(secret);
    }

    const key = this.MOCK_SECRETS_KEY + userId;
    localStorage.setItem(key, JSON.stringify(secrets));
  }

  async deleteSecret(userId: string, secretId: string): Promise<void> {
    const secrets = await this.getSecrets(userId);
    const filtered = secrets.filter(s => s.id !== secretId);

    const key = this.MOCK_SECRETS_KEY + userId;
    localStorage.setItem(key, JSON.stringify(filtered));
  }

  async updateSecretOrder(userId: string, secrets: EncryptedSecret[]): Promise<void> {
    const key = this.MOCK_SECRETS_KEY + userId;
    localStorage.setItem(key, JSON.stringify(secrets));
  }
}
