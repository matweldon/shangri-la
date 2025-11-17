/**
 * LocalStorage implementation of the storage interface
 */

import { IStorage } from './storage.js';
import { EncryptedSecret, UserProfile } from './types.js';

export class LocalStorageImpl implements IStorage {
  private readonly USER_PROFILE_KEY = 'shangri-la:user-profile:';
  private readonly SECRETS_KEY = 'shangri-la:secrets:';

  async initialize(): Promise<void> {
    // No initialization needed for localStorage
  }

  async getUserProfile(userId: string): Promise<UserProfile | null> {
    const key = this.USER_PROFILE_KEY + userId;
    const data = localStorage.getItem(key);
    if (!data) {
      return null;
    }
    return JSON.parse(data) as UserProfile;
  }

  async saveUserProfile(profile: UserProfile): Promise<void> {
    const key = this.USER_PROFILE_KEY + profile.userId;
    localStorage.setItem(key, JSON.stringify(profile));
  }

  async getSecrets(userId: string): Promise<EncryptedSecret[]> {
    const key = this.SECRETS_KEY + userId;
    const data = localStorage.getItem(key);
    if (!data) {
      return [];
    }
    const secrets = JSON.parse(data) as EncryptedSecret[];
    // Sort by order
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

    const key = this.SECRETS_KEY + userId;
    localStorage.setItem(key, JSON.stringify(secrets));
  }

  async deleteSecret(userId: string, secretId: string): Promise<void> {
    const secrets = await this.getSecrets(userId);
    const filtered = secrets.filter(s => s.id !== secretId);

    const key = this.SECRETS_KEY + userId;
    localStorage.setItem(key, JSON.stringify(filtered));
  }

  async updateSecretOrder(userId: string, secrets: EncryptedSecret[]): Promise<void> {
    const key = this.SECRETS_KEY + userId;
    localStorage.setItem(key, JSON.stringify(secrets));
  }
}
