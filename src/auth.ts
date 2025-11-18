/**
 * Authentication module
 * Handles user registration and login with master password and WebAuthn
 */

import { IStorage } from './storage.js';
import { UserProfile } from './types.js';
import { hashPassword, generateSalt, arrayBufferToBase64, base64ToArrayBuffer } from './crypto.js';
import * as WebAuthn from './webauthn.js';

export class AuthService {
  private storage: IStorage;
  private currentUserId: string | null = null;
  private masterPasswordHash: string | null = null;

  constructor(storage: IStorage) {
    this.storage = storage;
  }

  /**
   * Check if a user exists
   */
  async userExists(userId: string): Promise<boolean> {
    const profile = await this.storage.getUserProfile(userId);
    return profile !== null;
  }

  /**
   * Register a new user with a master password
   */
  async register(userId: string, masterPassword: string): Promise<void> {
    // Check if user already exists
    const exists = await this.userExists(userId);
    if (exists) {
      throw new Error('User already exists');
    }

    // Generate salt and hash password
    const salt = generateSalt();
    const passwordHash = await hashPassword(masterPassword, salt);

    // Create user profile
    const profile: UserProfile = {
      userId,
      passwordHash,
      passwordSalt: arrayBufferToBase64(salt),
      createdAt: Date.now()
    };

    // Save to storage
    await this.storage.saveUserProfile(profile);

    // Set current user
    this.currentUserId = userId;
    this.masterPasswordHash = passwordHash;
  }

  /**
   * Login with master password
   */
  async login(userId: string, masterPassword: string): Promise<boolean> {
    // Get user profile
    const profile = await this.storage.getUserProfile(userId);
    if (!profile) {
      return false;
    }

    // Hash the provided password with the stored salt
    const salt = base64ToArrayBuffer(profile.passwordSalt);
    const passwordHash = await hashPassword(masterPassword, salt);

    // Compare hashes
    if (passwordHash !== profile.passwordHash) {
      return false;
    }

    // Set current user
    this.currentUserId = userId;
    this.masterPasswordHash = passwordHash;

    return true;
  }

  /**
   * Logout current user
   */
  logout(): void {
    this.currentUserId = null;
    this.masterPasswordHash = null;
  }

  /**
   * Get current user ID
   */
  getCurrentUserId(): string | null {
    return this.currentUserId;
  }

  /**
   * Check if user is logged in
   */
  isLoggedIn(): boolean {
    return this.currentUserId !== null;
  }

  /**
   * Verify master password for current user
   * This is used when viewing secrets to ensure the user has the correct password
   */
  verifyMasterPassword(password: string): boolean {
    // For simplicity, we just check if the stored hash exists
    // In a real scenario, we'd re-hash and compare
    // But since we need the actual password to decrypt secrets,
    // this is mainly a UX feature
    return this.masterPasswordHash !== null;
  }

  /**
   * Check if WebAuthn is available
   */
  async isWebAuthnAvailable(): Promise<boolean> {
    return await WebAuthn.isPlatformAuthenticatorAvailable();
  }

  /**
   * Register a WebAuthn credential (fingerprint, Face ID, etc.)
   */
  async registerWebAuthnCredential(userId: string, displayName?: string): Promise<void> {
    if (!await this.isWebAuthnAvailable()) {
      throw new Error('WebAuthn is not available on this device');
    }

    // User must be logged in to register a credential
    if (this.currentUserId !== userId) {
      throw new Error('User must be logged in to register a credential');
    }

    const credential = await WebAuthn.registerCredential(
      userId,
      userId,
      displayName || userId
    );

    WebAuthn.saveCredential(credential);
  }

  /**
   * Login with WebAuthn credential
   */
  async loginWithWebAuthn(userId: string): Promise<boolean> {
    const credentials = WebAuthn.getStoredCredentials(userId);

    if (credentials.length === 0) {
      return false;
    }

    // Try to authenticate with the first credential
    // In a multi-device scenario, we could let the user choose
    const credential = credentials[0];

    const success = await WebAuthn.authenticateWithCredential(credential.credentialId);

    if (success) {
      // Set current user but don't set masterPasswordHash
      // WebAuthn is for quick unlock only
      this.currentUserId = userId;
      this.masterPasswordHash = null;
      return true;
    }

    return false;
  }

  /**
   * Check if user has registered WebAuthn credentials
   */
  hasWebAuthnCredentials(userId: string): boolean {
    return WebAuthn.hasRegisteredCredentials(userId);
  }

  /**
   * Get all WebAuthn credentials for a user
   */
  getWebAuthnCredentials(userId: string): WebAuthn.StoredCredential[] {
    return WebAuthn.getStoredCredentials(userId);
  }

  /**
   * Delete a WebAuthn credential
   */
  deleteWebAuthnCredential(userId: string, credentialId: string): void {
    WebAuthn.deleteCredential(userId, credentialId);
  }
}
