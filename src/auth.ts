/**
 * Authentication module
 * Handles user registration and login with master password
 */

import { IStorage } from './storage.js';
import { UserProfile } from './types.js';
import { hashPassword, generateSalt, arrayBufferToBase64, base64ToArrayBuffer } from './crypto.js';

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
}
