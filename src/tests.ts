/**
 * Jasmine test suite for Shangri-la
 * Tests all core modules: crypto, auth, secrets, and storage
 */

import * as crypto from './crypto.js';
import { AuthService } from './auth.js';
import { SecretsService } from './secrets.js';
import { LocalStorageImpl } from './localStorageImpl.js';
import { MockFirestoreImpl } from './firestoreImpl.js';

// Jasmine is loaded globally via CDN
declare const jasmine: any;
declare const describe: any;
declare const it: any;
declare const expect: any;
declare const beforeEach: any;
declare const afterEach: any;
declare const fail: any;

/**
 * Configure Jasmine to render to our custom container
 */
function configureJasmine() {
  const jasmineEnv = jasmine.getEnv();
  const htmlReporter = new jasmine.HtmlReporter({
    env: jasmineEnv,
    onRaiseExceptionsClick: function() {},
    getContainer: function() {
      return document.getElementById('jasmine-container');
    },
    createElement: function() {
      return document.createElement.apply(document, arguments as any);
    },
    createTextNode: function() {
      return document.createTextNode.apply(document, arguments as any);
    },
    timer: new jasmine.Timer()
  });

  jasmineEnv.addReporter(htmlReporter);
}

/**
 * Define all test suites
 */
function defineTests() {
/**
 * Crypto module tests
 */
describe('Crypto Module', () => {
  describe('generateSalt', () => {
    it('should generate a 16-byte salt', () => {
      const salt = crypto.generateSalt();
      expect(salt.length).toBe(16);
    });

    it('should generate different salts on each call', () => {
      const salt1 = crypto.generateSalt();
      const salt2 = crypto.generateSalt();
      expect(salt1).not.toEqual(salt2);
    });
  });

  describe('generateIV', () => {
    it('should generate a 12-byte IV', () => {
      const iv = crypto.generateIV();
      expect(iv.length).toBe(12);
    });

    it('should generate different IVs on each call', () => {
      const iv1 = crypto.generateIV();
      const iv2 = crypto.generateIV();
      expect(iv1).not.toEqual(iv2);
    });
  });

  describe('arrayBufferToBase64 and base64ToArrayBuffer', () => {
    it('should correctly convert to base64 and back', () => {
      const original = new Uint8Array([1, 2, 3, 4, 5, 255, 128, 0]);
      const base64 = crypto.arrayBufferToBase64(original);
      const decoded = crypto.base64ToArrayBuffer(base64);
      expect(decoded).toEqual(original);
    });

    it('should handle empty arrays', () => {
      const original = new Uint8Array([]);
      const base64 = crypto.arrayBufferToBase64(original);
      const decoded = crypto.base64ToArrayBuffer(base64);
      expect(decoded).toEqual(original);
    });
  });

  describe('hashPassword', () => {
    it('should hash a password with a salt', async () => {
      const password = 'test-password-123';
      const salt = crypto.generateSalt();
      const hash = await crypto.hashPassword(password, salt);
      expect(hash).toBeTruthy();
      expect(typeof hash).toBe('string');
    });

    it('should produce the same hash for the same password and salt', async () => {
      const password = 'test-password-123';
      const salt = crypto.generateSalt();
      const hash1 = await crypto.hashPassword(password, salt);
      const hash2 = await crypto.hashPassword(password, salt);
      expect(hash1).toBe(hash2);
    });

    it('should produce different hashes for different salts', async () => {
      const password = 'test-password-123';
      const salt1 = crypto.generateSalt();
      const salt2 = crypto.generateSalt();
      const hash1 = await crypto.hashPassword(password, salt1);
      const hash2 = await crypto.hashPassword(password, salt2);
      expect(hash1).not.toBe(hash2);
    });

    it('should produce different hashes for different passwords', async () => {
      const salt = crypto.generateSalt();
      const hash1 = await crypto.hashPassword('password1', salt);
      const hash2 = await crypto.hashPassword('password2', salt);
      expect(hash1).not.toBe(hash2);
    });
  });

  describe('encrypt and decrypt', () => {
    it('should encrypt and decrypt a message', async () => {
      const plaintext = 'This is a secret message!';
      const password = 'my-secure-password';

      const encrypted = await crypto.encrypt(plaintext, password);
      expect(encrypted.ciphertext).toBeTruthy();
      expect(encrypted.iv).toBeTruthy();
      expect(encrypted.salt).toBeTruthy();

      const decrypted = await crypto.decrypt(
        encrypted.ciphertext,
        encrypted.iv,
        encrypted.salt,
        password
      );

      expect(decrypted).toBe(plaintext);
    });

    it('should fail to decrypt with wrong password', async () => {
      const plaintext = 'This is a secret message!';
      const password = 'correct-password';
      const wrongPassword = 'wrong-password';

      const encrypted = await crypto.encrypt(plaintext, password);
      const decrypted = await crypto.decrypt(
        encrypted.ciphertext,
        encrypted.iv,
        encrypted.salt,
        wrongPassword
      );

      expect(decrypted).toBeNull();
    });

    it('should handle special characters and unicode', async () => {
      const plaintext = 'Hello 世界! 🔐 Special chars: @#$%^&*()';
      const password = 'test-password';

      const encrypted = await crypto.encrypt(plaintext, password);
      const decrypted = await crypto.decrypt(
        encrypted.ciphertext,
        encrypted.iv,
        encrypted.salt,
        password
      );

      expect(decrypted).toBe(plaintext);
    });

    it('should handle empty strings', async () => {
      const plaintext = '';
      const password = 'test-password';

      const encrypted = await crypto.encrypt(plaintext, password);
      const decrypted = await crypto.decrypt(
        encrypted.ciphertext,
        encrypted.iv,
        encrypted.salt,
        password
      );

      expect(decrypted).toBe(plaintext);
    });

    it('should produce different ciphertexts for same plaintext', async () => {
      const plaintext = 'This is a secret message!';
      const password = 'my-secure-password';

      const encrypted1 = await crypto.encrypt(plaintext, password);
      const encrypted2 = await crypto.encrypt(plaintext, password);

      // Should be different due to different IVs and salts
      expect(encrypted1.ciphertext).not.toBe(encrypted2.ciphertext);
      expect(encrypted1.iv).not.toBe(encrypted2.iv);
      expect(encrypted1.salt).not.toBe(encrypted2.salt);
    });
  });
});

/**
 * Auth Service tests
 */
describe('AuthService', () => {
  let storage: LocalStorageImpl;
  let auth: AuthService;

  beforeEach(async () => {
    // Clear localStorage before each test
    localStorage.clear();
    storage = new LocalStorageImpl();
    await storage.initialize();
    auth = new AuthService(storage);
  });

  afterEach(() => {
    localStorage.clear();
  });

  describe('userExists', () => {
    it('should return false for non-existent user', async () => {
      const exists = await auth.userExists('nonexistent-user');
      expect(exists).toBe(false);
    });

    it('should return true for existing user', async () => {
      await auth.register('test-user', 'test-password');
      const exists = await auth.userExists('test-user');
      expect(exists).toBe(true);
    });
  });

  describe('register', () => {
    it('should register a new user', async () => {
      await auth.register('test-user', 'test-password');
      const exists = await auth.userExists('test-user');
      expect(exists).toBe(true);
    });

    it('should set current user after registration', async () => {
      await auth.register('test-user', 'test-password');
      expect(auth.getCurrentUserId()).toBe('test-user');
      expect(auth.isLoggedIn()).toBe(true);
    });

    it('should throw error when registering existing user', async () => {
      await auth.register('test-user', 'test-password');
      try {
        await auth.register('test-user', 'another-password');
        fail('Should have thrown an error');
      } catch (error: any) {
        expect(error.message).toContain('already exists');
      }
    });
  });

  describe('login', () => {
    beforeEach(async () => {
      await auth.register('test-user', 'correct-password');
      auth.logout();
    });

    it('should login with correct password', async () => {
      const success = await auth.login('test-user', 'correct-password');
      expect(success).toBe(true);
      expect(auth.isLoggedIn()).toBe(true);
      expect(auth.getCurrentUserId()).toBe('test-user');
    });

    it('should fail login with incorrect password', async () => {
      const success = await auth.login('test-user', 'wrong-password');
      expect(success).toBe(false);
      expect(auth.isLoggedIn()).toBe(false);
      expect(auth.getCurrentUserId()).toBeNull();
    });

    it('should fail login for non-existent user', async () => {
      const success = await auth.login('nonexistent', 'any-password');
      expect(success).toBe(false);
    });
  });

  describe('logout', () => {
    it('should clear current user', async () => {
      await auth.register('test-user', 'test-password');
      expect(auth.isLoggedIn()).toBe(true);

      auth.logout();
      expect(auth.isLoggedIn()).toBe(false);
      expect(auth.getCurrentUserId()).toBeNull();
    });
  });
});

/**
 * Secrets Service tests
 */
describe('SecretsService', () => {
  let storage: LocalStorageImpl;
  let secrets: SecretsService;
  const testUserId = 'test-user';

  beforeEach(async () => {
    localStorage.clear();
    storage = new LocalStorageImpl();
    await storage.initialize();
    secrets = new SecretsService(storage);
  });

  afterEach(() => {
    localStorage.clear();
  });

  describe('createSecret', () => {
    it('should create and store an encrypted secret', async () => {
      const secret = await secrets.createSecret(
        testUserId,
        'Test Secret',
        'my secret value',
        'secret-password'
      );

      expect(secret.id).toBeTruthy();
      expect(secret.description).toBe('Test Secret');
      expect(secret.ciphertext).toBeTruthy();
      expect(secret.iv).toBeTruthy();
      expect(secret.salt).toBeTruthy();
    });

    it('should assign sequential order numbers', async () => {
      const secret1 = await secrets.createSecret(
        testUserId,
        'Secret 1',
        'value 1',
        'pass1'
      );
      const secret2 = await secrets.createSecret(
        testUserId,
        'Secret 2',
        'value 2',
        'pass2'
      );

      expect(secret1.order).toBe(0);
      expect(secret2.order).toBe(1);
    });
  });

  describe('getSecrets', () => {
    it('should return empty array for user with no secrets', async () => {
      const userSecrets = await secrets.getSecrets(testUserId);
      expect(userSecrets).toEqual([]);
    });

    it('should return all secrets for a user', async () => {
      await secrets.createSecret(testUserId, 'Secret 1', 'value 1', 'pass1');
      await secrets.createSecret(testUserId, 'Secret 2', 'value 2', 'pass2');

      const userSecrets = await secrets.getSecrets(testUserId);
      expect(userSecrets.length).toBe(2);
    });

    it('should return secrets in order', async () => {
      await secrets.createSecret(testUserId, 'Secret 1', 'value 1', 'pass1');
      await secrets.createSecret(testUserId, 'Secret 2', 'value 2', 'pass2');
      await secrets.createSecret(testUserId, 'Secret 3', 'value 3', 'pass3');

      const userSecrets = await secrets.getSecrets(testUserId);
      expect(userSecrets[0].description).toBe('Secret 1');
      expect(userSecrets[1].description).toBe('Secret 2');
      expect(userSecrets[2].description).toBe('Secret 3');
    });
  });

  describe('decryptSecret', () => {
    it('should decrypt secret with correct password', async () => {
      const encrypted = await secrets.createSecret(
        testUserId,
        'Test Secret',
        'my secret value',
        'correct-password'
      );

      const decrypted = await secrets.decryptSecret(encrypted, 'correct-password');
      expect(decrypted).not.toBeNull();
      expect(decrypted!.secret).toBe('my secret value');
      expect(decrypted!.description).toBe('Test Secret');
    });

    it('should fail to decrypt with wrong password', async () => {
      const encrypted = await secrets.createSecret(
        testUserId,
        'Test Secret',
        'my secret value',
        'correct-password'
      );

      const decrypted = await secrets.decryptSecret(encrypted, 'wrong-password');
      expect(decrypted).toBeNull();
    });
  });

  describe('deleteSecret', () => {
    it('should delete a secret', async () => {
      const secret = await secrets.createSecret(
        testUserId,
        'Test Secret',
        'value',
        'password'
      );

      await secrets.deleteSecret(testUserId, secret.id);

      const userSecrets = await secrets.getSecrets(testUserId);
      expect(userSecrets.length).toBe(0);
    });

    it('should only delete the specified secret', async () => {
      const secret1 = await secrets.createSecret(testUserId, 'Secret 1', 'value 1', 'pass1');
      const secret2 = await secrets.createSecret(testUserId, 'Secret 2', 'value 2', 'pass2');
      const secret3 = await secrets.createSecret(testUserId, 'Secret 3', 'value 3', 'pass3');

      await secrets.deleteSecret(testUserId, secret2.id);

      const userSecrets = await secrets.getSecrets(testUserId);
      expect(userSecrets.length).toBe(2);
      expect(userSecrets.find(s => s.id === secret1.id)).toBeTruthy();
      expect(userSecrets.find(s => s.id === secret2.id)).toBeFalsy();
      expect(userSecrets.find(s => s.id === secret3.id)).toBeTruthy();
    });
  });

  describe('reorderSecrets', () => {
    it('should reorder secrets', async () => {
      const secret1 = await secrets.createSecret(testUserId, 'Secret 1', 'value 1', 'pass1');
      const secret2 = await secrets.createSecret(testUserId, 'Secret 2', 'value 2', 'pass2');
      const secret3 = await secrets.createSecret(testUserId, 'Secret 3', 'value 3', 'pass3');

      // Reorder: 3, 1, 2
      await secrets.reorderSecrets(testUserId, [secret3.id, secret1.id, secret2.id]);

      const userSecrets = await secrets.getSecrets(testUserId);
      expect(userSecrets[0].id).toBe(secret3.id);
      expect(userSecrets[0].order).toBe(0);
      expect(userSecrets[1].id).toBe(secret1.id);
      expect(userSecrets[1].order).toBe(1);
      expect(userSecrets[2].id).toBe(secret2.id);
      expect(userSecrets[2].order).toBe(2);
    });
  });

  describe('updateDescription', () => {
    it('should update secret description', async () => {
      const secret = await secrets.createSecret(
        testUserId,
        'Original Description',
        'value',
        'password'
      );

      await secrets.updateDescription(testUserId, secret.id, 'New Description');

      const userSecrets = await secrets.getSecrets(testUserId);
      expect(userSecrets[0].description).toBe('New Description');
    });

    it('should throw error for non-existent secret', async () => {
      try {
        await secrets.updateDescription(testUserId, 'nonexistent-id', 'New Description');
        fail('Should have thrown an error');
      } catch (error: any) {
        expect(error.message).toContain('not found');
      }
    });
  });
});

/**
 * Storage implementations tests
 */
describe('Storage Implementations', () => {
  describe('LocalStorageImpl', () => {
    let storage: LocalStorageImpl;
    const testUserId = 'test-user';

    beforeEach(async () => {
      localStorage.clear();
      storage = new LocalStorageImpl();
      await storage.initialize();
    });

    afterEach(() => {
      localStorage.clear();
    });

    it('should save and retrieve user profile', async () => {
      const profile = {
        userId: testUserId,
        passwordHash: 'hash123',
        passwordSalt: 'salt123',
        createdAt: Date.now()
      };

      await storage.saveUserProfile(profile);
      const retrieved = await storage.getUserProfile(testUserId);

      expect(retrieved).toEqual(profile);
    });

    it('should return null for non-existent profile', async () => {
      const profile = await storage.getUserProfile('nonexistent');
      expect(profile).toBeNull();
    });

    it('should save and retrieve secrets', async () => {
      const secret = {
        id: 'secret-1',
        description: 'Test',
        ciphertext: 'encrypted',
        iv: 'iv123',
        salt: 'salt123',
        createdAt: Date.now(),
        order: 0
      };

      await storage.saveSecret(testUserId, secret);
      const secrets = await storage.getSecrets(testUserId);

      expect(secrets.length).toBe(1);
      expect(secrets[0]).toEqual(secret);
    });

    it('should update existing secret', async () => {
      const secret = {
        id: 'secret-1',
        description: 'Original',
        ciphertext: 'encrypted',
        iv: 'iv123',
        salt: 'salt123',
        createdAt: Date.now(),
        order: 0
      };

      await storage.saveSecret(testUserId, secret);

      const updated = { ...secret, description: 'Updated' };
      await storage.saveSecret(testUserId, updated);

      const secrets = await storage.getSecrets(testUserId);
      expect(secrets.length).toBe(1);
      expect(secrets[0].description).toBe('Updated');
    });

    it('should delete secret', async () => {
      const secret1 = {
        id: 'secret-1',
        description: 'Test 1',
        ciphertext: 'encrypted',
        iv: 'iv123',
        salt: 'salt123',
        createdAt: Date.now(),
        order: 0
      };
      const secret2 = {
        id: 'secret-2',
        description: 'Test 2',
        ciphertext: 'encrypted',
        iv: 'iv123',
        salt: 'salt123',
        createdAt: Date.now(),
        order: 1
      };

      await storage.saveSecret(testUserId, secret1);
      await storage.saveSecret(testUserId, secret2);
      await storage.deleteSecret(testUserId, 'secret-1');

      const secrets = await storage.getSecrets(testUserId);
      expect(secrets.length).toBe(1);
      expect(secrets[0].id).toBe('secret-2');
    });
  });

  describe('MockFirestoreImpl', () => {
    let storage: MockFirestoreImpl;
    const testUserId = 'test-user';

    beforeEach(async () => {
      localStorage.clear();
      storage = new MockFirestoreImpl();
      await storage.initialize();
    });

    afterEach(() => {
      localStorage.clear();
    });

    it('should behave like LocalStorageImpl for user profiles', async () => {
      const profile = {
        userId: testUserId,
        passwordHash: 'hash123',
        passwordSalt: 'salt123',
        createdAt: Date.now()
      };

      await storage.saveUserProfile(profile);
      const retrieved = await storage.getUserProfile(testUserId);

      expect(retrieved).toEqual(profile);
    });

    it('should behave like LocalStorageImpl for secrets', async () => {
      const secret = {
        id: 'secret-1',
        description: 'Test',
        ciphertext: 'encrypted',
        iv: 'iv123',
        salt: 'salt123',
        createdAt: Date.now(),
        order: 0
      };

      await storage.saveSecret(testUserId, secret);
      const secrets = await storage.getSecrets(testUserId);

      expect(secrets.length).toBe(1);
      expect(secrets[0]).toEqual(secret);
    });

    it('should use different localStorage keys than LocalStorageImpl', async () => {
      const localImpl = new LocalStorageImpl();
      const mockImpl = new MockFirestoreImpl();

      const profile = {
        userId: testUserId,
        passwordHash: 'hash123',
        passwordSalt: 'salt123',
        createdAt: Date.now()
      };

      await localImpl.saveUserProfile(profile);
      await mockImpl.saveUserProfile(profile);

      // Both should be retrievable independently
      const fromLocal = await localImpl.getUserProfile(testUserId);
      const fromMock = await mockImpl.getUserProfile(testUserId);

      expect(fromLocal).toEqual(profile);
      expect(fromMock).toEqual(profile);
    });
  });
});
}

// Export a function to run tests
export function runTests() {
  configureJasmine();
  defineTests();
  jasmine.getEnv().execute();
}

// Auto-export to global scope for easy access
(window as any).runShangriLaTests = runTests;
