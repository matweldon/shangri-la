/**
 * Main application module
 * Handles UI rendering, event handling, and application state
 */

import { IStorage } from './storage.js';
import { LocalStorageImpl } from './localStorageImpl.js';
import { FirestoreImpl, MockFirestoreImpl } from './firestoreImpl.js';
import { AuthService } from './auth.js';
import { SecretsService } from './secrets.js';
import { EncryptedSecret } from './types.js';

class ShangriLaApp {
  private storage: IStorage;
  private auth: AuthService;
  private secrets: SecretsService;
  private storageMode: 'local' | 'online' = 'local';
  private useMockFirestore: boolean = true;

  // UI State
  private draggedElement: HTMLElement | null = null;
  private draggedSecretId: string | null = null;

  constructor() {
    // Initialize with local storage by default
    this.storage = new LocalStorageImpl();
    this.auth = new AuthService(this.storage);
    this.secrets = new SecretsService(this.storage);
  }

  /**
   * Initialize the application
   */
  async initialize(): Promise<void> {
    // Load settings from localStorage
    const savedMode = localStorage.getItem('shangri-la:storage-mode');
    if (savedMode === 'online') {
      this.storageMode = 'online';
      await this.switchToOnlineMode();
    }

    await this.storage.initialize();

    // Set up event listeners
    this.setupEventListeners();

    // Show appropriate view
    this.showLoginView();
  }

  /**
   * Switch storage mode
   */
  async switchStorageMode(mode: 'local' | 'online'): Promise<void> {
    if (mode === this.storageMode) {
      return;
    }

    this.storageMode = mode;
    localStorage.setItem('shangri-la:storage-mode', mode);

    if (mode === 'local') {
      this.storage = new LocalStorageImpl();
    } else {
      await this.switchToOnlineMode();
    }

    this.auth = new AuthService(this.storage);
    this.secrets = new SecretsService(this.storage);
    await this.storage.initialize();

    // Logout and return to login view
    this.auth.logout();
    this.showLoginView();
  }

  /**
   * Switch to online (Firestore) mode
   */
  private async switchToOnlineMode(): Promise<void> {
    try {
      // Try to use real Firestore if available
      this.storage = new FirestoreImpl();
      await this.storage.initialize();
      this.useMockFirestore = false;
    } catch (error) {
      // Fall back to mock Firestore
      console.warn('Firestore not available, using mock implementation');
      this.storage = new MockFirestoreImpl();
      this.useMockFirestore = true;
    }
  }

  /**
   * Set up global event listeners
   */
  private setupEventListeners(): void {
    // Hamburger menu
    const hamburger = document.getElementById('hamburger-menu');
    const settingsPanel = document.getElementById('settings-panel');
    const closeSettings = document.getElementById('close-settings');

    hamburger?.addEventListener('click', () => {
      settingsPanel?.classList.add('active');
    });

    closeSettings?.addEventListener('click', () => {
      settingsPanel?.classList.remove('active');
    });

    // Settings - storage mode
    const localModeBtn = document.getElementById('local-mode-btn');
    const onlineModeBtn = document.getElementById('online-mode-btn');

    localModeBtn?.addEventListener('click', async () => {
      await this.switchStorageMode('local');
      this.updateStorageModeUI();
    });

    onlineModeBtn?.addEventListener('click', async () => {
      await this.switchStorageMode('online');
      this.updateStorageModeUI();
    });

    // Settings - logout
    const logoutBtn = document.getElementById('logout-btn');
    logoutBtn?.addEventListener('click', () => {
      this.auth.logout();
      settingsPanel?.classList.remove('active');
      this.showLoginView();
    });

    // Login form
    const loginForm = document.getElementById('login-form');
    loginForm?.addEventListener('submit', (e) => {
      e.preventDefault();
      this.handleLogin();
    });

    // Add secret button
    const addSecretBtn = document.getElementById('add-secret-btn');
    addSecretBtn?.addEventListener('click', () => {
      this.showAddSecretView();
    });

    // Add secret form
    const addSecretForm = document.getElementById('add-secret-form');
    addSecretForm?.addEventListener('submit', (e) => {
      e.preventDefault();
      this.handleAddSecret();
    });

    // Cancel add secret
    const cancelAddBtn = document.getElementById('cancel-add-secret');
    cancelAddBtn?.addEventListener('click', () => {
      this.showSecretsListView();
    });

    // View secret form
    const viewSecretForm = document.getElementById('view-secret-form');
    viewSecretForm?.addEventListener('submit', (e) => {
      e.preventDefault();
      this.handleViewSecret();
    });

    // Cancel view secret
    const cancelViewBtn = document.getElementById('cancel-view-secret');
    cancelViewBtn?.addEventListener('click', () => {
      this.showSecretsListView();
    });

    // Copy secret button
    const copySecretBtn = document.getElementById('copy-secret-btn');
    copySecretBtn?.addEventListener('click', () => {
      this.copySecretToClipboard();
    });

    // Close secret view
    const closeSecretBtn = document.getElementById('close-secret-view');
    closeSecretBtn?.addEventListener('click', () => {
      this.showSecretsListView();
    });
  }

  /**
   * Update storage mode UI
   */
  private updateStorageModeUI(): void {
    const localModeBtn = document.getElementById('local-mode-btn');
    const onlineModeBtn = document.getElementById('online-mode-btn');

    if (this.storageMode === 'local') {
      localModeBtn?.classList.add('active');
      onlineModeBtn?.classList.remove('active');
    } else {
      localModeBtn?.classList.remove('active');
      onlineModeBtn?.classList.add('active');
    }

    // Show mock warning if using mock Firestore
    const mockWarning = document.getElementById('mock-firestore-warning');
    if (this.storageMode === 'online' && this.useMockFirestore && mockWarning) {
      mockWarning.style.display = 'block';
    } else if (mockWarning) {
      mockWarning.style.display = 'none';
    }
  }

  /**
   * Handle login
   */
  private async handleLogin(): Promise<void> {
    const userIdInput = document.getElementById('user-id') as HTMLInputElement;
    const passwordInput = document.getElementById('master-password') as HTMLInputElement;
    const errorMsg = document.getElementById('login-error');

    const userId = userIdInput.value.trim();
    const password = passwordInput.value;

    if (!userId || !password) {
      this.showError(errorMsg, 'Please enter both user ID and password');
      return;
    }

    try {
      // Check if user exists
      const userExists = await this.auth.userExists(userId);

      if (userExists) {
        // Login
        const success = await this.auth.login(userId, password);
        if (success) {
          this.showSecretsListView();
        } else {
          this.showError(errorMsg, 'Incorrect password');
        }
      } else {
        // Register new user
        await this.auth.register(userId, password);
        this.showSecretsListView();
      }
    } catch (error) {
      this.showError(errorMsg, 'An error occurred. Please try again.');
      console.error(error);
    }
  }

  /**
   * Show login view
   */
  private showLoginView(): void {
    this.hideAllViews();
    const loginView = document.getElementById('login-view');
    loginView?.classList.add('active');

    // Clear form
    const userIdInput = document.getElementById('user-id') as HTMLInputElement;
    const passwordInput = document.getElementById('master-password') as HTMLInputElement;
    if (userIdInput) userIdInput.value = '';
    if (passwordInput) passwordInput.value = '';

    // Hide error
    const errorMsg = document.getElementById('login-error');
    if (errorMsg) errorMsg.style.display = 'none';

    // Hide hamburger menu
    const hamburger = document.getElementById('hamburger-menu');
    if (hamburger) hamburger.style.display = 'none';

    // Hide add button
    const addBtn = document.getElementById('add-secret-btn');
    if (addBtn) addBtn.style.display = 'none';
  }

  /**
   * Show secrets list view
   */
  private async showSecretsListView(): Promise<void> {
    this.hideAllViews();
    const listView = document.getElementById('secrets-list-view');
    listView?.classList.add('active');

    // Show hamburger menu
    const hamburger = document.getElementById('hamburger-menu');
    if (hamburger) hamburger.style.display = 'block';

    // Show add button
    const addBtn = document.getElementById('add-secret-btn');
    if (addBtn) addBtn.style.display = 'flex';

    // Update storage mode UI
    this.updateStorageModeUI();

    // Load and display secrets
    await this.loadSecretsList();
  }

  /**
   * Load and display secrets list
   */
  private async loadSecretsList(): Promise<void> {
    const userId = this.auth.getCurrentUserId();
    if (!userId) {
      this.showLoginView();
      return;
    }

    try {
      const secrets = await this.secrets.getSecrets(userId);
      this.renderSecretsList(secrets);
    } catch (error) {
      console.error('Error loading secrets:', error);
    }
  }

  /**
   * Render secrets list
   */
  private renderSecretsList(secrets: EncryptedSecret[]): void {
    const container = document.getElementById('secrets-container');
    if (!container) return;

    if (secrets.length === 0) {
      container.innerHTML = '<div class="empty-state">No secrets yet. Tap + to add one.</div>';
      return;
    }

    container.innerHTML = '';

    secrets.forEach(secret => {
      const item = document.createElement('div');
      item.className = 'secret-item';
      item.draggable = true;
      item.dataset.secretId = secret.id;

      item.innerHTML = `
        <div class="drag-handle">☰</div>
        <div class="secret-description">${this.escapeHtml(secret.description)}</div>
        <button class="delete-btn" data-secret-id="${secret.id}">×</button>
      `;

      // Add event listeners
      item.addEventListener('click', (e) => {
        const target = e.target as HTMLElement;
        if (!target.classList.contains('delete-btn')) {
          this.showViewSecretPrompt(secret);
        }
      });

      const deleteBtn = item.querySelector('.delete-btn');
      deleteBtn?.addEventListener('click', (e) => {
        e.stopPropagation();
        this.handleDeleteSecret(secret.id);
      });

      // Drag and drop
      item.addEventListener('dragstart', (e) => this.handleDragStart(e, secret.id));
      item.addEventListener('dragover', (e) => this.handleDragOver(e));
      item.addEventListener('drop', (e) => this.handleDrop(e));
      item.addEventListener('dragend', () => this.handleDragEnd());

      container.appendChild(item);
    });
  }

  /**
   * Show add secret view
   */
  private showAddSecretView(): void {
    this.hideAllViews();
    const addView = document.getElementById('add-secret-view');
    addView?.classList.add('active');

    // Clear form
    const descInput = document.getElementById('secret-description') as HTMLInputElement;
    const secretInput = document.getElementById('secret-text') as HTMLTextAreaElement;
    const passwordInput = document.getElementById('secret-password') as HTMLInputElement;
    if (descInput) descInput.value = '';
    if (secretInput) secretInput.value = '';
    if (passwordInput) passwordInput.value = '';

    // Hide error
    const errorMsg = document.getElementById('add-secret-error');
    if (errorMsg) errorMsg.style.display = 'none';
  }

  /**
   * Handle add secret
   */
  private async handleAddSecret(): Promise<void> {
    const descInput = document.getElementById('secret-description') as HTMLInputElement;
    const secretInput = document.getElementById('secret-text') as HTMLTextAreaElement;
    const passwordInput = document.getElementById('secret-password') as HTMLInputElement;
    const errorMsg = document.getElementById('add-secret-error');

    const description = descInput.value.trim();
    const secret = secretInput.value;
    const password = passwordInput.value;

    if (!description || !secret || !password) {
      this.showError(errorMsg, 'Please fill in all fields');
      return;
    }

    const userId = this.auth.getCurrentUserId();
    if (!userId) {
      this.showLoginView();
      return;
    }

    try {
      await this.secrets.createSecret(userId, description, secret, password);
      this.showSecretsListView();
    } catch (error) {
      this.showError(errorMsg, 'Failed to save secret');
      console.error(error);
    }
  }

  /**
   * Show view secret prompt
   */
  private showViewSecretPrompt(secret: EncryptedSecret): void {
    this.hideAllViews();
    const viewPromptView = document.getElementById('view-secret-prompt');
    viewPromptView?.classList.add('active');

    // Store secret ID
    viewPromptView?.setAttribute('data-secret-id', secret.id);

    // Clear password input
    const passwordInput = document.getElementById('view-password') as HTMLInputElement;
    if (passwordInput) passwordInput.value = '';

    // Hide error
    const errorMsg = document.getElementById('view-secret-error');
    if (errorMsg) errorMsg.style.display = 'none';
  }

  /**
   * Handle view secret
   */
  private async handleViewSecret(): Promise<void> {
    const viewPromptView = document.getElementById('view-secret-prompt');
    const secretId = viewPromptView?.getAttribute('data-secret-id');
    const passwordInput = document.getElementById('view-password') as HTMLInputElement;
    const errorMsg = document.getElementById('view-secret-error');

    const password = passwordInput.value;

    if (!password) {
      this.showError(errorMsg, 'Please enter password');
      return;
    }

    if (!secretId) {
      this.showError(errorMsg, 'Secret not found');
      return;
    }

    const userId = this.auth.getCurrentUserId();
    if (!userId) {
      this.showLoginView();
      return;
    }

    try {
      // Get the encrypted secret
      const secrets = await this.secrets.getSecrets(userId);
      const encryptedSecret = secrets.find(s => s.id === secretId);

      if (!encryptedSecret) {
        this.showError(errorMsg, 'Secret not found');
        return;
      }

      // Decrypt the secret
      const decryptedSecret = await this.secrets.decryptSecret(encryptedSecret, password);

      if (!decryptedSecret) {
        this.showError(errorMsg, 'Incorrect password');
        return;
      }

      // Show the secret
      this.showDecryptedSecret(decryptedSecret.secret, encryptedSecret.description);
    } catch (error) {
      this.showError(errorMsg, 'Failed to decrypt secret');
      console.error(error);
    }
  }

  /**
   * Show decrypted secret
   */
  private showDecryptedSecret(secret: string, description: string): void {
    this.hideAllViews();
    const secretView = document.getElementById('secret-display-view');
    secretView?.classList.add('active');

    const titleEl = document.getElementById('secret-display-title');
    const textEl = document.getElementById('secret-display-text');

    if (titleEl) titleEl.textContent = description;
    if (textEl) textEl.textContent = secret;
  }

  /**
   * Copy secret to clipboard
   */
  private async copySecretToClipboard(): Promise<void> {
    const textEl = document.getElementById('secret-display-text');
    const copyBtn = document.getElementById('copy-secret-btn');

    if (!textEl || !copyBtn) return;

    const text = textEl.textContent || '';

    try {
      await navigator.clipboard.writeText(text);
      copyBtn.textContent = '✓ Copied';
      setTimeout(() => {
        copyBtn.textContent = 'Copy to Clipboard';
      }, 2000);
    } catch (error) {
      console.error('Failed to copy:', error);
    }
  }

  /**
   * Handle delete secret
   */
  private async handleDeleteSecret(secretId: string): Promise<void> {
    if (!confirm('Are you sure you want to delete this secret?')) {
      return;
    }

    const userId = this.auth.getCurrentUserId();
    if (!userId) {
      this.showLoginView();
      return;
    }

    try {
      await this.secrets.deleteSecret(userId, secretId);
      await this.loadSecretsList();
    } catch (error) {
      console.error('Error deleting secret:', error);
    }
  }

  /**
   * Drag and drop handlers
   */
  private handleDragStart(e: DragEvent, secretId: string): void {
    this.draggedElement = e.target as HTMLElement;
    this.draggedSecretId = secretId;
    this.draggedElement.classList.add('dragging');
  }

  private handleDragOver(e: DragEvent): void {
    e.preventDefault();
    const target = (e.target as HTMLElement).closest('.secret-item') as HTMLElement;
    if (target && target !== this.draggedElement) {
      const container = document.getElementById('secrets-container');
      const afterElement = this.getDragAfterElement(container!, e.clientY);
      if (afterElement === null) {
        container?.appendChild(this.draggedElement!);
      } else {
        container?.insertBefore(this.draggedElement!, afterElement);
      }
    }
  }

  private handleDrop(e: DragEvent): void {
    e.preventDefault();
  }

  private async handleDragEnd(): Promise<void> {
    if (this.draggedElement) {
      this.draggedElement.classList.remove('dragging');
    }

    // Get new order
    const container = document.getElementById('secrets-container');
    const items = container?.querySelectorAll('.secret-item');
    const newOrder: string[] = [];

    items?.forEach(item => {
      const secretId = (item as HTMLElement).dataset.secretId;
      if (secretId) {
        newOrder.push(secretId);
      }
    });

    // Update order in storage
    const userId = this.auth.getCurrentUserId();
    if (userId) {
      try {
        await this.secrets.reorderSecrets(userId, newOrder);
      } catch (error) {
        console.error('Error reordering secrets:', error);
      }
    }

    this.draggedElement = null;
    this.draggedSecretId = null;
  }

  private getDragAfterElement(container: HTMLElement, y: number): HTMLElement | null {
    const draggableElements = Array.from(
      container.querySelectorAll('.secret-item:not(.dragging)')
    );

    return draggableElements.reduce<HTMLElement | null>((closest, child) => {
      const box = child.getBoundingClientRect();
      const offset = y - box.top - box.height / 2;

      if (offset < 0 && (closest === null || offset > (closest as any).offset)) {
        return { element: child as HTMLElement, offset } as any;
      } else {
        return closest;
      }
    }, null) as HTMLElement | null;
  }

  /**
   * Utility functions
   */
  private hideAllViews(): void {
    const views = document.querySelectorAll('.view');
    views.forEach(view => view.classList.remove('active'));
  }

  private showError(element: HTMLElement | null, message: string): void {
    if (element) {
      element.textContent = message;
      element.style.display = 'block';
    }
  }

  private escapeHtml(text: string): string {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
}

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  const app = new ShangriLaApp();
  app.initialize();
});
