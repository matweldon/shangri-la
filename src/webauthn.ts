/**
 * WebAuthn module for biometric authentication (fingerprint, Face ID, etc.)
 * Uses the Web Authentication API for secure, phishing-resistant authentication
 */

/**
 * Credential data stored in localStorage
 */
export interface StoredCredential {
  credentialId: string; // Base64-encoded credential ID
  publicKey: string; // Base64-encoded public key
  userId: string;
  createdAt: number;
  deviceName: string;
}

/**
 * Check if WebAuthn is supported in the current browser
 */
export function isWebAuthnSupported(): boolean {
  return (
    window.PublicKeyCredential !== undefined &&
    navigator.credentials !== undefined &&
    typeof navigator.credentials.create === 'function'
  );
}

/**
 * Check if platform authenticator (fingerprint, Face ID) is available
 */
export async function isPlatformAuthenticatorAvailable(): Promise<boolean> {
  if (!isWebAuthnSupported()) {
    return false;
  }

  try {
    const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    return available;
  } catch (error) {
    console.error('Error checking platform authenticator:', error);
    return false;
  }
}

/**
 * Convert ArrayBuffer to Base64 string
 */
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  const binary = String.fromCharCode(...bytes);
  return btoa(binary);
}

/**
 * Convert Base64 string to ArrayBuffer
 */
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Register a new credential (enroll fingerprint)
 */
export async function registerCredential(
  userId: string,
  userName: string,
  displayName: string
): Promise<StoredCredential> {
  if (!isWebAuthnSupported()) {
    throw new Error('WebAuthn is not supported in this browser');
  }

  // Generate a random challenge
  const challenge = crypto.getRandomValues(new Uint8Array(32));

  // Convert userId to bytes
  const userIdBytes = new TextEncoder().encode(userId);

  // Create credential options
  const publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions = {
    challenge: challenge,
    rp: {
      name: 'Shangri-la Secrets Manager',
      id: window.location.hostname
    },
    user: {
      id: userIdBytes,
      name: userName,
      displayName: displayName
    },
    pubKeyCredParams: [
      { alg: -7, type: 'public-key' }, // ES256
      { alg: -257, type: 'public-key' } // RS256
    ],
    authenticatorSelection: {
      authenticatorAttachment: 'platform', // Use platform authenticator (fingerprint, Face ID)
      userVerification: 'required',
      requireResidentKey: false
    },
    timeout: 60000,
    attestation: 'none'
  };

  // Create the credential
  const credential = (await navigator.credentials.create({
    publicKey: publicKeyCredentialCreationOptions
  })) as PublicKeyCredential;

  if (!credential) {
    throw new Error('Failed to create credential');
  }

  const response = credential.response as AuthenticatorAttestationResponse;

  // Store credential info
  const storedCredential: StoredCredential = {
    credentialId: arrayBufferToBase64(credential.rawId),
    publicKey: arrayBufferToBase64(response.getPublicKey()!),
    userId: userId,
    createdAt: Date.now(),
    deviceName: getDeviceName()
  };

  return storedCredential;
}

/**
 * Authenticate using an existing credential
 */
export async function authenticateWithCredential(
  credentialId: string
): Promise<boolean> {
  if (!isWebAuthnSupported()) {
    throw new Error('WebAuthn is not supported in this browser');
  }

  // Generate a random challenge
  const challenge = crypto.getRandomValues(new Uint8Array(32));

  // Convert credential ID to ArrayBuffer
  const credentialIdBuffer = base64ToArrayBuffer(credentialId);

  // Create assertion options
  const publicKeyCredentialRequestOptions: PublicKeyCredentialRequestOptions = {
    challenge: challenge,
    allowCredentials: [
      {
        id: credentialIdBuffer,
        type: 'public-key',
        transports: ['internal']
      }
    ],
    timeout: 60000,
    userVerification: 'required'
  };

  try {
    // Get the credential
    const credential = (await navigator.credentials.get({
      publicKey: publicKeyCredentialRequestOptions
    })) as PublicKeyCredential;

    if (!credential) {
      return false;
    }

    // In a real implementation, you would verify the signature on the server
    // For this client-side app, we just check that the credential was retrieved successfully
    return true;
  } catch (error) {
    console.error('Authentication failed:', error);
    return false;
  }
}

/**
 * Get a device name for display purposes
 */
function getDeviceName(): string {
  const ua = navigator.userAgent;

  if (/(iPhone|iPad|iPod)/.test(ua)) {
    return 'iOS Device';
  } else if (/Mac/.test(ua)) {
    return 'Mac';
  } else if (/Android/.test(ua)) {
    return 'Android Device';
  } else if (/Windows/.test(ua)) {
    return 'Windows PC';
  } else if (/Linux/.test(ua)) {
    return 'Linux PC';
  } else {
    return 'Unknown Device';
  }
}

/**
 * Get stored credentials for a user
 */
export function getStoredCredentials(userId: string): StoredCredential[] {
  const key = `shangri-la:webauthn-credentials:${userId}`;
  const data = localStorage.getItem(key);
  if (!data) {
    return [];
  }
  return JSON.parse(data) as StoredCredential[];
}

/**
 * Save a credential to localStorage
 */
export function saveCredential(credential: StoredCredential): void {
  const key = `shangri-la:webauthn-credentials:${credential.userId}`;
  const existing = getStoredCredentials(credential.userId);

  // Add new credential
  existing.push(credential);

  localStorage.setItem(key, JSON.stringify(existing));
}

/**
 * Delete a credential from localStorage
 */
export function deleteCredential(userId: string, credentialId: string): void {
  const key = `shangri-la:webauthn-credentials:${userId}`;
  const existing = getStoredCredentials(userId);

  // Filter out the credential to delete
  const filtered = existing.filter(c => c.credentialId !== credentialId);

  if (filtered.length > 0) {
    localStorage.setItem(key, JSON.stringify(filtered));
  } else {
    localStorage.removeItem(key);
  }
}

/**
 * Check if user has any registered credentials
 */
export function hasRegisteredCredentials(userId: string): boolean {
  return getStoredCredentials(userId).length > 0;
}
