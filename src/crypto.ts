const IV_LENGTH = 12;
const MASTER_KEY_BYTES = 32;
const HKDF_INFO_ENCRYPT = "encrypt";
const HKDF_INFO_HMAC = "hmac";

export class MasterKeyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MasterKeyError";
  }
}

export function generateMasterKey(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(MASTER_KEY_BYTES));
  return encodeBase64(bytes);
}

export function parseMasterKey(value: string | undefined): Uint8Array {
  if (value == null || value.length === 0) {
    throw new MasterKeyError("MASTER_KEY is required");
  }
  let bytes: Uint8Array;
  try {
    bytes = decodeBase64(value.trim());
  } catch {
    throw new MasterKeyError("MASTER_KEY must be standard base64");
  }
  if (bytes.byteLength !== MASTER_KEY_BYTES) {
    throw new MasterKeyError("MASTER_KEY must be base64 of exactly 32 bytes");
  }
  return bytes;
}

export class VaultCrypto {
  private constructor(
    private readonly encryptionKey: CryptoKey,
    private readonly hmacKey: CryptoKey,
  ) {}

  static async fromMasterKey(masterKey: string | undefined): Promise<VaultCrypto> {
    const raw = parseMasterKey(masterKey);
    const keyBytes = new Uint8Array(raw);
    const hkdfKey = await crypto.subtle.importKey("raw", keyBytes, "HKDF", false, [
      "deriveKey",
    ]);
    const [encryptionKey, hmacKey] = await Promise.all([
      crypto.subtle.deriveKey(
        {
          name: "HKDF",
          hash: "SHA-256",
          salt: new Uint8Array(0),
          info: new TextEncoder().encode(HKDF_INFO_ENCRYPT),
        },
        hkdfKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"],
      ),
      crypto.subtle.deriveKey(
        {
          name: "HKDF",
          hash: "SHA-256",
          salt: new Uint8Array(0),
          info: new TextEncoder().encode(HKDF_INFO_HMAC),
        },
        hkdfKey,
        { name: "HMAC", hash: "SHA-256", length: 256 },
        false,
        ["sign"],
      ),
    ]);
    return new VaultCrypto(encryptionKey, hmacKey);
  }

  async encrypt(plaintext: string): Promise<string> {
    const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      this.encryptionKey,
      new TextEncoder().encode(plaintext),
    );
    const combined = new Uint8Array(iv.byteLength + ciphertext.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(ciphertext), iv.byteLength);
    return encodeBase64(combined);
  }

  async decrypt(stored: string): Promise<string> {
    const raw = decodeBase64(stored);
    const iv = raw.slice(0, IV_LENGTH);
    const ciphertext = raw.slice(IV_LENGTH);
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      this.encryptionKey,
      ciphertext,
    );
    return new TextDecoder().decode(decrypted);
  }

  async lookupHash(name: string): Promise<string> {
    const sig = await crypto.subtle.sign(
      "HMAC",
      this.hmacKey,
      new TextEncoder().encode(name),
    );
    return toHex(sig);
  }

  async sha256(input: string): Promise<string> {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
    return toHex(digest);
  }
}

function encodeBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function decodeBase64(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function toHex(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let hex = "";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  return hex;
}
