/**
 * Envelope encryption for the vault.
 *
 * Two levels: a 32-byte *root* key lives in Cloudflare Secrets Store and wraps
 * a 32-byte *data* key, and the data key encrypts every row. The data key is
 * stored only in wrapped form, once per root fingerprint, so rotating a root
 * means adding a wrap rather than decrypting and rewriting the database.
 *
 * HKDF-SHA256 splits the data key into two keys with different `info` labels
 * so the same bytes never both encrypt and authenticate:
 *
 * - `"encrypt"` derives the AES-GCM-256 key used for every stored value.
 * - `"hmac"` derives the HMAC-SHA256 key used for lookup hashes.
 *
 * A lookup hash is what lets D1 find a row by a name it does not store. It is
 * keyed, so it is not a dictionary attack away from the plaintext name, and
 * deterministic, so `getSecretByName` is an indexed lookup instead of a
 * decrypt-everything scan.
 *
 * @see {@link https://vault.buildwithfriends.dev/concepts/encryption/}
 */
const IV_LENGTH = 12;
const MASTER_KEY_BYTES = 32;
const DATA_KEY_BYTES = 32;
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
    private readonly dataKey: Uint8Array,
    private readonly encryptionKey: CryptoKey,
    private readonly hmacKey: CryptoKey,
  ) {}

  static async fromMasterKey(masterKey: string | undefined): Promise<VaultCrypto> {
    return VaultCrypto.fromDataKey(parseMasterKey(masterKey));
  }

  static async generate(): Promise<VaultCrypto> {
    return VaultCrypto.fromDataKey(
      crypto.getRandomValues(new Uint8Array(DATA_KEY_BYTES)),
    );
  }

  static async fromDataKey(dataKey: Uint8Array): Promise<VaultCrypto> {
    if (dataKey.byteLength !== DATA_KEY_BYTES) {
      throw new MasterKeyError("vault data key must contain exactly 32 bytes");
    }
    const keyBytes = new Uint8Array(dataKey);
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
    return new VaultCrypto(keyBytes, encryptionKey, hmacKey);
  }

  static async fromWrappedDataKey(
    masterKey: string | undefined,
    wrappedDataKey: string,
  ): Promise<VaultCrypto> {
    return VaultCrypto.fromDataKey(
      await unwrapDataKey(parseMasterKey(masterKey), wrappedDataKey),
    );
  }

  async wrapForMasterKey(masterKey: string | undefined): Promise<{
    fingerprint: string;
    wrappedDataKey: string;
  }> {
    const root = parseMasterKey(masterKey);
    return {
      fingerprint: await masterKeyFingerprint(root),
      wrappedDataKey: await wrapDataKey(root, this.dataKey),
    };
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

export async function masterKeyFingerprint(masterKey: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", masterKey);
  return toHex(digest).slice(0, 32);
}

export async function timingSafeStringEqual(
  provided: string,
  expected: string,
): Promise<boolean> {
  const encoder = new TextEncoder();
  const [providedHash, expectedHash] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(provided)),
    crypto.subtle.digest("SHA-256", encoder.encode(expected)),
  ]);
  const left = new Uint8Array(providedHash);
  const right = new Uint8Array(expectedHash);
  let different = left.byteLength ^ right.byteLength;
  for (let index = 0; index < left.byteLength; index += 1) {
    different |= left[index]! ^ right[index % right.byteLength]!;
  }
  return different === 0;
}

async function rootEncryptionKey(masterKey: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", masterKey, "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);
}

async function wrapDataKey(masterKey: Uint8Array, dataKey: Uint8Array): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const wrapped = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    await rootEncryptionKey(masterKey),
    dataKey,
  );
  const combined = new Uint8Array(iv.byteLength + wrapped.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(wrapped), iv.byteLength);
  return encodeBase64(combined);
}

async function unwrapDataKey(masterKey: Uint8Array, stored: string): Promise<Uint8Array> {
  const raw = decodeBase64(stored);
  if (raw.byteLength <= IV_LENGTH) {
    throw new MasterKeyError("wrapped vault data key is malformed");
  }
  try {
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: raw.slice(0, IV_LENGTH) },
      await rootEncryptionKey(masterKey),
      raw.slice(IV_LENGTH),
    );
    return new Uint8Array(decrypted);
  } catch {
    throw new MasterKeyError("MASTER_KEY does not unwrap this vault");
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
