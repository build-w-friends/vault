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
  return crypto.getRandomValues(new Uint8Array(MASTER_KEY_BYTES)).toBase64();
}

type Bytes = Uint8Array<ArrayBuffer>;

export function parseMasterKey(value: string | undefined): Bytes {
  if (value == null || value.length === 0) {
    throw new MasterKeyError("MASTER_KEY is required");
  }
  let bytes: Bytes;
  try {
    bytes = Uint8Array.fromBase64(value.trim());
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
    private readonly dataKey: Bytes,
    private readonly encryptionKey: CryptoKey,
    private readonly hmacKey: CryptoKey,
  ) {}

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
    return seal(this.encryptionKey, new TextEncoder().encode(plaintext));
  }

  async decrypt(stored: string): Promise<string> {
    return new TextDecoder().decode(
      await open(this.encryptionKey, Uint8Array.fromBase64(stored)),
    );
  }

  async lookupHash(name: string): Promise<string> {
    const sig = await crypto.subtle.sign(
      "HMAC",
      this.hmacKey,
      new TextEncoder().encode(name),
    );
    return new Uint8Array(sig).toHex();
  }

  async sha256(input: string): Promise<string> {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
    return new Uint8Array(digest).toHex();
  }
}

export async function masterKeyFingerprint(masterKey: Bytes): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", masterKey);
  return new Uint8Array(digest).toHex().slice(0, 32);
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

async function rootEncryptionKey(masterKey: Bytes): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", masterKey, "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);
}

/** AES-GCM with a fresh IV, stored as base64 of `iv || ciphertext`. */
async function seal(key: CryptoKey, plaintext: BufferSource): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
  const combined = new Uint8Array(IV_LENGTH + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), IV_LENGTH);
  return combined.toBase64();
}

/** Reverses `seal` for already-decoded `iv || ciphertext` bytes. */
function open(key: CryptoKey, raw: Bytes): Promise<ArrayBuffer> {
  return crypto.subtle.decrypt(
    { name: "AES-GCM", iv: raw.slice(0, IV_LENGTH) },
    key,
    raw.slice(IV_LENGTH),
  );
}

async function wrapDataKey(masterKey: Bytes, dataKey: Bytes): Promise<string> {
  return seal(await rootEncryptionKey(masterKey), dataKey);
}

async function unwrapDataKey(masterKey: Bytes, stored: string): Promise<Bytes> {
  const raw = Uint8Array.fromBase64(stored);
  if (raw.byteLength <= IV_LENGTH) {
    throw new MasterKeyError("wrapped vault data key is malformed");
  }
  try {
    return new Uint8Array(await open(await rootEncryptionKey(masterKey), raw));
  } catch {
    throw new MasterKeyError("MASTER_KEY does not unwrap this vault");
  }
}
