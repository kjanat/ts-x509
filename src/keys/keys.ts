/**
 * WebCrypto key generation plus import/export for PKCS#1, PKCS#8, SEC1, SPKI, and JWK.
 *
 * Supports RSA (PKCS#1v1.5, PSS, and OAEP), ECDSA (P-256, P-384, P-521), and Ed25519 keys.
 * All functions use the WebCrypto API and return extractable keys.
 *
 * @example
 * ```ts
 * import { unwrap } from 'micro509';
 * import { generateKeyPair, exportSpkiPem, importSpkiPem } from 'micro509/keys';
 *
 * // Generate and export
 * const keys = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
 * const publicPem = await exportSpkiPem(keys.publicKey);
 *
 * // Import — Result-returning; unwrap() throws on failure
 * const publicKey = unwrap(await importSpkiPem(publicPem, { kind: 'ecdsa', curve: 'P-256' }));
 * ```
 *
 * @module
 */

import {
	decodeObjectIdentifier,
	extractBitStringValue,
	hexToBytes,
	toArrayBuffer,
	toHex,
} from '#micro509/internal/asn1/asn1';
import type { DerElement } from '#micro509/internal/asn1/der';
import {
	explicitContext,
	integer,
	nullValue,
	objectIdentifier,
	octetString,
	readRootElement,
	readSequenceChildren,
	sequence,
	tlv,
} from '#micro509/internal/asn1/der';
import { OIDS } from '#micro509/internal/asn1/oids';
import { md5 } from '#micro509/internal/crypto/hash';
import {
	createKdfBudget,
	decryptPbes2,
	encryptPbes2,
	isKdfIterationLimitError,
	isWrongPasswordError,
	type KdfLimitOptions,
	type Pbes2Parameters,
	parsePbes2AlgorithmIdentifier,
	wrongPasswordError,
} from '#micro509/internal/crypto/pbes2';
import { getCrypto } from '#micro509/internal/crypto/webcrypto';
import { base64Decode, base64Encode } from '#micro509/internal/shared/base64';
import {
	parseTraditionalPemOrThrow,
	pemDecodeOrThrow,
	pemEncode,
	trimLwsp,
} from '#micro509/pem/pem';
import {
	type ErrorResult,
	failureResult,
	type Micro509Error,
	rethrowIfInvariant,
	successResult,
} from '#micro509/result/result';

export type {
	KdfLimitOptions,
	Pbes2EncryptionOptions,
	Pbes2EncryptionScheme,
	Pbes2Parameters,
	Pbes2Prf,
} from '#micro509/internal/crypto/pbes2';
export { parsePbes2AlgorithmIdentifier } from '#micro509/internal/crypto/pbes2';

/** Hash algorithm paired with an RSA key. */
export type RsaHash = 'SHA-256' | 'SHA-384' | 'SHA-512';

/** RSA signature padding scheme. */
export type RsaSignatureScheme = 'pkcs1-v1_5' | 'pss';

/**
 * RSA padding scheme: a signature scheme, or `'oaep'` for RSA-OAEP encryption
 * keys (usable with {@linkcode encryptRsaOaep} / {@linkcode decryptRsaOaep}).
 */
export type RsaScheme = RsaSignatureScheme | 'oaep';

/** NIST elliptic curve for ECDSA keys. */
export type EcNamedCurve = 'P-256' | 'P-384' | 'P-521';

/** RSA variant of {@linkcode KeyAlgorithmInput}. */
export interface RsaKeyAlgorithmInput {
	/** Discriminant selecting RSA key generation. */
	readonly kind: 'rsa';
	/** RSA modulus size in bits. Defaults to `2048`. */
	readonly modulusLength?: 2048 | 3072 | 4096;
	/** Hash algorithm for the key. Defaults to `'SHA-256'`. */
	readonly hash?: RsaHash;
	/**
	 * Padding scheme. Defaults to `'pkcs1-v1_5'`. Pass `'oaep'` to generate an
	 * RSA-OAEP encryption pair (`encrypt`/`decrypt` usages instead of `sign`/`verify`).
	 */
	readonly scheme?: RsaScheme;
}

/** ECDSA variant of {@linkcode KeyAlgorithmInput}. */
export interface EcKeyAlgorithmInput {
	/** Discriminant selecting ECDSA key generation. */
	readonly kind: 'ecdsa';
	/** NIST curve. Defaults to `'P-256'`. */
	readonly curve?: EcNamedCurve;
}

/** Ed25519 variant of {@linkcode KeyAlgorithmInput}. */
export interface Ed25519KeyAlgorithmInput {
	/** Discriminant selecting Ed25519 key generation. */
	readonly kind: 'ed25519';
}

/** Input for {@linkcode generateKeyPair}. Selects algorithm family and parameters. */
export type KeyAlgorithmInput =
	| RsaKeyAlgorithmInput
	| EcKeyAlgorithmInput
	| Ed25519KeyAlgorithmInput;

/** Key pair with convenience export helpers. Returned by {@linkcode generateKeyPair}. */
export interface KeyPairMaterial {
	/** The WebCrypto public key (extractable, `verify` usage; `encrypt` for RSA-OAEP). */
	readonly publicKey: CryptoKey;
	/** The WebCrypto private key (extractable, `sign` usage; `decrypt` for RSA-OAEP). */
	readonly privateKey: CryptoKey;
	/** Export the public key as DER-encoded SubjectPublicKeyInfo. */
	exportSpkiDer(): Promise<Uint8Array>;
	/** Export the public key as PEM-encoded SubjectPublicKeyInfo. */
	exportSpkiPem(): Promise<string>;
	/** Export the private key as DER-encoded PKCS#8 PrivateKeyInfo. */
	exportPkcs8Der(): Promise<Uint8Array>;
	/** Export the private key as PEM-encoded PKCS#8 PrivateKeyInfo. */
	exportPkcs8Pem(): Promise<string>;
	/** Export the public key as a JSON Web Key. */
	exportPublicJwk(): Promise<JsonWebKey>;
	/** Export the private key as a JSON Web Key. */
	exportPrivateJwk(): Promise<JsonWebKey>;
}

/** RSA variant of {@linkcode PublicKeyImportInput} / {@linkcode PrivateKeyImportInput}. */
export interface ImportRsaKeyInput {
	/** Discriminant selecting RSA import. */
	readonly kind: 'rsa';
	/** Hash algorithm. Defaults to `'SHA-256'`. */
	readonly hash?: RsaHash;
	/**
	 * Padding scheme. Defaults to `'pkcs1-v1_5'`. Pass `'oaep'` to import an
	 * RSA-OAEP encryption key (`encrypt`/`decrypt` usage instead of `verify`/`sign`).
	 */
	readonly scheme?: RsaScheme;
}

/** ECDSA variant of {@linkcode PublicKeyImportInput} / {@linkcode PrivateKeyImportInput}. */
export interface ImportEcKeyInput {
	/** Discriminant selecting ECDSA import. */
	readonly kind: 'ecdsa';
	/** NIST curve the key belongs to. Required for EC import. */
	readonly curve: EcNamedCurve;
}

/** Ed25519 variant of {@linkcode PublicKeyImportInput} / {@linkcode PrivateKeyImportInput}. */
export interface ImportEd25519KeyInput {
	/** Discriminant selecting Ed25519 import. */
	readonly kind: 'ed25519';
}

/** Algorithm descriptor for public key import functions. */
export type PublicKeyImportInput = ImportRsaKeyInput | ImportEcKeyInput | ImportEd25519KeyInput;

/** Algorithm descriptor for private key import functions. Same shape as {@linkcode PublicKeyImportInput}. */
export type PrivateKeyImportInput = PublicKeyImportInput;

/** PBES2 encryption options for the encrypted PKCS#8 export/import functions. */
export interface EncryptedPkcs8Options {
	/** Password fed to PBKDF2 for key derivation. */
	readonly password: string;
	/** PBKDF2 iteration count. Default: `100_000`. */
	readonly iterations?: number;
	/** PBKDF2 salt. Default: 16 cryptographically random bytes. */
	readonly salt?: Uint8Array;
	/** AES-CBC initialization vector. Default: 16 cryptographically random bytes. */
	readonly iv?: Uint8Array;
	/** AES-CBC cipher. Default: `'AES-256-CBC'`. */
	readonly cipher?: 'AES-128-CBC' | 'AES-192-CBC' | 'AES-256-CBC';
	/** PBKDF2 pseudo-random function. Default: `'HMAC-SHA-256'`. */
	readonly prf?: 'HMAC-SHA-1' | 'HMAC-SHA-256';
}

/** Options for OpenSSL-style `Proc-Type: 4,ENCRYPTED` PEM encryption (PKCS#1/SEC1). */
export interface LegacyPemEncryptionOptions {
	/** Passphrase used to derive the encryption key. */
	readonly password: string;
	/** 16-byte initialization vector. Random when omitted. */
	readonly iv?: Uint8Array;
	/** AES-CBC cipher. Defaults to `'AES-256-CBC'`. */
	readonly cipher?: 'AES-128-CBC' | 'AES-192-CBC' | 'AES-256-CBC';
}

/** Machine-readable failure reason for the `import*` key functions. */
export type ImportKeyErrorCode = 'malformed';

/** Structured failure payload for key import. */
export interface ImportKeyFailure extends Micro509Error<ImportKeyErrorCode> {
	/** Always `false` for failures. */
	readonly ok: false;
}

/**
 * Success-or-failure result returned by the public `import*` key functions.
 *
 * On failure, `code` is always `'malformed'`: structurally invalid input,
 * algorithm mismatches, and wrong-password decryption failures all surface
 * the same way (see the throwing `*OrThrow` variants for raw error messages).
 */
export type ImportKeyResult<T> =
	| { readonly ok: true; readonly value: T }
	| ErrorResult<ImportKeyErrorCode, Record<never, never>, ImportKeyFailure>;

/**
 * Machine-readable failure reason for the `importEncrypted*` key functions.
 *
 * Distinguishes a wrong decryption password (`'invalid_password'`) from
 * structurally invalid input or algorithm mismatches (`'malformed'`), and
 * from an encoded KDF iteration count above the caller's limit
 * (`'kdf_iterations_exceeded'`).
 */
export type ImportEncryptedKeyErrorCode =
	| 'malformed'
	| 'invalid_password'
	| 'kdf_iterations_exceeded';

/** Options for the encrypted PKCS#8 import functions. */
export type ImportEncryptedKeyOptions = KdfLimitOptions;

/** Structured failure payload for encrypted key import. */
export interface ImportEncryptedKeyFailure extends Micro509Error<ImportEncryptedKeyErrorCode> {
	/** Always `false` for failures. */
	readonly ok: false;
}

/**
 * Success-or-failure result returned by the public `importEncrypted*` key functions.
 *
 * On failure, `code` is `'invalid_password'` when decryption failed (wrong
 * password or corrupted ciphertext) and `'malformed'` for everything else.
 */
export type ImportEncryptedKeyResult<T> =
	| { readonly ok: true; readonly value: T }
	| ErrorResult<ImportEncryptedKeyErrorCode, Record<never, never>, ImportEncryptedKeyFailure>;

/** Options shared by {@linkcode encryptRsaOaep} and {@linkcode decryptRsaOaep}. */
export interface RsaOaepOptions {
	/**
	 * Optional OAEP label bound to the ciphertext. Not encrypted, but decryption
	 * fails unless the exact same label is presented. Default: empty.
	 */
	readonly label?: Uint8Array;
}

/**
 * Machine-readable failure reason for {@linkcode encryptRsaOaep}.
 *
 * `'invalid_key'` when the key is not an RSA-OAEP public key with `encrypt`
 * usage; `'message_too_long'` when the plaintext exceeds the OAEP capacity of
 * the key (modulus bytes − 2 × hash bytes − 2).
 */
export type EncryptRsaOaepErrorCode = 'invalid_key' | 'message_too_long';

/** Structured failure payload for {@linkcode encryptRsaOaep}. */
export interface EncryptRsaOaepFailure extends Micro509Error<EncryptRsaOaepErrorCode> {
	/** Always `false` for failures. */
	readonly ok: false;
}

/** Success-or-failure result returned by {@linkcode encryptRsaOaep}. */
export type EncryptRsaOaepResult =
	| { readonly ok: true; readonly value: Uint8Array }
	| ErrorResult<EncryptRsaOaepErrorCode, Record<never, never>, EncryptRsaOaepFailure>;

/**
 * Machine-readable failure reason for {@linkcode decryptRsaOaep}.
 *
 * `'invalid_key'` when the key is not an RSA-OAEP private key with `decrypt`
 * usage; `'decryption_failed'` for every ciphertext-level failure (wrong key,
 * wrong label, tampered or truncated ciphertext) — OAEP deliberately does not
 * reveal which.
 */
export type DecryptRsaOaepErrorCode = 'invalid_key' | 'decryption_failed';

/** Structured failure payload for {@linkcode decryptRsaOaep}. */
export interface DecryptRsaOaepFailure extends Micro509Error<DecryptRsaOaepErrorCode> {
	/** Always `false` for failures. */
	readonly ok: false;
}

/** Success-or-failure result returned by {@linkcode decryptRsaOaep}. */
export type DecryptRsaOaepResult =
	| { readonly ok: true; readonly value: Uint8Array }
	| ErrorResult<DecryptRsaOaepErrorCode, Record<never, never>, DecryptRsaOaepFailure>;

/**
 * Generate an asymmetric key pair for signing and verification, or — with
 * `{ kind: 'rsa', scheme: 'oaep' }` — for RSA-OAEP encryption and decryption.
 *
 * @example
 * ```ts
 * const ecKeys = await generateKeyPair({ kind: 'ecdsa', curve: 'P-384' });
 * const rsaKeys = await generateKeyPair({ kind: 'rsa', modulusLength: 4096 });
 * const edKeys = await generateKeyPair({ kind: 'ed25519' });
 * const oaepKeys = await generateKeyPair({ kind: 'rsa', scheme: 'oaep' });
 *
 * // Default: ECDSA P-256
 * const keys = await generateKeyPair();
 * const pem = await keys.exportPkcs8Pem();
 * ```
 */
export async function generateKeyPair(
	algorithm: KeyAlgorithmInput = { kind: 'ecdsa', curve: 'P-256' },
): Promise<KeyPairMaterial> {
	const subtle = getCrypto().subtle;
	const usages: KeyUsage[] = isRsaOaepInput(algorithm)
		? ['encrypt', 'decrypt']
		: ['sign', 'verify'];
	const generated = await subtle.generateKey(toGenerateKeyAlgorithm(algorithm), true, usages);

	if (!('publicKey' in generated) || !('privateKey' in generated)) {
		throw new Error('Expected an asymmetric key pair');
	}

	return wrapKeyPair(generated.publicKey, generated.privateKey);
}

function wrapKeyPair(publicKey: CryptoKey, privateKey: CryptoKey): KeyPairMaterial {
	return {
		publicKey,
		privateKey,
		async exportSpkiDer() {
			return new Uint8Array(await getCrypto().subtle.exportKey('spki', publicKey));
		},
		async exportSpkiPem() {
			return pemEncode('PUBLIC KEY', await this.exportSpkiDer());
		},
		async exportPkcs8Der() {
			return new Uint8Array(await getCrypto().subtle.exportKey('pkcs8', privateKey));
		},
		async exportPkcs8Pem() {
			return pemEncode('PRIVATE KEY', await this.exportPkcs8Der());
		},
		exportPublicJwk() {
			return getCrypto().subtle.exportKey('jwk', publicKey);
		},
		exportPrivateJwk() {
			return getCrypto().subtle.exportKey('jwk', privateKey);
		},
	};
}

/**
 * Export a public key as DER-encoded SubjectPublicKeyInfo.
 *
 * @see {@linkcode importSpkiDer} for the inverse operation
 * @see {@linkcode exportSpkiPem} for PEM output
 */
export async function exportSpkiDer(publicKey: CryptoKey): Promise<Uint8Array> {
	return new Uint8Array(await getCrypto().subtle.exportKey('spki', publicKey));
}

/**
 * Export a private key as DER-encoded PKCS#8 PrivateKeyInfo.
 *
 * @see {@linkcode importPkcs8Der} for the inverse operation
 * @see {@linkcode exportPkcs8Pem} for PEM output
 * @see {@linkcode exportEncryptedPkcs8Der} for password-protected export
 */
export async function exportPkcs8Der(privateKey: CryptoKey): Promise<Uint8Array> {
	return new Uint8Array(await getCrypto().subtle.exportKey('pkcs8', privateKey));
}

/**
 * Export a public key as a JSON Web Key.
 *
 * @example
 * ```ts
 * const keys = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
 * const jwk = await exportPublicJwk(keys.publicKey);
 * ```
 */
export function exportPublicJwk(publicKey: CryptoKey): Promise<JsonWebKey> {
	return getCrypto().subtle.exportKey('jwk', publicKey);
}

/**
 * Export a private key as a JSON Web Key.
 *
 * @see {@linkcode importPrivateJwk} for the inverse operation
 * @see {@linkcode exportPublicJwk} for public key export
 */
export function exportPrivateJwk(privateKey: CryptoKey): Promise<JsonWebKey> {
	return getCrypto().subtle.exportKey('jwk', privateKey);
}

/**
 * Export a private key as PEM-encoded PKCS#8 PrivateKeyInfo.
 *
 * @example
 * ```ts
 * const keys = await generateKeyPair();
 * const pem = await exportPkcs8Pem(keys.privateKey);
 * // -----BEGIN PRIVATE KEY-----
 * // MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEH...
 * // -----END PRIVATE KEY-----
 * ```
 *
 * @see {@linkcode importPkcs8Pem} for the inverse operation
 * @see {@linkcode exportEncryptedPkcs8Pem} for password-protected export
 */
export async function exportPkcs8Pem(privateKey: CryptoKey): Promise<string> {
	return pemEncode('PRIVATE KEY', await exportPkcs8Der(privateKey));
}

/**
 * Export a private key as DER-encoded PBES2-encrypted PKCS#8 EncryptedPrivateKeyInfo.
 *
 * Uses PBES2 (PKCS#5 v2.1) with AES-CBC and PBKDF2. Compatible with OpenSSL.
 *
 * @param privateKey - The private key to export
 * @param options - Encryption options including password and optional algorithm settings
 *
 * @see {@linkcode importEncryptedPkcs8Der} for the inverse operation
 * @see {@linkcode exportEncryptedPkcs8Pem} for PEM output
 */
export async function exportEncryptedPkcs8Der(
	privateKey: CryptoKey,
	options: EncryptedPkcs8Options,
): Promise<Uint8Array> {
	const pkcs8 = await exportPkcs8Der(privateKey);
	const encryption = await encryptPbes2(pkcs8, options);
	return sequence([encryption.algorithmIdentifierDer, octetString(encryption.encryptedData)]);
}

/**
 * Export a private key as PEM-encoded PBES2-encrypted PKCS#8 EncryptedPrivateKeyInfo.
 *
 * @example
 * ```ts
 * const keys = await generateKeyPair();
 * const pem = await exportEncryptedPkcs8Pem(keys.privateKey, { password: 'secret' });
 * // -----BEGIN ENCRYPTED PRIVATE KEY-----
 * // MIHsMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAc...
 * // -----END ENCRYPTED PRIVATE KEY-----
 * ```
 *
 * @see {@linkcode importEncryptedPkcs8Pem} for the inverse operation
 */
export async function exportEncryptedPkcs8Pem(
	privateKey: CryptoKey,
	options: EncryptedPkcs8Options,
): Promise<string> {
	return pemEncode('ENCRYPTED PRIVATE KEY', await exportEncryptedPkcs8Der(privateKey, options));
}

/**
 * Export an RSA private key as DER-encoded PKCS#1 RSAPrivateKey.
 *
 * PKCS#1 is the legacy RSA-only format. For algorithm-agnostic export, use
 * {@linkcode exportPkcs8Der}.
 *
 * @throws {Error} If the key is not an RSA key
 *
 * @see {@linkcode importPkcs1Der} for the inverse operation
 * @see {@linkcode exportPkcs1Pem} for PEM output
 */
export async function exportPkcs1Der(privateKey: CryptoKey): Promise<Uint8Array> {
	const pkcs8 = await exportPkcs8Der(privateKey);
	const parsed = parsePkcs8PrivateKey(pkcs8);
	if (parsed.algorithmOid !== OIDS.rsaEncryption) {
		throw new Error('PKCS#1 export requires an RSA private key');
	}
	return parsed.privateKeyDer;
}

/**
 * Export an RSA private key as PEM-encoded PKCS#1 RSAPrivateKey.
 *
 * @throws {Error} If the key is not an RSA key
 *
 * @see {@linkcode importPkcs1Pem} for the inverse operation
 * @see {@linkcode exportEncryptedPkcs1Pem} for password-protected export
 */
export async function exportPkcs1Pem(privateKey: CryptoKey): Promise<string> {
	return pemEncode('RSA PRIVATE KEY', await exportPkcs1Der(privateKey));
}

/**
 * Export an RSA private key as legacy `Proc-Type: 4,ENCRYPTED` PEM (PKCS#1).
 *
 * Uses OpenSSL's traditional PEM encryption with MD5-based key derivation.
 * For modern encryption, prefer {@linkcode exportEncryptedPkcs8Pem}.
 *
 * @throws {Error} If the key is not an RSA key
 *
 * @see {@linkcode importEncryptedPkcs1Pem} for the inverse operation
 */
export async function exportEncryptedPkcs1Pem(
	privateKey: CryptoKey,
	options: LegacyPemEncryptionOptions,
): Promise<string> {
	return encryptTraditionalPem('RSA PRIVATE KEY', await exportPkcs1Der(privateKey), options);
}

/**
 * Export an EC private key as DER-encoded SEC 1 ECPrivateKey.
 *
 * SEC 1 is the legacy EC-only format. For algorithm-agnostic export, use
 * {@linkcode exportPkcs8Der}.
 *
 * The output always carries the RFC 5915 `parameters [0]` named curve
 * (matching OpenSSL), so it re-imports via {@linkcode importSec1Der} without
 * an explicit curve.
 *
 * @throws {Error} If the key is not an EC key
 *
 * @see {@linkcode importSec1Der} for the inverse operation
 * @see {@linkcode exportSec1Pem} for PEM output
 */
export async function exportSec1Der(privateKey: CryptoKey): Promise<Uint8Array> {
	const pkcs8 = await exportPkcs8Der(privateKey);
	const parsed = parsePkcs8PrivateKey(pkcs8);
	if (parsed.algorithmOid !== OIDS.ecPublicKey) {
		throw new Error('SEC1 export requires an EC private key');
	}
	return ensureSec1NamedCurveParameters(parsed.privateKeyDer, parsed.parametersOid);
}

/**
 * Export an EC private key as PEM-encoded SEC 1 ECPrivateKey.
 *
 * @throws {Error} If the key is not an EC key
 *
 * @see {@linkcode importSec1Pem} for the inverse operation
 * @see {@linkcode exportEncryptedSec1Pem} for password-protected export
 */
export async function exportSec1Pem(privateKey: CryptoKey): Promise<string> {
	return pemEncode('EC PRIVATE KEY', await exportSec1Der(privateKey));
}

/**
 * Export an EC private key as legacy `Proc-Type: 4,ENCRYPTED` PEM (SEC 1).
 *
 * Uses OpenSSL's traditional PEM encryption with MD5-based key derivation.
 * For modern encryption, prefer {@linkcode exportEncryptedPkcs8Pem}.
 *
 * @throws {Error} If the key is not an EC key
 *
 * @see {@linkcode importEncryptedSec1Pem} for the inverse operation
 */
export async function exportEncryptedSec1Pem(
	privateKey: CryptoKey,
	options: LegacyPemEncryptionOptions,
): Promise<string> {
	return encryptTraditionalPem('EC PRIVATE KEY', await exportSec1Der(privateKey), options);
}

/**
 * Export a public key as PEM-encoded SubjectPublicKeyInfo.
 *
 * @example
 * ```ts
 * const keys = await generateKeyPair();
 * const pem = await exportSpkiPem(keys.publicKey);
 * ```
 */
export async function exportSpkiPem(publicKey: CryptoKey): Promise<string> {
	return pemEncode('PUBLIC KEY', await exportSpkiDer(publicKey));
}

/**
 * Derive the matching public key from an imported (or generated) private key.
 *
 * The `import*` functions that read a PKCS#8 / PKCS#1 / SEC 1 / JWK private key
 * return a bare `CryptoKey` with only `sign` (or, for RSA-OAEP, `decrypt`)
 * usage — there is no accompanying public handle. This bridges that gap: it
 * exports the private key's JWK, strips the private components, and re-imports
 * the public half with `verify` (RSA-OAEP: `encrypt`) usage, so callers can go
 * straight to {@linkcode exportSpkiDer} / {@linkcode exportSpkiPem} (e.g. to
 * rebuild a self-signed cert or distribute the public key when only the
 * private key is on disk).
 *
 * Supports RSA (`n`/`e`), ECDSA (`x`/`y`), and Ed25519 (`x`). The derived key
 * inherits the private key's algorithm parameters (hash, curve).
 *
 * @param privateKey - An extractable private `CryptoKey`
 * @returns Extractable public `CryptoKey` with `verify` (RSA-OAEP: `encrypt`) usage
 *
 * @throws {Error} If the key is not a private key, is non-extractable, or uses
 * an unsupported key type
 *
 * @example
 * ```ts
 * const privateKey = await importPkcs8PemOrThrow(pem, { kind: 'ecdsa', curve: 'P-256' });
 * const publicKey = await derivePublicKey(privateKey);
 * const spkiPem = await exportSpkiPem(publicKey);
 * ```
 *
 * @see {@linkcode exportSpkiDer} for exporting the derived key
 */
export async function derivePublicKey(privateKey: CryptoKey): Promise<CryptoKey> {
	if (privateKey.type !== 'private') {
		throw new Error('derivePublicKey requires a private CryptoKey');
	}
	if (!privateKey.extractable) {
		throw new Error('Cannot derive public key from a non-extractable private key');
	}
	const subtle = getCrypto().subtle;
	const usage: KeyUsage = privateKey.algorithm.name === 'RSA-OAEP' ? 'encrypt' : 'verify';
	const privateJwk = await subtle.exportKey('jwk', privateKey);
	return subtle.importKey('jwk', toPublicJwk(privateJwk, usage), privateKey.algorithm, true, [
		usage,
	]);
}

/**
 * Export a key as raw base64 (no PEM headers).
 *
 * Returns SPKI-encoded base64 for public keys, PKCS#8-encoded base64 for private keys.
 * Useful for compact storage or transmission where PEM overhead is undesirable.
 *
 * @throws {Error} If the key is a symmetric/secret key
 *
 * @see {@linkcode importSpkiBase64} for public key import
 * @see {@linkcode importPkcs8Base64} for private key import
 */
export async function exportBinaryBase64(key: CryptoKey): Promise<string> {
	if (key.type === 'public') {
		return base64Encode(await exportSpkiDer(key));
	}
	if (key.type === 'private') {
		return base64Encode(await exportPkcs8Der(key));
	}
	throw new Error('Cannot export secret/symmetric CryptoKey');
}

/**
 * Import a public key from DER-encoded SubjectPublicKeyInfo.
 *
 * When `algorithm` is omitted, the algorithm (and, for EC keys, the curve) is
 * inferred from the SPKI's own AlgorithmIdentifier — useful for keys whose type
 * isn't known ahead of time. Pass `algorithm` to additionally assert that the
 * DER matches an expected algorithm.
 *
 * @param der - DER-encoded SubjectPublicKeyInfo bytes
 * @param algorithm - Optional expected algorithm; must match key contents when given
 * @returns Extractable CryptoKey with `verify` usage
 *
 * @throws {Error} If DER is malformed, encodes an unsupported algorithm, or doesn't match `algorithm`
 *
 * @see {@linkcode exportSpkiDer} for the inverse operation
 * @see {@linkcode importSpkiPem} for PEM input
 */
export async function importSpkiDerOrThrow(
	der: Uint8Array,
	algorithm?: PublicKeyImportInput,
): Promise<CryptoKey> {
	const parsedSpki = parseSpkiDer(der);
	let importInput: PublicKeyImportInput;
	if (algorithm === undefined) {
		importInput = inferKeyImportInput(parsedSpki, 'Unsupported SubjectPublicKeyInfo algorithm');
	} else {
		assertSpkiMatchesRequestedAlgorithm(parsedSpki, algorithm);
		importInput = algorithm;
	}
	try {
		return await getCrypto().subtle.importKey(
			'spki',
			new Uint8Array(der),
			toImportAlgorithm(importInput),
			true,
			publicKeyUsages(importInput),
		);
	} catch {
		throw new Error('Malformed SubjectPublicKeyInfo');
	}
}

/** Runs a throwing key import and maps an EXPECTED failure to a `'malformed'` result; invariants rethrow. */
async function importResult(run: () => Promise<CryptoKey>): Promise<ImportKeyResult<CryptoKey>> {
	try {
		return successResult(await run());
	} catch (error) {
		rethrowIfInvariant(error);
		return failureResult('malformed', error instanceof Error ? error.message : 'Malformed key');
	}
}

/** Like {@link importResult} but distinguishes a typed wrong-password failure (`'invalid_password'`). */
async function encryptedImportResult(
	run: () => Promise<CryptoKey>,
): Promise<ImportEncryptedKeyResult<CryptoKey>> {
	try {
		return successResult(await run());
	} catch (error) {
		rethrowIfInvariant(error);
		if (isWrongPasswordError(error)) {
			return failureResult('invalid_password', error.message);
		}
		if (isKdfIterationLimitError(error)) {
			return failureResult('kdf_iterations_exceeded', error.message);
		}
		return failureResult(
			'malformed',
			error instanceof Error ? error.message : 'Malformed encrypted key',
		);
	}
}

/**
 * Import a public key from DER-encoded SubjectPublicKeyInfo.
 *
 * @see `importSpkiDerOrThrow` for the throwing variant
 */
export function importSpkiDer(
	der: Uint8Array,
	algorithm?: PublicKeyImportInput,
): Promise<ImportKeyResult<CryptoKey>> {
	return importResult(() => importSpkiDerOrThrow(der, algorithm));
}

/**
 * Import a public key from PEM-encoded SubjectPublicKeyInfo.
 *
 * @example
 * ```ts
 * const pem = `-----BEGIN PUBLIC KEY-----
 * MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
 * -----END PUBLIC KEY-----`;
 * const key = await importSpkiPemOrThrow(pem, { kind: 'ecdsa', curve: 'P-256' });
 * ```
 *
 * @see {@linkcode exportSpkiPem} for the inverse operation
 */
export function importSpkiPemOrThrow(
	pem: string,
	algorithm?: PublicKeyImportInput,
): Promise<CryptoKey> {
	return importSpkiDerOrThrow(pemDecodeOrThrow('PUBLIC KEY', pem), algorithm);
}

/**
 * Import a public key from PEM-encoded SubjectPublicKeyInfo.
 *
 * @see `importSpkiPemOrThrow` for the throwing variant
 */
export function importSpkiPem(
	pem: string,
	algorithm?: PublicKeyImportInput,
): Promise<ImportKeyResult<CryptoKey>> {
	return importResult(() => importSpkiPemOrThrow(pem, algorithm));
}

/**
 * Import a public key from base64-encoded SubjectPublicKeyInfo (no PEM headers).
 *
 * @see {@linkcode exportBinaryBase64} for the inverse operation
 * @see {@linkcode importSpkiPem} for PEM input with headers
 */
export function importSpkiBase64OrThrow(
	base64: string,
	algorithm?: PublicKeyImportInput,
): Promise<CryptoKey> {
	let decoded: Uint8Array;
	try {
		decoded = base64Decode(base64);
	} catch {
		throw new Error('Invalid base64 SubjectPublicKeyInfo');
	}
	return importSpkiDerOrThrow(decoded, algorithm);
}

/**
 * Import a public key from base64-encoded SubjectPublicKeyInfo (no PEM headers).
 *
 * @see `importSpkiBase64OrThrow` for the throwing variant
 */
export function importSpkiBase64(
	base64: string,
	algorithm?: PublicKeyImportInput,
): Promise<ImportKeyResult<CryptoKey>> {
	return importResult(() => importSpkiBase64OrThrow(base64, algorithm));
}

/**
 * Import a private key from DER-encoded PKCS#8 PrivateKeyInfo.
 *
 * When `algorithm` is omitted, the algorithm (and, for EC keys, the curve) is
 * inferred from the PrivateKeyInfo's own `privateKeyAlgorithm` — useful for
 * keys whose type isn't known ahead of time. Pass `algorithm` to additionally
 * assert that the DER matches an expected algorithm.
 *
 * An RFC 5958 v2 `OneAsymmetricKey` carrying `attributes [0]` or `publicKey [1]`
 * is reduced to its v1 fields for the platform import, which Bun 1.3.14 and
 * earlier rejects outright
 * ([oven-sh/bun#35432](https://github.com/oven-sh/bun/issues/35432)). A
 * `publicKey [1]` field is checked against the private key it accompanies.
 *
 * @param der - DER-encoded PKCS#8 PrivateKeyInfo bytes
 * @param algorithm - Optional expected algorithm; must match key contents when given
 * @returns Extractable CryptoKey with `sign` usage
 *
 * @throws {Error} If DER is malformed, encodes an unsupported algorithm, doesn't match `algorithm`, or carries a `publicKey [1]` that is not the private key's own
 *
 * @see {@linkcode exportPkcs8Der} for the inverse operation
 * @see {@linkcode importPkcs8Pem} for PEM input
 * @see {@linkcode importEncryptedPkcs8Der} for encrypted PKCS#8
 */
export async function importPkcs8DerOrThrow(
	der: Uint8Array,
	algorithm?: PrivateKeyImportInput,
): Promise<CryptoKey> {
	let parsedPrivateKey: ReturnType<typeof parsePkcs8PrivateKey>;
	try {
		parsedPrivateKey = parsePkcs8PrivateKey(der);
	} catch {
		throw new Error('Malformed PKCS#8 private key');
	}
	let importInput: PrivateKeyImportInput;
	if (algorithm === undefined) {
		importInput = inferKeyImportInput(parsedPrivateKey, 'Unsupported PKCS#8 private key algorithm');
	} else {
		assertPkcs8MatchesRequestedAlgorithm(parsedPrivateKey, algorithm);
		importInput = algorithm;
	}
	let privateKey: CryptoKey;
	try {
		privateKey = await getCrypto().subtle.importKey(
			'pkcs8',
			new Uint8Array(parsedPrivateKey.v1Der),
			toImportAlgorithm(importInput),
			true,
			privateKeyUsages(importInput),
		);
	} catch {
		throw new Error('Malformed PKCS#8 private key');
	}
	const declaredPublicKey = parsedPrivateKey.declaredPublicKey;
	if (declaredPublicKey !== undefined) {
		await assertDeclaredPublicKeyMatches(privateKey, declaredPublicKey);
	}
	return privateKey;
}

/**
 * Reject a OneAsymmetricKey whose `publicKey [1]` field is not the public key of
 * its own `privateKey`.
 *
 * RFC 8410 Appendix A: "Key mismatch errors: If a public key is provided, it may
 * not agree with the private key because either it is wrong or the wrong
 * algorithm was used."
 */
async function assertDeclaredPublicKeyMatches(
	privateKey: CryptoKey,
	declared: Uint8Array,
): Promise<void> {
	const spki = await exportSpkiDer(await derivePublicKey(privateKey));
	const subjectPublicKey = readSequenceChildren(spki)[1];
	if (subjectPublicKey === undefined || subjectPublicKey.tag !== 0x03) {
		throw new Error('Malformed PKCS#8 private key');
	}
	const derived = subjectPublicKey.value.slice(1);
	if (
		derived.length !== declared.length ||
		derived.some((byte, index) => byte !== declared[index])
	) {
		throw new Error('PKCS#8 publicKey does not match the private key');
	}
}

/**
 * Import a private key from DER-encoded PKCS#8 PrivateKeyInfo.
 *
 * @see `importPkcs8DerOrThrow` for the throwing variant
 */
export function importPkcs8Der(
	der: Uint8Array,
	algorithm?: PrivateKeyImportInput,
): Promise<ImportKeyResult<CryptoKey>> {
	return importResult(() => importPkcs8DerOrThrow(der, algorithm));
}

/**
 * Import a private key from PEM-encoded PKCS#8 PrivateKeyInfo.
 *
 * When `algorithm` is omitted, it is inferred from the key's own
 * `privateKeyAlgorithm` (see {@linkcode importPkcs8DerOrThrow}).
 *
 * @example
 * ```ts
 * const key = await importPkcs8PemOrThrow(pemString, { kind: 'ecdsa', curve: 'P-256' });
 * const inferred = await importPkcs8PemOrThrow(pemString);
 * ```
 */
export function importPkcs8PemOrThrow(
	pem: string,
	algorithm?: PrivateKeyImportInput,
): Promise<CryptoKey> {
	return importPkcs8DerOrThrow(pemDecodeOrThrow('PRIVATE KEY', pem), algorithm);
}

/**
 * Import a private key from PEM-encoded PKCS#8 PrivateKeyInfo.
 *
 * @see `importPkcs8PemOrThrow` for the throwing variant
 */
export function importPkcs8Pem(
	pem: string,
	algorithm?: PrivateKeyImportInput,
): Promise<ImportKeyResult<CryptoKey>> {
	return importResult(() => importPkcs8PemOrThrow(pem, algorithm));
}

/**
 * Import a private key from DER-encoded PBES2-encrypted PKCS#8 EncryptedPrivateKeyInfo.
 *
 * Decrypts the PBES2 envelope using the provided password, then imports the key.
 *
 * When `algorithm` is omitted, it is inferred from the decrypted key's own
 * `privateKeyAlgorithm` (see {@linkcode importPkcs8DerOrThrow}).
 *
 * @param der - DER-encoded EncryptedPrivateKeyInfo bytes
 * @param password - Decryption password
 * @param algorithm - Optional expected algorithm; must match decrypted key when given
 * @param options - KDF work-factor limit
 *
 * @throws {Error} If DER is malformed, password is wrong, the PBKDF2 iteration
 * count exceeds `options.maxKdfIterations`, or algorithm doesn't match
 *
 * @see {@linkcode exportEncryptedPkcs8Der} for the inverse operation
 */
export async function importEncryptedPkcs8DerOrThrow(
	der: Uint8Array,
	password: string,
	algorithm?: PrivateKeyImportInput,
	options?: ImportEncryptedKeyOptions,
): Promise<CryptoKey> {
	const envelope = readEncryptedPkcs8Envelope(der);
	const decrypted = await decryptPbes2(
		envelope.algorithmIdentifierDer,
		envelope.encryptedData,
		password,
		createKdfBudget(options),
	);
	assertDecryptedPrivateKey(
		() => parsePkcs8PrivateKey(decrypted),
		'Invalid password or encrypted content',
	);
	return importPkcs8DerOrThrow(decrypted, algorithm);
}

/** Splits a DER `EncryptedPrivateKeyInfo` into its AlgorithmIdentifier DER and encryptedData bytes. */
function readEncryptedPkcs8Envelope(der: Uint8Array): {
	readonly algorithmIdentifierDer: Uint8Array;
	readonly encryptedData: Uint8Array;
} {
	let children: readonly ReturnType<typeof readSequenceChildren>[number][];
	try {
		children = readSequenceChildren(der);
	} catch {
		throw new Error('Malformed EncryptedPrivateKeyInfo');
	}
	const algorithmIdentifier = children[0];
	const encryptedData = children[1];
	if (
		children.length !== 2 ||
		algorithmIdentifier === undefined ||
		encryptedData === undefined ||
		encryptedData.tag !== 0x04
	) {
		throw new Error('Malformed EncryptedPrivateKeyInfo');
	}
	return {
		algorithmIdentifierDer: der.slice(
			algorithmIdentifier.start - algorithmIdentifier.headerLength,
			algorithmIdentifier.end,
		),
		encryptedData: encryptedData.value,
	};
}

/**
 * Reads the PBES2 encryption parameters of a DER PKCS#8
 * `EncryptedPrivateKeyInfo` (RFC 5958 §3) without the password: PBKDF2
 * iteration count, salt, and PRF, plus the AES-CBC variant and IV.
 * Throws on malformed DER or a non-PBES2 encryption algorithm.
 */
export function inspectEncryptedPkcs8Der(der: Uint8Array): Pbes2Parameters {
	return parsePbes2AlgorithmIdentifier(readEncryptedPkcs8Envelope(der).algorithmIdentifierDer);
}

/**
 * Import a private key from DER-encoded PBES2-encrypted PKCS#8 EncryptedPrivateKeyInfo.
 *
 * @see `importEncryptedPkcs8DerOrThrow` for the throwing variant
 */
export function importEncryptedPkcs8Der(
	der: Uint8Array,
	password: string,
	algorithm?: PrivateKeyImportInput,
	options?: ImportEncryptedKeyOptions,
): Promise<ImportEncryptedKeyResult<CryptoKey>> {
	return encryptedImportResult(() =>
		importEncryptedPkcs8DerOrThrow(der, password, algorithm, options),
	);
}

/**
 * Import a private key from PEM-encoded PBES2-encrypted PKCS#8 EncryptedPrivateKeyInfo.
 *
 * When `algorithm` is omitted, it is inferred from the decrypted key's own
 * `privateKeyAlgorithm` (see {@linkcode importPkcs8DerOrThrow}).
 *
 * @example
 * ```ts
 * const key = await importEncryptedPkcs8PemOrThrow(pem, 'secret', { kind: 'rsa' });
 * const inferred = await importEncryptedPkcs8PemOrThrow(pem, 'secret');
 * ```
 */
export function importEncryptedPkcs8PemOrThrow(
	pem: string,
	password: string,
	algorithm?: PrivateKeyImportInput,
	options?: ImportEncryptedKeyOptions,
): Promise<CryptoKey> {
	return importEncryptedPkcs8DerOrThrow(
		pemDecodeOrThrow('ENCRYPTED PRIVATE KEY', pem),
		password,
		algorithm,
		options,
	);
}

/**
 * Import a private key from PEM-encoded PBES2-encrypted PKCS#8 EncryptedPrivateKeyInfo.
 *
 * @see `importEncryptedPkcs8PemOrThrow` for the throwing variant
 */
export function importEncryptedPkcs8Pem(
	pem: string,
	password: string,
	algorithm?: PrivateKeyImportInput,
	options?: ImportEncryptedKeyOptions,
): Promise<ImportEncryptedKeyResult<CryptoKey>> {
	return encryptedImportResult(() =>
		importEncryptedPkcs8PemOrThrow(pem, password, algorithm, options),
	);
}

/**
 * Import an RSA private key from DER-encoded PKCS#1 RSAPrivateKey.
 *
 * PKCS#1 is the legacy RSA-only format. Internally converts to PKCS#8 for import.
 *
 * @see {@linkcode exportPkcs1Der} for the inverse operation
 * @see {@linkcode importPkcs1Pem} for PEM input
 */
export function importPkcs1DerOrThrow(
	der: Uint8Array,
	algorithm: ImportRsaKeyInput = { kind: 'rsa' },
): Promise<CryptoKey> {
	return importPkcs8DerOrThrow(wrapPkcs1InPkcs8(der), algorithm);
}

/**
 * Import an RSA private key from DER-encoded PKCS#1 RSAPrivateKey.
 *
 * @see `importPkcs1DerOrThrow` for the throwing variant
 */
export function importPkcs1Der(
	der: Uint8Array,
	algorithm: ImportRsaKeyInput = { kind: 'rsa' },
): Promise<ImportKeyResult<CryptoKey>> {
	return importResult(() => importPkcs1DerOrThrow(der, algorithm));
}

/**
 * Import an RSA private key from PEM-encoded PKCS#1 RSAPrivateKey.
 *
 * Expects the `-----BEGIN RSA PRIVATE KEY-----` PEM label.
 *
 * @see {@linkcode exportPkcs1Pem} for the inverse operation
 * @see {@linkcode importEncryptedPkcs1Pem} for encrypted PEM
 */
export function importPkcs1PemOrThrow(
	pem: string,
	algorithm: ImportRsaKeyInput = { kind: 'rsa' },
): Promise<CryptoKey> {
	return importPkcs1DerOrThrow(pemDecodeOrThrow('RSA PRIVATE KEY', pem), algorithm);
}

/**
 * Import an RSA private key from PEM-encoded PKCS#1 RSAPrivateKey.
 *
 * @see `importPkcs1PemOrThrow` for the throwing variant
 */
export function importPkcs1Pem(
	pem: string,
	algorithm: ImportRsaKeyInput = { kind: 'rsa' },
): Promise<ImportKeyResult<CryptoKey>> {
	return importResult(() => importPkcs1PemOrThrow(pem, algorithm));
}

/**
 * Import an RSA private key from legacy `Proc-Type: 4,ENCRYPTED` PEM (PKCS#1).
 *
 * Decrypts OpenSSL's traditional PEM encryption format.
 *
 * @see {@linkcode exportEncryptedPkcs1Pem} for the inverse operation
 * @see {@linkcode importEncryptedPkcs8Pem} for modern PBES2 encryption
 */
export async function importEncryptedPkcs1PemOrThrow(
	pem: string,
	password: string,
	algorithm: ImportRsaKeyInput = { kind: 'rsa' },
): Promise<CryptoKey> {
	const decrypted = await decryptTraditionalPem('RSA PRIVATE KEY', pem, password);
	assertDecryptedPrivateKey(
		() => parsePkcs1PrivateKey(decrypted),
		'Invalid password or encrypted PEM content',
	);
	return importPkcs1DerOrThrow(decrypted, algorithm);
}

/**
 * Import an RSA private key from legacy `Proc-Type: 4,ENCRYPTED` PEM (PKCS#1).
 *
 * @see `importEncryptedPkcs1PemOrThrow` for the throwing variant
 */
export function importEncryptedPkcs1Pem(
	pem: string,
	password: string,
	algorithm: ImportRsaKeyInput = { kind: 'rsa' },
): Promise<ImportEncryptedKeyResult<CryptoKey>> {
	return encryptedImportResult(() => importEncryptedPkcs1PemOrThrow(pem, password, algorithm));
}

/**
 * Import a private key from base64-encoded PKCS#8 PrivateKeyInfo (no PEM headers).
 *
 * @see {@linkcode exportBinaryBase64} for the inverse operation
 * @see {@linkcode importPkcs8Pem} for PEM input with headers
 */
export function importPkcs8Base64OrThrow(
	base64: string,
	algorithm?: PrivateKeyImportInput,
): Promise<CryptoKey> {
	let decoded: Uint8Array;
	try {
		decoded = base64Decode(base64);
	} catch {
		throw new Error('Invalid base64 PKCS#8 private key');
	}
	return importPkcs8DerOrThrow(decoded, algorithm);
}

/**
 * Import a private key from base64-encoded PKCS#8 PrivateKeyInfo (no PEM headers).
 *
 * @see `importPkcs8Base64OrThrow` for the throwing variant
 */
export function importPkcs8Base64(
	base64: string,
	algorithm?: PrivateKeyImportInput,
): Promise<ImportKeyResult<CryptoKey>> {
	return importResult(() => importPkcs8Base64OrThrow(base64, algorithm));
}

/**
 * Import an EC private key from DER-encoded SEC 1 ECPrivateKey.
 *
 * SEC 1 is the legacy EC-only format. Internally converts to PKCS#8 for import.
 * When the ECPrivateKey carries the optional RFC 5915 `parameters [0]` field
 * (OpenSSL always writes it), its named-curve OID must match `algorithm.curve`;
 * when the field is absent, the caller-supplied curve is trusted.
 *
 * When `algorithm` is omitted, the curve is inferred from the embedded
 * `parameters [0]` field; a key without a supported named curve then fails.
 *
 * @throws {Error} If DER is not an ECPrivateKey, its embedded curve doesn't
 * match `algorithm`, or no curve is available (neither embedded nor supplied)
 *
 * @see {@linkcode exportSec1Der} for the inverse operation
 * @see {@linkcode importSec1Pem} for PEM input
 */
export async function importSec1DerOrThrow(
	der: Uint8Array,
	algorithm?: ImportEcKeyInput,
): Promise<CryptoKey> {
	let parsedSec1: ReturnType<typeof parseSec1PrivateKey>;
	try {
		parsedSec1 = parseSec1PrivateKey(der);
	} catch {
		throw new Error('Malformed SEC 1 private key');
	}
	let importInput: ImportEcKeyInput;
	if (algorithm === undefined) {
		importInput = inferSec1ImportInput(parsedSec1);
	} else {
		assertSec1MatchesRequestedAlgorithm(parsedSec1, algorithm);
		importInput = algorithm;
	}
	return await importPkcs8DerOrThrow(wrapSec1InPkcs8(der, importInput.curve), importInput);
}

/**
 * Import an EC private key from DER-encoded SEC 1 ECPrivateKey.
 *
 * @see `importSec1DerOrThrow` for the throwing variant
 */
export function importSec1Der(
	der: Uint8Array,
	algorithm?: ImportEcKeyInput,
): Promise<ImportKeyResult<CryptoKey>> {
	return importResult(() => importSec1DerOrThrow(der, algorithm));
}

/**
 * Import an EC private key from PEM-encoded SEC 1 ECPrivateKey.
 *
 * Expects the `-----BEGIN EC PRIVATE KEY-----` PEM label. When `algorithm` is
 * omitted, the curve is inferred from the embedded `parameters [0]` field
 * (see {@linkcode importSec1DerOrThrow}).
 *
 * @see {@linkcode exportSec1Pem} for the inverse operation
 * @see {@linkcode importEncryptedSec1Pem} for encrypted PEM
 */
export function importSec1PemOrThrow(
	pem: string,
	algorithm?: ImportEcKeyInput,
): Promise<CryptoKey> {
	return importSec1DerOrThrow(pemDecodeOrThrow('EC PRIVATE KEY', pem), algorithm);
}

/**
 * Import an EC private key from PEM-encoded SEC 1 ECPrivateKey.
 *
 * @see `importSec1PemOrThrow` for the throwing variant
 */
export function importSec1Pem(
	pem: string,
	algorithm?: ImportEcKeyInput,
): Promise<ImportKeyResult<CryptoKey>> {
	return importResult(() => importSec1PemOrThrow(pem, algorithm));
}

/**
 * Import an EC private key from legacy `Proc-Type: 4,ENCRYPTED` PEM (SEC 1).
 *
 * Decrypts OpenSSL's traditional PEM encryption format.
 *
 * @see {@linkcode exportEncryptedSec1Pem} for the inverse operation
 * @see {@linkcode importEncryptedPkcs8Pem} for modern PBES2 encryption
 */
export async function importEncryptedSec1PemOrThrow(
	pem: string,
	password: string,
	algorithm?: ImportEcKeyInput,
): Promise<CryptoKey> {
	const decrypted = await decryptTraditionalPem('EC PRIVATE KEY', pem, password);
	assertDecryptedPrivateKey(
		() => parseSec1PrivateKey(decrypted),
		'Invalid password or encrypted PEM content',
	);
	return importSec1DerOrThrow(decrypted, algorithm);
}

/**
 * Import an EC private key from legacy `Proc-Type: 4,ENCRYPTED` PEM (SEC 1).
 *
 * @see `importEncryptedSec1PemOrThrow` for the throwing variant
 */
export function importEncryptedSec1Pem(
	pem: string,
	password: string,
	algorithm?: ImportEcKeyInput,
): Promise<ImportEncryptedKeyResult<CryptoKey>> {
	return encryptedImportResult(() => importEncryptedSec1PemOrThrow(pem, password, algorithm));
}

/**
 * Import a public verification key from a JSON Web Key.
 *
 * When `algorithm` is omitted, it is inferred from the JWK's own `kty`, `crv`,
 * and `alg` members (e.g. `PS256` → RSA-PSS/SHA-256, `RSA-OAEP-256` →
 * RSA-OAEP/SHA-256; an RSA JWK without `alg` defaults to PKCS#1 v1.5 with
 * SHA-256). Pass `algorithm` to additionally assert an expected algorithm.
 *
 * @param jwk - JSON Web Key object with public key components
 * @param algorithm - Optional expected algorithm; must match JWK's `kty` and `crv` when given
 * @returns Extractable CryptoKey with `verify` usage
 *
 * @throws {Error} If JWK is malformed, encodes an unsupported algorithm, or doesn't match `algorithm`
 *
 * @see {@linkcode exportPublicJwk} for the inverse operation
 */
export async function importPublicJwkOrThrow(
	jwk: JsonWebKey,
	algorithm?: PublicKeyImportInput,
): Promise<CryptoKey> {
	const importInput = algorithm ?? inferJwkImportInput(jwk);
	assertPublicJwkMatchesRequestedAlgorithm(jwk, importInput);
	try {
		return await getCrypto().subtle.importKey(
			'jwk',
			jwk,
			toImportAlgorithm(importInput),
			true,
			publicKeyUsages(importInput),
		);
	} catch {
		throw new Error('Malformed public JWK');
	}
}

/**
 * Import a public verification key from a JSON Web Key.
 *
 * @see `importPublicJwkOrThrow` for the throwing variant
 */
export function importPublicJwk(
	jwk: JsonWebKey,
	algorithm?: PublicKeyImportInput,
): Promise<ImportKeyResult<CryptoKey>> {
	return importResult(() => importPublicJwkOrThrow(jwk, algorithm));
}

/**
 * Import a private signing key from a JSON Web Key.
 *
 * When `algorithm` is omitted, it is inferred from the JWK's own `kty`, `crv`,
 * and `alg` members (see {@linkcode importPublicJwkOrThrow}).
 *
 * @param jwk - JSON Web Key object with private key components
 * @param algorithm - Optional expected algorithm; must match JWK's `kty` and `crv` when given
 * @returns Extractable CryptoKey with `sign` usage
 *
 * @throws {Error} If JWK is malformed, lacks private key material, encodes an
 * unsupported algorithm, or doesn't match `algorithm`
 *
 * @example
 * ```ts
 * const jwk = { kty: 'EC', crv: 'P-256', x: '...', y: '...', d: '...' };
 * const key = await importPrivateJwkOrThrow(jwk, { kind: 'ecdsa', curve: 'P-256' });
 * const inferred = await importPrivateJwkOrThrow(jwk);
 * ```
 *
 * @see {@linkcode exportPrivateJwk} for the inverse operation
 */
export async function importPrivateJwkOrThrow(
	jwk: JsonWebKey,
	algorithm?: PrivateKeyImportInput,
): Promise<CryptoKey> {
	const importInput = algorithm ?? inferJwkImportInput(jwk);
	assertPrivateJwkMatchesRequestedAlgorithm(jwk, importInput);
	try {
		return await getCrypto().subtle.importKey(
			'jwk',
			jwk,
			toImportAlgorithm(importInput),
			true,
			privateKeyUsages(importInput),
		);
	} catch {
		throw new Error('Malformed private JWK');
	}
}

/**
 * Import a private signing key from a JSON Web Key.
 *
 * @see `importPrivateJwkOrThrow` for the throwing variant
 */
export function importPrivateJwk(
	jwk: JsonWebKey,
	algorithm?: PrivateKeyImportInput,
): Promise<ImportKeyResult<CryptoKey>> {
	return importResult(() => importPrivateJwkOrThrow(jwk, algorithm));
}

/**
 * Encrypt a small message with an RSA-OAEP public key.
 *
 * The key must have been generated or imported with `{ kind: 'rsa', scheme: 'oaep' }`.
 * RSA-OAEP encrypts at most modulus bytes − 2 × hash bytes − 2 per call
 * (190 bytes for a 2048-bit key with SHA-256) — encrypt a symmetric key, not
 * bulk data.
 *
 * @param publicKey - RSA-OAEP public `CryptoKey` with `encrypt` usage
 * @param plaintext - Message bytes, at most the OAEP capacity of the key
 * @param options - Optional OAEP label bound to the ciphertext
 *
 * @throws {Error} If the key is not an RSA-OAEP public encryption key, or the
 * plaintext exceeds the key's OAEP capacity
 *
 * @example
 * ```ts
 * const keys = await generateKeyPair({ kind: 'rsa', scheme: 'oaep' });
 * const ciphertext = await encryptRsaOaepOrThrow(
 * 	keys.publicKey,
 * 	new TextEncoder().encode('session key'),
 * );
 * ```
 *
 * @see {@linkcode decryptRsaOaepOrThrow} for the inverse operation
 * @see `encryptRsaOaep` for the Result-returning variant
 */
export async function encryptRsaOaepOrThrow(
	publicKey: CryptoKey,
	plaintext: Uint8Array,
	options: RsaOaepOptions = {},
): Promise<Uint8Array> {
	const keyProblem = validateRsaOaepKey(publicKey, 'public', 'encrypt');
	if (keyProblem !== undefined) {
		throw new Error(keyProblem);
	}
	try {
		return new Uint8Array(
			await getCrypto().subtle.encrypt(
				toRsaOaepParams(options),
				publicKey,
				toArrayBuffer(plaintext),
			),
		);
	} catch (error) {
		rethrowIfInvariant(error);
		throw new Error(
			'Plaintext exceeds the RSA-OAEP capacity of the key (modulus bytes − 2 × hash bytes − 2)',
		);
	}
}

/**
 * Encrypt a small message with an RSA-OAEP public key.
 *
 * @example
 * ```ts
 * const keys = await generateKeyPair({ kind: 'rsa', scheme: 'oaep' });
 * const encrypted = await encryptRsaOaep(keys.publicKey, plaintext);
 * if (!encrypted.ok) {
 * 	// encrypted.code: 'invalid_key' | 'message_too_long'
 * 	throw new Error(encrypted.message);
 * }
 * const ciphertext = encrypted.value;
 * ```
 *
 * @see `encryptRsaOaepOrThrow` for the throwing variant
 */
export async function encryptRsaOaep(
	publicKey: CryptoKey,
	plaintext: Uint8Array,
	options: RsaOaepOptions = {},
): Promise<EncryptRsaOaepResult> {
	const keyProblem = validateRsaOaepKey(publicKey, 'public', 'encrypt');
	if (keyProblem !== undefined) {
		return failureResult('invalid_key', keyProblem);
	}
	try {
		return successResult(await encryptRsaOaepOrThrow(publicKey, plaintext, options));
	} catch (error) {
		rethrowIfInvariant(error);
		return failureResult(
			'message_too_long',
			error instanceof Error ? error.message : 'Plaintext exceeds the RSA-OAEP capacity',
		);
	}
}

/**
 * Decrypt an RSA-OAEP ciphertext with the matching private key.
 *
 * The key must have been generated or imported with `{ kind: 'rsa', scheme: 'oaep' }`,
 * and `options.label` must repeat the label used at encryption time (if any).
 *
 * @param privateKey - RSA-OAEP private `CryptoKey` with `decrypt` usage
 * @param ciphertext - Ciphertext produced by {@linkcode encryptRsaOaep} (or any RSA-OAEP encryptor)
 * @param options - OAEP label matching the one bound at encryption
 *
 * @throws {Error} If the key is not an RSA-OAEP private decryption key, or
 * decryption fails — wrong key, wrong label, or corrupted ciphertext (OAEP
 * deliberately does not reveal which)
 *
 * @example
 * ```ts
 * const plaintext = await decryptRsaOaepOrThrow(keys.privateKey, ciphertext);
 * ```
 *
 * @see {@linkcode encryptRsaOaepOrThrow} for the inverse operation
 * @see `decryptRsaOaep` for the Result-returning variant
 */
export async function decryptRsaOaepOrThrow(
	privateKey: CryptoKey,
	ciphertext: Uint8Array,
	options: RsaOaepOptions = {},
): Promise<Uint8Array> {
	const keyProblem = validateRsaOaepKey(privateKey, 'private', 'decrypt');
	if (keyProblem !== undefined) {
		throw new Error(keyProblem);
	}
	try {
		return new Uint8Array(
			await getCrypto().subtle.decrypt(
				toRsaOaepParams(options),
				privateKey,
				toArrayBuffer(ciphertext),
			),
		);
	} catch (error) {
		rethrowIfInvariant(error);
		throw new Error('RSA-OAEP decryption failed: wrong key, wrong label, or corrupted ciphertext');
	}
}

/**
 * Decrypt an RSA-OAEP ciphertext with the matching private key.
 *
 * @example
 * ```ts
 * const decrypted = await decryptRsaOaep(keys.privateKey, ciphertext);
 * if (!decrypted.ok) {
 * 	// decrypted.code: 'invalid_key' | 'decryption_failed'
 * 	throw new Error(decrypted.message);
 * }
 * const plaintext = decrypted.value;
 * ```
 *
 * @see `decryptRsaOaepOrThrow` for the throwing variant
 */
export async function decryptRsaOaep(
	privateKey: CryptoKey,
	ciphertext: Uint8Array,
	options: RsaOaepOptions = {},
): Promise<DecryptRsaOaepResult> {
	const keyProblem = validateRsaOaepKey(privateKey, 'private', 'decrypt');
	if (keyProblem !== undefined) {
		return failureResult('invalid_key', keyProblem);
	}
	try {
		return successResult(await decryptRsaOaepOrThrow(privateKey, ciphertext, options));
	} catch (error) {
		rethrowIfInvariant(error);
		return failureResult(
			'decryption_failed',
			error instanceof Error ? error.message : 'RSA-OAEP decryption failed',
		);
	}
}

/** Map a {@linkcode KeyAlgorithmInput} to the WebCrypto `generateKey` algorithm parameter. */
function toGenerateKeyAlgorithm(
	algorithm: KeyAlgorithmInput,
): EcKeyGenParams | RsaHashedKeyGenParams | AlgorithmIdentifier {
	switch (algorithm.kind) {
		case 'rsa':
			return {
				name: rsaSchemeToWebCryptoAlgorithmName(algorithm.scheme),
				modulusLength: algorithm.modulusLength ?? 2048,
				publicExponent: Uint8Array.of(0x01, 0x00, 0x01),
				hash: algorithm.hash ?? 'SHA-256',
			};
		case 'ecdsa':
			return {
				name: 'ECDSA',
				namedCurve: algorithm.curve ?? 'P-256',
			};
		case 'ed25519':
			return { name: 'Ed25519' };
		default: {
			const _exhaustive: never = algorithm;
			throw new Error(`Unhandled KeyAlgorithmInput kind: ${String(_exhaustive)}`);
		}
	}
}

/** Map a {@linkcode PublicKeyImportInput} to the WebCrypto `importKey` algorithm parameter. */
function toImportAlgorithm(
	algorithm: PublicKeyImportInput,
): EcKeyImportParams | RsaHashedImportParams | AlgorithmIdentifier {
	switch (algorithm.kind) {
		case 'rsa':
			return {
				name: rsaSchemeToWebCryptoAlgorithmName(algorithm.scheme),
				hash: algorithm.hash ?? 'SHA-256',
			};
		case 'ecdsa':
			return {
				name: 'ECDSA',
				namedCurve: algorithm.curve,
			};
		case 'ed25519':
			return { name: 'Ed25519' };
		default: {
			const _exhaustive: never = algorithm;
			throw new Error(`Unhandled PublicKeyImportInput kind: ${String(_exhaustive)}`);
		}
	}
}

/**
 * Rejects decrypted plaintext that is not the private-key structure it should be.
 *
 * PBES2 and traditional PEM both encrypt with unauthenticated AES-CBC, where a
 * wrong key clears the padding check roughly once in every 256 attempts and
 * yields random plaintext. Structure is the only integrity signal left, so
 * plaintext that fails to parse means the password was wrong or the ciphertext
 * was corrupted, not that the enclosing input was malformed.
 */
function assertDecryptedPrivateKey(parse: () => unknown, message: string): void {
	try {
		parse();
	} catch {
		throw wrongPasswordError(message);
	}
}

/** Structural check for a PKCS#1 RSAPrivateKey, including optional multiprime fields. */
function parsePkcs1PrivateKey(der: Uint8Array): void {
	const children = readSequenceChildren(der);
	const version = children[0];
	if (
		version === undefined ||
		version.tag !== 0x02 ||
		version.value.length !== 1 ||
		!children.slice(1, 9).every((child) => child.tag === 0x02)
	) {
		throw new Error('Malformed PKCS#1 private key');
	}
	const versionValue = version.value[0];
	if (versionValue === 0x00 && children.length === 9) {
		return;
	}
	const otherPrimeInfos = children[9];
	if (
		versionValue !== 0x01 ||
		children.length !== 10 ||
		otherPrimeInfos === undefined ||
		!isOtherPrimeInfosShape(der, otherPrimeInfos)
	) {
		throw new Error('Malformed PKCS#1 private key');
	}
}

/** RFC 8017 Appendix A.1.2: OtherPrimeInfos is a non-empty SEQUENCE OF three-INTEGER entries. */
function isOtherPrimeInfosShape(source: Uint8Array, element: DerElement): boolean {
	if (element.tag !== 0x30) {
		return false;
	}
	const otherPrimeInfosDer = source.slice(element.start - element.headerLength, element.end);
	const infos = readSequenceChildren(otherPrimeInfosDer);
	if (infos.length === 0) {
		return false;
	}
	return infos.every((info) => {
		if (info.tag !== 0x30) {
			return false;
		}
		const fields = readSequenceChildren(
			otherPrimeInfosDer.slice(info.start - info.headerLength, info.end),
		);
		return fields.length === 3 && fields.every((field) => field.tag === 0x02);
	});
}

/** Extract algorithm OID and inner key bytes from a PKCS#8 PrivateKeyInfo envelope. */
function parsePkcs8PrivateKey(der: Uint8Array): {
	/** OID identifying the algorithm family (e.g. rsaEncryption, ecPublicKey). */
	readonly algorithmOid: string;
	/** Optional algorithm parameter OID (e.g. named curve for EC keys). */
	readonly parametersOid?: string;
	/** Optional algorithm parameter tag. */
	readonly parametersTag?: number;
	/** Raw DER of the inner private key (PKCS#1 for RSA, SEC 1 for EC). */
	readonly privateKeyDer: Uint8Array;
	/** The same key reduced to `version`, `privateKeyAlgorithm`, and `privateKey`. */
	readonly v1Der: Uint8Array;
	/** `publicKey [1]` octets without the BIT STRING unused-bits octet, when the field is present. */
	readonly declaredPublicKey?: Uint8Array;
} {
	const children = readSequenceChildren(der);
	const version = children[0];
	const algorithm = children[1];
	const privateKey = children[2];
	if (
		children.length < 3 ||
		version === undefined ||
		version.tag !== 0x02 ||
		algorithm === undefined ||
		algorithm.tag !== 0x30 ||
		privateKey === undefined ||
		privateKey.tag !== 0x04
	) {
		throw new Error('Malformed PKCS#8 private key');
	}
	const declaredPublicKey = validateOneAsymmetricKeyTail(children.slice(3));
	if (readPkcs8Version(version.value) !== (declaredPublicKey === undefined ? 0 : 1)) {
		throw new Error('Malformed PKCS#8 private key');
	}
	const algorithmDer = der.slice(algorithm.start - algorithm.headerLength, algorithm.end);
	const algorithmChildren = readSequenceChildren(algorithmDer);
	const algorithmOid = algorithmChildren[0];
	if (
		algorithmOid === undefined ||
		algorithmOid.tag !== 0x06 ||
		algorithmChildren.length < 1 ||
		algorithmChildren.length > 2
	) {
		throw new Error('Malformed PKCS#8 private key');
	}
	const parameters = algorithmChildren[1];
	const oid = decodeObjectIdentifier(algorithmOid.value);
	if (CURVE_PRIVATE_KEY_ALGORITHM_OIDS.includes(oid)) {
		assertCurvePrivateKey(privateKey.value);
	}
	return {
		algorithmOid: oid,
		...(parameters === undefined ? {} : { parametersTag: parameters.tag }),
		...(parameters?.tag === 0x06
			? { parametersOid: decodeObjectIdentifier(parameters.value) }
			: {}),
		privateKeyDer: privateKey.value,
		v1Der:
			children.length === 3
				? der
				: sequence([integer(Uint8Array.of(0)), algorithmDer, octetString(privateKey.value)]),
		...(declaredPublicKey === undefined ? {} : { declaredPublicKey }),
	};
}

/** Algorithms whose `privateKey` field holds an RFC 8410 §7 `CurvePrivateKey`. */
const CURVE_PRIVATE_KEY_ALGORITHM_OIDS: readonly string[] = [
	OIDS.x25519,
	OIDS.x448,
	OIDS.ed25519,
	OIDS.ed448,
];

/**
 * Reject a `privateKey` field that does not hold exactly one DER `CurvePrivateKey`.
 *
 * RFC 8410 §7: "when encoding a OneAsymmetricKey object, the private key is
 * wrapped in a CurvePrivateKey object and wrapped by the OCTET STRING of the
 * 'privateKey' field", and `CurvePrivateKey ::= OCTET STRING`.
 */
function assertCurvePrivateKey(content: Uint8Array): void {
	const curvePrivateKey = readRootElement(content);
	if (curvePrivateKey.tag !== 0x04) {
		throw new Error('Malformed PKCS#8 private key');
	}
}

/**
 * Validate the OneAsymmetricKey tail after `privateKey` and return the
 * `publicKey [1]` octets when the field is present.
 *
 * RFC 5958 §2 encodes `attributes [0]` as an IMPLICIT constructed `SET OF`
 * (tag `A0`); RFC 8410 §7 adds `publicKey [1]` as an IMPLICIT primitive
 * `BIT STRING` (tag `81`) after it. Each appears at most once and in that order.
 * The type's two X.680 extensibility markers admit later additions, which take
 * the next context-specific numbers, so `[2]` and above are tolerated and every
 * other class is malformed.
 */
function validateOneAsymmetricKeyTail(tail: readonly DerElement[]): Uint8Array | undefined {
	let seenAttributes = false;
	let publicKey: Uint8Array | undefined;
	let seenUnknown = false;
	for (const child of tail) {
		const contextNumber = (child.tag & 0xc0) === 0x80 ? child.tag & 0x1f : -1;
		if (contextNumber === 0) {
			if (seenAttributes || publicKey !== undefined || seenUnknown || child.tag !== 0xa0) {
				throw new Error('Malformed PKCS#8 private key');
			}
			assertOneAsymmetricKeyAttributes(child.value);
			seenAttributes = true;
		} else if (contextNumber === 1) {
			if (publicKey !== undefined || seenUnknown || child.tag !== 0x81) {
				throw new Error('Malformed PKCS#8 private key');
			}
			publicKey = readPublicKeyBitString(child.value);
		} else if (contextNumber >= 2 && contextNumber <= 30) {
			seenUnknown = true;
		} else {
			throw new Error('Malformed PKCS#8 private key');
		}
	}
	return publicKey;
}

/**
 * Reject an `attributes [0]` field that does not hold a `SET OF Attribute`.
 *
 * RFC 5958 §2 types the field `Attributes ::= SET OF Attribute`, over the
 * `Attribute ::= SEQUENCE { attrType OBJECT IDENTIFIER, attrValues SET OF
 * AttributeValue }` of RFC 5652 §5.3. The implicit tag has replaced the SET OF
 * tag, so the members are read back under a universal constructed one.
 */
function assertOneAsymmetricKeyAttributes(content: Uint8Array): void {
	const attributes = tlv(0x30, content);
	for (const attribute of readSequenceChildren(attributes)) {
		if (attribute.tag !== 0x30) {
			throw new Error('Malformed PKCS#8 private key');
		}
		const fields = readSequenceChildren(
			attributes.slice(attribute.start - attribute.headerLength, attribute.end),
		);
		const type = fields[0];
		const values = fields[1];
		if (
			fields.length !== 2 ||
			type === undefined ||
			type.tag !== 0x06 ||
			values === undefined ||
			values.tag !== 0x31
		) {
			throw new Error('Malformed PKCS#8 private key');
		}
	}
}

/** Reject a `publicKey [1]` BIT STRING that is not octet-aligned or carries no key octets. */
function readPublicKeyBitString(content: Uint8Array): Uint8Array {
	if (content.length < 2 || content[0] !== 0x00) {
		throw new Error('Malformed PKCS#8 private key');
	}
	return content.slice(1);
}

/** Decode the canonical RFC 5958 version INTEGER content, `v1(0)` or `v2(1)`. */
function readPkcs8Version(content: Uint8Array): number {
	const value = content[0];
	if (content.length !== 1 || (value !== 0x00 && value !== 0x01)) {
		throw new Error('Malformed PKCS#8 private key');
	}
	return value;
}

/**
 * Extract the optional `parameters [0]` curve identifier from a SEC 1 ECPrivateKey.
 *
 * RFC 5915 §3: `ECPrivateKey ::= SEQUENCE { version INTEGER { ecPrivkeyVer1(1) }
 * (ecPrivkeyVer1), privateKey OCTET STRING, parameters [0] ECParameters
 * {{ NamedCurve }} OPTIONAL, publicKey [1] BIT STRING OPTIONAL }`.
 */
function parseSec1PrivateKey(der: Uint8Array): {
	/** Optional ECParameters tag inside `parameters [0]` (0x06 for a named curve). */
	readonly parametersTag?: number;
	/** Optional named-curve OID when the ECParameters choice is an OBJECT IDENTIFIER. */
	readonly parametersOid?: string;
} {
	const children = readSequenceChildren(der);
	const version = children[0];
	const privateKey = children[1];
	const third = children[2];
	const fourth = children[3];
	if (
		children.length < 2 ||
		children.length > 4 ||
		version === undefined ||
		version.tag !== 0x02 ||
		version.value.length !== 1 ||
		version.value[0] !== 0x01 ||
		privateKey === undefined ||
		privateKey.tag !== 0x04 ||
		(third !== undefined && third.tag !== 0xa0 && third.tag !== 0xa1) ||
		(fourth !== undefined && (third?.tag !== 0xa0 || fourth.tag !== 0xa1))
	) {
		throw new Error('Malformed SEC 1 private key');
	}
	const parameters = third?.tag === 0xa0 ? third : undefined;
	if (parameters === undefined) {
		return {};
	}
	const ecParameters = readRootElement(parameters.value);
	return {
		parametersTag: ecParameters.tag,
		...(ecParameters.tag === 0x06
			? { parametersOid: decodeObjectIdentifier(ecParameters.value) }
			: {}),
	};
}

/**
 * Ensure a SEC 1 ECPrivateKey carries the RFC 5915 `parameters [0]` named
 * curve. WebCrypto's PKCS#8 export omits it from the inner ECPrivateKey (the
 * curve lives in the envelope's privateKeyAlgorithm), but RFC 5915 wants it in
 * standalone SEC 1 — and OpenSSL always writes it. Injecting it keeps exports
 * self-describing, so they re-import without an explicit curve.
 */
function ensureSec1NamedCurveParameters(
	sec1Der: Uint8Array,
	curveOid: string | undefined,
): Uint8Array {
	const children = readSequenceChildren(sec1Der);
	if (children.some((child) => child.tag === 0xa0)) {
		return new Uint8Array(sec1Der);
	}
	if (curveOid === undefined) {
		throw new Error('SEC1 export requires a named curve in the PKCS#8 privateKeyAlgorithm');
	}
	const raw = (child: DerElement): Uint8Array =>
		sec1Der.slice(child.start - child.headerLength, child.end);
	// RFC 5915 field order: version, privateKey, parameters [0], publicKey [1].
	return sequence([
		...children.slice(0, 2).map(raw),
		explicitContext(0, objectIdentifier(curveOid)),
		...children.slice(2).map(raw),
	]);
}

/** Wrap a PKCS#1 RSAPrivateKey in a PKCS#8 PrivateKeyInfo envelope for WebCrypto import. */
function wrapPkcs1InPkcs8(der: Uint8Array): Uint8Array {
	return sequence([
		Uint8Array.of(0x02, 0x01, 0x00),
		sequence([objectIdentifier(OIDS.rsaEncryption), nullValue()]),
		octetString(new Uint8Array(der)),
	]);
}

/** Wrap a SEC 1 ECPrivateKey in a PKCS#8 PrivateKeyInfo envelope for WebCrypto import. */
function wrapSec1InPkcs8(der: Uint8Array, curve: ImportEcKeyInput['curve']): Uint8Array {
	return sequence([
		Uint8Array.of(0x02, 0x01, 0x00),
		sequence([objectIdentifier(OIDS.ecPublicKey), objectIdentifier(curveToOid(curve))]),
		octetString(new Uint8Array(der)),
	]);
}

/** Project a private JWK onto its public-only members, discarding private key material. */
function toPublicJwk(jwk: JsonWebKey, usage: KeyUsage): JsonWebKey {
	if (jwk.kty !== 'RSA' && jwk.kty !== 'EC' && jwk.kty !== 'OKP') {
		throw new Error(`Cannot derive public key: unsupported JWK key type ${String(jwk.kty)}`);
	}
	const publicJwk: JsonWebKey = { ...jwk };
	// Strip every private component: RSA (d, p, q, dp, dq, qi, oth), EC/OKP (d).
	for (const field of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'] as const) {
		delete publicJwk[field];
	}
	publicJwk.key_ops = [usage];
	publicJwk.ext = true;
	return publicJwk;
}

/**
 * Single source of truth for the NIST curve ↔ named-curve OID mapping, read in
 * both directions by {@linkcode curveToOid} and {@linkcode oidToCurve}.
 */
const EC_CURVE_OIDS = [
	['P-256', OIDS.prime256v1],
	['P-384', OIDS.secp384r1],
	['P-521', OIDS.secp521r1],
] as const satisfies readonly (readonly [EcNamedCurve, string])[];

/** Map a curve name to its ASN.1 OID string. */
function curveToOid(curve: ImportEcKeyInput['curve']): string {
	for (const [name, oid] of EC_CURVE_OIDS) {
		if (name === curve) {
			return oid;
		}
	}
	throw new Error(`Unsupported EC curve: ${curve}`);
}

/** Map an ASN.1 curve OID string back to its curve name, or `undefined` if unrecognized. */
function oidToCurve(oid: string): EcNamedCurve | undefined {
	for (const [name, curveOid] of EC_CURVE_OIDS) {
		if (curveOid === oid) {
			return name;
		}
	}
	return undefined;
}

/** Map an {@linkcode RsaScheme} to the WebCrypto algorithm name string. */
function rsaSchemeToWebCryptoAlgorithmName(
	scheme: RsaScheme | undefined,
): 'RSASSA-PKCS1-v1_5' | 'RSA-PSS' | 'RSA-OAEP' {
	if (scheme === 'pss') {
		return 'RSA-PSS';
	}
	if (scheme === 'oaep') {
		return 'RSA-OAEP';
	}
	return 'RSASSA-PKCS1-v1_5';
}

/** `true` when the algorithm input selects RSA-OAEP, whose keys carry encrypt/decrypt usages. */
function isRsaOaepInput(algorithm: KeyAlgorithmInput | PublicKeyImportInput): boolean {
	return algorithm.kind === 'rsa' && algorithm.scheme === 'oaep';
}

/** Key usages for an imported public key: `verify`, or `encrypt` for RSA-OAEP. */
function publicKeyUsages(algorithm: PublicKeyImportInput): KeyUsage[] {
	return isRsaOaepInput(algorithm) ? ['encrypt'] : ['verify'];
}

/** Key usages for an imported private key: `sign`, or `decrypt` for RSA-OAEP. */
function privateKeyUsages(algorithm: PrivateKeyImportInput): KeyUsage[] {
	return isRsaOaepInput(algorithm) ? ['decrypt'] : ['sign'];
}

/**
 * Diagnose a key unfit for the given RSA-OAEP operation.
 *
 * Returns a human-readable problem description, or `undefined` when the key is
 * usable — keeping key-level failures (`'invalid_key'`) separable from
 * ciphertext-level failures before WebCrypto is ever called.
 */
function validateRsaOaepKey(
	key: CryptoKey,
	type: 'public' | 'private',
	usage: 'encrypt' | 'decrypt',
): string | undefined {
	const operation = usage === 'encrypt' ? 'encryption' : 'decryption';
	if (key.type !== type) {
		return `RSA-OAEP ${operation} requires a ${type} CryptoKey`;
	}
	if (key.algorithm.name !== 'RSA-OAEP') {
		return `RSA-OAEP ${operation} requires an RSA-OAEP key (got ${key.algorithm.name}); generate or import the key with scheme: 'oaep'`;
	}
	if (!key.usages.includes(usage)) {
		return `RSA-OAEP ${operation} requires a key with '${usage}' usage`;
	}
	return undefined;
}

/** Build the WebCrypto RSA-OAEP params, attaching the optional label. */
function toRsaOaepParams(options: RsaOaepOptions): RsaOaepParams {
	return {
		name: 'RSA-OAEP',
		...(options.label === undefined ? {} : { label: toArrayBuffer(options.label) }),
	};
}

/** Encrypt DER key material as an OpenSSL-style `Proc-Type: 4,ENCRYPTED` PEM block. */
async function encryptTraditionalPem(
	label: 'RSA PRIVATE KEY' | 'EC PRIVATE KEY',
	der: Uint8Array,
	options: LegacyPemEncryptionOptions,
): Promise<string> {
	const iv = options.iv ?? getCrypto().getRandomValues(new Uint8Array(16));
	if (iv.length !== 16) {
		throw new Error('Traditional PEM encryption requires a 16-byte IV');
	}
	const cipher = options.cipher ?? 'AES-256-CBC';
	const key = await importTraditionalPemAesKey(options.password, iv.slice(0, 8), cipher, [
		'encrypt',
	]);
	const encrypted = new Uint8Array(
		await getCrypto().subtle.encrypt(
			{ name: 'AES-CBC', iv: toArrayBuffer(iv) },
			key,
			toArrayBuffer(der),
		),
	);
	const body =
		base64Encode(encrypted)
			.match(/.{1,64}/g)
			?.join('\n') ?? '';
	return [
		`-----BEGIN ${label}-----`,
		'Proc-Type: 4,ENCRYPTED',
		`DEK-Info: ${cipher},${toHex(iv).toUpperCase()}`,
		'',
		body,
		`-----END ${label}-----`,
	].join('\n');
}

/** Decrypt a `Proc-Type: 4,ENCRYPTED` PEM block, RFC 1421 §4.6 headers, to plaintext DER. */
async function decryptTraditionalPem(
	expectedLabel: 'RSA PRIVATE KEY' | 'EC PRIVATE KEY',
	pem: string,
	password: string,
): Promise<Uint8Array> {
	const parsed = parseTraditionalPemOrThrow(pem);
	if (parsed.label !== expectedLabel) {
		throw new Error(`Expected ${expectedLabel} PEM block`);
	}
	const dekInfo = parsed.headers.get('DEK-Info');
	const procType = parsed.headers.get('Proc-Type');
	if (procType === undefined || !isEncryptedProcType(procType) || dekInfo === undefined) {
		throw new Error('Traditional PEM encryption headers missing');
	}
	const [cipher, ivHex] = dekInfo.split(',').map(trimLwsp);
	if (!isTraditionalPemCipher(cipher) || ivHex === undefined) {
		throw new Error(
			'Only AES-128-CBC, AES-192-CBC, and AES-256-CBC traditional PEM encryption is supported',
		);
	}
	if (!isTraditionalPemIvHex(ivHex)) {
		throw new Error(
			'Traditional PEM encryption requires a 16-byte IV encoded as 32 hex characters',
		);
	}
	const iv = hexToBytes(ivHex);
	const key = await importTraditionalPemAesKey(password, iv.slice(0, 8), cipher, ['decrypt']);
	try {
		return new Uint8Array(
			await getCrypto().subtle.decrypt(
				{ name: 'AES-CBC', iv: toArrayBuffer(iv) },
				key,
				toArrayBuffer(base64Decode(parsed.base64Body)),
			),
		);
	} catch {
		throw wrongPasswordError('Invalid password or encrypted PEM content');
	}
}

/** Derive and import an AES-CBC key for legacy PEM encryption using OpenSSL `EVP_BytesToKey`. */
function importTraditionalPemAesKey(
	password: string,
	salt: Uint8Array,
	cipher: 'AES-128-CBC' | 'AES-192-CBC' | 'AES-256-CBC',
	usages: KeyUsage[],
): Promise<CryptoKey> {
	const keyLength = traditionalPemCipherKeyLength(cipher);
	const keyBytes = opensslBytesToKey(password, salt, keyLength / 8);
	return getCrypto().subtle.importKey(
		'raw',
		toArrayBuffer(keyBytes),
		{ name: 'AES-CBC', length: keyLength },
		false,
		usages,
	);
}

/**
 * RFC 1421 §4.6.1.1 `Proc-Type: 4,ENCRYPTED`.
 *
 * Fields are trimmed because RFC 822 §3.1.1 unfolding leaves an LWSP-char
 * wherever the header was folded.
 */
function isEncryptedProcType(value: string): boolean {
	const fields = value.split(',');
	return (
		fields.length === 2 &&
		trimLwsp(fields[0] ?? '') === '4' &&
		trimLwsp(fields[1] ?? '') === 'ENCRYPTED'
	);
}

/** Type guard for the three AES-CBC ciphers supported by legacy PEM encryption. */
function isTraditionalPemCipher(
	cipher: string | undefined,
): cipher is 'AES-128-CBC' | 'AES-192-CBC' | 'AES-256-CBC' {
	return cipher === 'AES-128-CBC' || cipher === 'AES-192-CBC' || cipher === 'AES-256-CBC';
}

function isTraditionalPemIvHex(value: string): boolean {
	return value.length === 32 && /^[0-9A-Fa-f]+$/.test(value);
}

/** Return the AES key size in bits for a given cipher name. */
function traditionalPemCipherKeyLength(
	cipher: 'AES-128-CBC' | 'AES-192-CBC' | 'AES-256-CBC',
): 128 | 192 | 256 {
	switch (cipher) {
		case 'AES-128-CBC':
			return 128;
		case 'AES-192-CBC':
			return 192;
		case 'AES-256-CBC':
			return 256;
		default: {
			const _exhaustive: never = cipher;
			throw new Error(`Unhandled traditional PEM cipher: ${String(_exhaustive)}`);
		}
	}
}

/** OpenSSL `EVP_BytesToKey` with MD5 — derives a fixed-length key from password + salt. */
function opensslBytesToKey(password: string, salt: Uint8Array, length: number): Uint8Array {
	const passwordBytes = new TextEncoder().encode(password);
	const chunks: Uint8Array[] = [];
	let previous = new Uint8Array();
	let total = 0;
	while (total < length) {
		const input = new Uint8Array(previous.length + passwordBytes.length + salt.length);
		input.set(previous, 0);
		input.set(passwordBytes, previous.length);
		input.set(salt, previous.length + passwordBytes.length);
		previous = md5(input);
		chunks.push(previous);
		total += previous.length;
	}
	const out = new Uint8Array(length);
	let offset = 0;
	for (const chunk of chunks) {
		const slice = chunk.slice(0, Math.min(chunk.length, length - offset));
		out.set(slice, offset);
		offset += slice.length;
		if (offset >= length) {
			break;
		}
	}
	return out;
}

function parseSpkiDer(der: Uint8Array): {
	readonly algorithmOid: string;
	readonly parametersOid?: string;
	readonly parametersTag?: number;
} {
	try {
		const children = readSequenceChildren(der);
		if (children.length !== 2) {
			throw new Error('Malformed SubjectPublicKeyInfo');
		}
		const algorithm = children[0];
		const subjectPublicKey = children[1];
		if (
			algorithm === undefined ||
			algorithm.tag !== 0x30 ||
			subjectPublicKey === undefined ||
			subjectPublicKey.tag !== 0x03
		) {
			throw new Error('Malformed SubjectPublicKeyInfo');
		}
		extractBitStringValue(subjectPublicKey);
		const algorithmChildren = readSequenceChildren(
			der.slice(algorithm.start - algorithm.headerLength, algorithm.end),
		);
		const algorithmOid = algorithmChildren[0];
		if (
			algorithmOid === undefined ||
			algorithmOid.tag !== 0x06 ||
			algorithmChildren.length < 1 ||
			algorithmChildren.length > 2
		) {
			throw new Error('Malformed SubjectPublicKeyInfo');
		}
		const parameters = algorithmChildren[1];
		return {
			algorithmOid: decodeObjectIdentifier(algorithmOid.value),
			...(parameters === undefined ? {} : { parametersTag: parameters.tag }),
			...(parameters?.tag === 0x06
				? { parametersOid: decodeObjectIdentifier(parameters.value) }
				: {}),
		};
	} catch {
		throw new Error('Malformed SubjectPublicKeyInfo');
	}
}

/**
 * Derive the import algorithm from a key envelope's own AlgorithmIdentifier
 * (SPKI `algorithm` or PKCS#8 `privateKeyAlgorithm` — both share the shape).
 *
 * RSA keys default to the `pkcs1-v1_5`/`SHA-256` import parameters (a plain
 * `rsaEncryption` AlgorithmIdentifier does not encode padding scheme or hash);
 * EC keys carry their curve in the DER; Ed25519 is fully determined by its OID.
 */
function inferKeyImportInput(
	parsed: {
		readonly algorithmOid: string;
		readonly parametersOid?: string;
		readonly parametersTag?: number;
	},
	unsupportedMessage: string,
): PublicKeyImportInput {
	switch (parsed.algorithmOid) {
		case OIDS.rsaEncryption:
			if (parsed.parametersTag === undefined || parsed.parametersTag === 0x05) {
				return { kind: 'rsa' };
			}
			break;
		case OIDS.ecPublicKey: {
			const curve =
				parsed.parametersTag === 0x06 && parsed.parametersOid !== undefined
					? oidToCurve(parsed.parametersOid)
					: undefined;
			if (curve !== undefined) {
				return { kind: 'ecdsa', curve };
			}
			break;
		}
		case OIDS.ed25519:
			if (parsed.parametersTag === undefined) {
				return { kind: 'ed25519' };
			}
			break;
	}
	throw new Error(unsupportedMessage);
}

/**
 * Derive the import curve from a SEC 1 ECPrivateKey's own RFC 5915
 * `parameters [0]` field. SEC 1 encodes no algorithm family (it is EC by
 * definition), so only the named curve needs recovering — and it may be
 * absent, in which case the caller must supply it.
 */
function inferSec1ImportInput(parsedSec1: {
	readonly parametersTag?: number;
	readonly parametersOid?: string;
}): ImportEcKeyInput {
	const curve =
		parsedSec1.parametersTag === 0x06 && parsedSec1.parametersOid !== undefined
			? oidToCurve(parsedSec1.parametersOid)
			: undefined;
	if (curve === undefined) {
		throw new Error(
			'SEC 1 private key does not encode a supported named curve; pass the algorithm explicitly',
		);
	}
	return { kind: 'ecdsa', curve };
}

/**
 * Derive the import algorithm from a JWK's own `kty`, `crv`, and `alg` members.
 *
 * `alg` disambiguates the RSA scheme and hash (`RS*`, `PS*`, `RSA-OAEP-*`) —
 * WebCrypto rejects a JWK whose `alg` disagrees with the import algorithm, so
 * it must be honored rather than defaulted over. An RSA JWK without `alg`
 * defaults to `pkcs1-v1_5`/`SHA-256`, mirroring SPKI inference.
 */
function inferJwkImportInput(jwk: JsonWebKey): PublicKeyImportInput {
	if (jwk.kty === 'RSA') {
		return rsaImportInputFromJwkAlg(jwk.alg);
	}
	if (jwk.kty === 'EC') {
		if (jwk.crv === 'P-256' || jwk.crv === 'P-384' || jwk.crv === 'P-521') {
			return { kind: 'ecdsa', curve: jwk.crv };
		}
		throw new Error(`Unsupported EC JWK curve: ${String(jwk.crv)}`);
	}
	if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') {
		return { kind: 'ed25519' };
	}
	throw new Error('Unsupported JWK key type');
}

/** Map a JWA `alg` identifier to the RSA scheme + hash it pins down. */
function rsaImportInputFromJwkAlg(alg: string | undefined): ImportRsaKeyInput {
	switch (alg) {
		case undefined:
		case 'RS256':
			return { kind: 'rsa' };
		case 'RS384':
			return { kind: 'rsa', hash: 'SHA-384' };
		case 'RS512':
			return { kind: 'rsa', hash: 'SHA-512' };
		case 'PS256':
			return { kind: 'rsa', scheme: 'pss' };
		case 'PS384':
			return { kind: 'rsa', scheme: 'pss', hash: 'SHA-384' };
		case 'PS512':
			return { kind: 'rsa', scheme: 'pss', hash: 'SHA-512' };
		case 'RSA-OAEP-256':
			return { kind: 'rsa', scheme: 'oaep' };
		case 'RSA-OAEP-384':
			return { kind: 'rsa', scheme: 'oaep', hash: 'SHA-384' };
		case 'RSA-OAEP-512':
			return { kind: 'rsa', scheme: 'oaep', hash: 'SHA-512' };
		default:
			// Includes plain 'RSA-OAEP' (SHA-1) — this library supports SHA-2 only.
			throw new Error(`Unsupported RSA JWK alg: ${alg}`);
	}
}

function assertSpkiMatchesRequestedAlgorithm(
	parsedSpki: {
		readonly algorithmOid: string;
		readonly parametersOid?: string;
		readonly parametersTag?: number;
	},
	algorithm: PublicKeyImportInput,
): void {
	switch (algorithm.kind) {
		case 'rsa':
			if (
				parsedSpki.algorithmOid !== OIDS.rsaEncryption ||
				(parsedSpki.parametersTag !== undefined && parsedSpki.parametersTag !== 0x05)
			) {
				throw new Error('SubjectPublicKeyInfo algorithm does not match requested import algorithm');
			}
			return;
		case 'ecdsa':
			if (
				parsedSpki.algorithmOid !== OIDS.ecPublicKey ||
				parsedSpki.parametersTag !== 0x06 ||
				parsedSpki.parametersOid !== curveToOid(algorithm.curve)
			) {
				throw new Error('SubjectPublicKeyInfo algorithm does not match requested import algorithm');
			}
			return;
		case 'ed25519':
			if (parsedSpki.algorithmOid !== OIDS.ed25519 || parsedSpki.parametersTag !== undefined) {
				throw new Error('SubjectPublicKeyInfo algorithm does not match requested import algorithm');
			}
			return;
		default: {
			const _exhaustive: never = algorithm;
			throw new Error(`Unhandled PublicKeyImportInput kind: ${String(_exhaustive)}`);
		}
	}
}

function assertPkcs8MatchesRequestedAlgorithm(
	parsedPrivateKey: {
		readonly algorithmOid: string;
		readonly parametersOid?: string;
		readonly parametersTag?: number;
	},
	algorithm: PrivateKeyImportInput,
): void {
	switch (algorithm.kind) {
		case 'rsa':
			if (
				parsedPrivateKey.algorithmOid !== OIDS.rsaEncryption ||
				(parsedPrivateKey.parametersTag !== undefined && parsedPrivateKey.parametersTag !== 0x05)
			) {
				throw new Error('PKCS#8 private key algorithm does not match requested import algorithm');
			}
			return;
		case 'ecdsa':
			if (
				parsedPrivateKey.algorithmOid !== OIDS.ecPublicKey ||
				parsedPrivateKey.parametersTag !== 0x06 ||
				parsedPrivateKey.parametersOid !== curveToOid(algorithm.curve)
			) {
				throw new Error('PKCS#8 private key algorithm does not match requested import algorithm');
			}
			return;
		case 'ed25519':
			if (
				parsedPrivateKey.algorithmOid !== OIDS.ed25519 ||
				parsedPrivateKey.parametersTag !== undefined
			) {
				throw new Error('PKCS#8 private key algorithm does not match requested import algorithm');
			}
			return;
		default: {
			const _exhaustive: never = algorithm;
			throw new Error(`Unhandled PrivateKeyImportInput kind: ${String(_exhaustive)}`);
		}
	}
}

function assertSec1MatchesRequestedAlgorithm(
	parsedSec1: {
		readonly parametersTag?: number;
		readonly parametersOid?: string;
	},
	algorithm: ImportEcKeyInput,
): void {
	if (parsedSec1.parametersTag === undefined) {
		// Parameters field absent: nothing encoded to cross-check, trust the caller.
		return;
	}
	if (
		parsedSec1.parametersTag !== 0x06 ||
		parsedSec1.parametersOid !== curveToOid(algorithm.curve)
	) {
		throw new Error('SEC 1 private key curve does not match requested import algorithm');
	}
}

function assertPublicJwkMatchesRequestedAlgorithm(
	jwk: JsonWebKey,
	algorithm: PublicKeyImportInput,
): void {
	if (
		jwk.k !== undefined ||
		jwk.d !== undefined ||
		jwk.p !== undefined ||
		jwk.q !== undefined ||
		jwk.dp !== undefined ||
		jwk.dq !== undefined ||
		jwk.qi !== undefined ||
		jwk.oth !== undefined
	) {
		throw new Error('Public JWK must not contain private key material');
	}
	switch (algorithm.kind) {
		case 'rsa':
			if (jwk.kty !== 'RSA' || typeof jwk.n !== 'string' || typeof jwk.e !== 'string') {
				throw new Error('Public JWK algorithm does not match requested import algorithm');
			}
			return;
		case 'ecdsa':
			if (
				jwk.kty !== 'EC' ||
				jwk.crv !== algorithm.curve ||
				typeof jwk.x !== 'string' ||
				typeof jwk.y !== 'string'
			) {
				throw new Error('Public JWK algorithm does not match requested import algorithm');
			}
			return;
		case 'ed25519':
			if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') {
				throw new Error('Public JWK algorithm does not match requested import algorithm');
			}
			return;
		default: {
			const _exhaustive: never = algorithm;
			throw new Error(`Unhandled PublicKeyImportInput kind: ${String(_exhaustive)}`);
		}
	}
}

function assertPrivateJwkMatchesRequestedAlgorithm(
	jwk: JsonWebKey,
	algorithm: PrivateKeyImportInput,
): void {
	if (jwk.k !== undefined || jwk.oth !== undefined) {
		throw new Error('Private JWK must not contain symmetric or multi-prime key material');
	}
	if (typeof jwk.d !== 'string') {
		throw new Error('Private JWK must contain private key material');
	}
	switch (algorithm.kind) {
		case 'rsa':
			if (
				jwk.kty !== 'RSA' ||
				typeof jwk.n !== 'string' ||
				typeof jwk.e !== 'string' ||
				typeof jwk.p !== 'string' ||
				typeof jwk.q !== 'string' ||
				typeof jwk.dp !== 'string' ||
				typeof jwk.dq !== 'string' ||
				typeof jwk.qi !== 'string'
			) {
				throw new Error('Private JWK algorithm does not match requested import algorithm');
			}
			return;
		case 'ecdsa':
			if (
				jwk.kty !== 'EC' ||
				jwk.crv !== algorithm.curve ||
				typeof jwk.x !== 'string' ||
				typeof jwk.y !== 'string'
			) {
				throw new Error('Private JWK algorithm does not match requested import algorithm');
			}
			return;
		case 'ed25519':
			if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') {
				throw new Error('Private JWK algorithm does not match requested import algorithm');
			}
			return;
		default: {
			const _exhaustive: never = algorithm;
			throw new Error(`Unhandled PrivateKeyImportInput kind: ${String(_exhaustive)}`);
		}
	}
}
