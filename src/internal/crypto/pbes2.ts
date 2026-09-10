/**
 * PBES2 password-based encryption and decryption (RFC 8018).
 *
 * Supports AES-CBC-128/192/256 with PBKDF2 using HMAC-SHA-1 or HMAC-SHA-256.
 * Used internally by encrypted PKCS#8 and PFX flows.
 *
 * @module
 */

import {
	decodeIntegerNumber,
	decodeObjectIdentifier,
	toArrayBuffer,
} from '#micro509/internal/asn1/asn1';
import {
	integerFromNumber,
	nullValue,
	objectIdentifier,
	octetString,
	readSequenceChildren,
	sequence,
} from '#micro509/internal/asn1/der';
import { OIDS } from '#micro509/internal/asn1/oids';
import { getCrypto } from '#micro509/internal/crypto/webcrypto';

/** Module-private brand so {@link isWrongPasswordError} cannot be fooled by look-alike errors. */
const wrongPasswordBrand = Symbol('micro509.WrongPasswordError');

/**
 * Thrown when PBES2 / AES-CBC decryption fails its integrity check, which in
 * practice means the supplied password was wrong (or the ciphertext was
 * corrupted). Lets callers distinguish a bad password from malformed input.
 */
export function wrongPasswordError(message: string): Error {
	return Object.assign(new Error(message), {
		name: 'WrongPasswordError',
		[wrongPasswordBrand]: true,
	});
}

/** Type guard: was decryption rejected for a wrong password / corrupt content? */
export function isWrongPasswordError(value: unknown): value is Error {
	return value instanceof Error && wrongPasswordBrand in value;
}

/** Upper bound on PBKDF2 iteration counts accepted from untrusted input. */
export const DEFAULT_MAX_KDF_ITERATIONS = 2_000_000;

/**
 * Upper bound on PKCS#12 KDF iteration counts accepted from untrusted input.
 * RFC 7292 Appendix B defines the KDF as a chain of single-block digests, so a
 * round costs a separate WebCrypto call and runs orders of magnitude slower
 * than a PBKDF2 round.
 */
export const DEFAULT_MAX_PKCS12_MAC_ITERATIONS = 100_000;

const kdfIterationLimitBrand = Symbol('micro509.KdfIterationLimitError');

/** Thrown before key derivation when an encoded iteration count exceeds the caller's limit. */
export function kdfIterationLimitError(iterations: number, remaining: number): Error {
	return Object.assign(
		new Error(`KDF iteration count ${iterations} exceeds the remaining budget of ${remaining}`),
		{ name: 'KdfIterationLimitError', [kdfIterationLimitBrand]: true },
	);
}

/** Type guard: was derivation refused because the iteration count exceeds the limit? */
export function isKdfIterationLimitError(value: unknown): value is Error {
	return value instanceof Error && kdfIterationLimitBrand in value;
}

/** Caller-supplied bound on password-based KDF work. */
export interface KdfLimitOptions {
	/**
	 * Maximum KDF iteration count accepted from the input. Higher counts fail
	 * before any derivation runs. Defaults to `2_000_000` for PBKDF2 and
	 * `100_000` for the PKCS#12 KDF, which costs far more per round.
	 */
	readonly maxKdfIterations?: number;
}

/**
 * KDF iterations one operation may still spend. A container decrypting many
 * entries shares a single budget, so entries that each sit under the ceiling
 * cannot sum past it.
 */
export interface KdfBudget {
	/** Iterations still available. */
	remaining: number;
}

/** Opens a budget from the caller's limit. Throws when that limit is not a positive integer. */
export function createKdfBudget(
	options: KdfLimitOptions | undefined,
	defaultLimit: number = DEFAULT_MAX_KDF_ITERATIONS,
): KdfBudget {
	const limit = options?.maxKdfIterations ?? defaultLimit;
	if (!Number.isSafeInteger(limit) || limit < 1) {
		throw new RangeError(`Invalid maxKdfIterations: must be an integer >= 1, got ${limit}`);
	}
	return { remaining: limit };
}

/** Charges iterations against the budget, throwing before any derivation runs. */
export function chargeKdfBudget(budget: KdfBudget, iterations: number): void {
	if (iterations > budget.remaining) {
		throw kdfIterationLimitError(iterations, budget.remaining);
	}
	budget.remaining -= iterations;
}

/** AES-CBC key sizes supported by this PBES2 implementation. */
export type Pbes2EncryptionScheme = 'AES-128-CBC' | 'AES-192-CBC' | 'AES-256-CBC';

/** PBKDF2 pseudo-random function choices. `HMAC-SHA-1` is the RFC default; `HMAC-SHA-256` is preferred. */
export type Pbes2Prf = 'HMAC-SHA-1' | 'HMAC-SHA-256';

/** Input for `encryptPbes2`. */
export interface Pbes2EncryptionOptions {
	/** Password fed to PBKDF2 for key derivation. */
	readonly password: string;
	/** PBKDF2 iteration count. Default: `100_000`. */
	readonly iterations?: number;
	/** PBKDF2 salt. Default: 16 cryptographically random bytes. */
	readonly salt?: Uint8Array;
	/** AES-CBC initialization vector. Default: 16 cryptographically random bytes. */
	readonly iv?: Uint8Array;
	/** AES-CBC cipher. Default: `'AES-256-CBC'`. */
	readonly cipher?: Pbes2EncryptionScheme;
	/** PBKDF2 PRF. Default: `'HMAC-SHA-256'`. */
	readonly prf?: Pbes2Prf;
}

/** Resolved PBES2 algorithm parameters, either parsed from DER or built by `encryptPbes2`. */
export interface Pbes2Parameters {
	/** PBKDF2 iteration count. */
	readonly iterations: number;
	/** PBKDF2 salt bytes. */
	readonly salt: Uint8Array;
	/** AES-CBC initialization vector. */
	readonly iv: Uint8Array;
	/** AES-CBC key-size variant. */
	readonly cipher: Pbes2EncryptionScheme;
	/** PBKDF2 pseudo-random function. */
	readonly prf: Pbes2Prf;
}

/** Output of `encryptPbes2`: ciphertext plus the DER-encoded AlgorithmIdentifier. */
export interface Pbes2EncryptionResult {
	/** DER-encoded PBES2 AlgorithmIdentifier SEQUENCE (embeds KDF + cipher params). */
	readonly algorithmIdentifierDer: Uint8Array;
	/** AES-CBC ciphertext (includes PKCS#7 padding). */
	readonly encryptedData: Uint8Array;
	/** Resolved algorithm parameters used during encryption. */
	readonly parameters: Pbes2Parameters;
}

/** Encrypts `data` using PBES2 (PBKDF2 + AES-CBC) and returns ciphertext with algorithm params. */
export async function encryptPbes2(
	data: Uint8Array,
	options: Pbes2EncryptionOptions,
): Promise<Pbes2EncryptionResult> {
	const iterations = options.iterations ?? 100_000;
	const salt = options.salt ?? getCrypto().getRandomValues(new Uint8Array(16));
	const iv = options.iv ?? getCrypto().getRandomValues(new Uint8Array(16));
	const encryption = options.cipher ?? 'AES-256-CBC';
	const prf = options.prf ?? 'HMAC-SHA-256';

	// Validate inputs before any WebCrypto calls
	if (!Number.isInteger(iterations) || iterations < 1) {
		throw new RangeError(`Invalid iterations: must be an integer >= 1, got ${iterations}`);
	}
	if (!(salt instanceof Uint8Array) || salt.length < 8) {
		throw new TypeError(
			`Invalid salt: must be Uint8Array with length >= 8, got length ${salt.length}`,
		);
	}
	if (!(iv instanceof Uint8Array) || iv.length !== 16) {
		throw new TypeError(
			`Invalid IV: must be Uint8Array of exactly 16 bytes, got length ${iv.length}`,
		);
	}

	const key = await deriveAesKey(options.password, salt, iterations, encryption, prf, ['encrypt']);
	const encryptedData = new Uint8Array(
		await getCrypto().subtle.encrypt(
			{ name: 'AES-CBC', iv: toArrayBuffer(iv) },
			key,
			toArrayBuffer(data),
		),
	);
	return {
		algorithmIdentifierDer: encodePbes2AlgorithmIdentifier({
			iterations,
			salt,
			iv,
			cipher: encryption,
			prf,
		}),
		encryptedData,
		parameters: { iterations, salt, iv, cipher: encryption, prf },
	};
}

/**
 * Decrypts PBES2 ciphertext given the DER AlgorithmIdentifier and password.
 * Throws on wrong password, and before derivation when the encoded iteration
 * count exceeds what `budget` still allows.
 */
export async function decryptPbes2(
	algorithmIdentifierDer: Uint8Array,
	encryptedData: Uint8Array,
	password: string,
	budget: KdfBudget = createKdfBudget(undefined),
): Promise<Uint8Array> {
	const parameters = parsePbes2AlgorithmIdentifier(algorithmIdentifierDer);
	chargeKdfBudget(budget, parameters.iterations);
	const key = await deriveAesKey(
		password,
		parameters.salt,
		parameters.iterations,
		parameters.cipher,
		parameters.prf,
		['decrypt'],
	);
	try {
		return new Uint8Array(
			await getCrypto().subtle.decrypt(
				{ name: 'AES-CBC', iv: toArrayBuffer(parameters.iv) },
				key,
				toArrayBuffer(encryptedData),
			),
		);
	} catch {
		throw wrongPasswordError('Invalid password or encrypted content');
	}
}

/** DER-encodes a PBES2 AlgorithmIdentifier SEQUENCE from resolved parameters. */
export function encodePbes2AlgorithmIdentifier(parameters: Pbes2Parameters): Uint8Array {
	const encryption = resolveEncryptionProfile(parameters.cipher);
	const prf = resolvePrfProfile(parameters.prf);
	const pbkdf2Params = [
		octetString(parameters.salt),
		integerFromNumber(parameters.iterations),
		// keyLength is OPTIONAL (kept); prf AlgorithmIdentifier DEFAULT
		// algid-hmacWithSHA1, which X.690 §11.5 forbids encoding.
		integerFromNumber(encryption.keyLengthBytes),
		...(parameters.prf === 'HMAC-SHA-1'
			? []
			: [sequence([objectIdentifier(prf.oid), nullValue()])]),
	];
	return sequence([
		objectIdentifier(OIDS.pbes2),
		sequence([
			sequence([objectIdentifier(OIDS.pbkdf2), sequence(pbkdf2Params)]),
			sequence([objectIdentifier(encryption.oid), octetString(parameters.iv)]),
		]),
	]);
}

/** Decodes a DER-encoded PBES2 AlgorithmIdentifier into structured {@linkcode Pbes2Parameters}. */
export function parsePbes2AlgorithmIdentifier(algorithmIdentifierDer: Uint8Array): Pbes2Parameters {
	const { paramsDer, kdf, scheme } = parsePbes2OuterFields(algorithmIdentifierDer);
	const { pbkdf2Der, pbkdf2Params } = parsePbes2KdfFields(paramsDer, kdf);
	// RFC 8018 A.2 PBKDF2-params: SEQUENCE { salt CHOICE { specified OCTET STRING,
	// otherSource AlgorithmIdentifier }, iterationCount INTEGER, keyLength INTEGER
	// OPTIONAL, prf AlgorithmIdentifier DEFAULT algid-hmacWithSHA1 }. Only the
	// `specified` salt alternative is accepted.
	const salt = pbkdf2Params[0];
	const iterations = pbkdf2Params[1];
	if (salt === undefined || iterations === undefined || salt.tag !== 0x04) {
		throw new Error('Malformed PBKDF2 params');
	}
	const keyLengthElement = pbkdf2Params[2];
	const hasExplicitKeyLength = keyLengthElement?.tag === 0x02;
	const prfElement = hasExplicitKeyLength ? pbkdf2Params[3] : keyLengthElement;
	const schemeDer = paramsDer.slice(scheme.start - scheme.headerLength, scheme.end);
	const schemeChildren = readSequenceChildren(schemeDer);
	const schemeOid = schemeChildren[0];
	const iv = schemeChildren[1];
	if (schemeOid === undefined || iv === undefined || iv.tag !== 0x04) {
		throw new Error('Malformed encryption scheme');
	}
	const encryption = encryptionSchemeFromOid(decodeObjectIdentifier(schemeOid.value));
	if (encryption === undefined) {
		throw new Error('Unsupported content encryption scheme');
	}
	if (keyLengthElement !== undefined && !hasExplicitKeyLength && keyLengthElement.tag !== 0x30) {
		throw new Error('Malformed PBKDF2 params');
	}
	if (
		hasExplicitKeyLength &&
		decodeIntegerNumber(keyLengthElement.value) !== encryption.keyLengthBytes
	) {
		throw new Error('Unsupported PBKDF2 key length');
	}
	const prf = parsePbkdf2Prf(pbkdf2Der, prfElement);

	// Validate parsed parameters before returning
	const iterationsValue = decodeIntegerNumber(iterations.value);
	const saltValue = new Uint8Array(salt.value);
	const ivValue = new Uint8Array(iv.value);

	if (iterationsValue < 1) {
		throw new Error(`Invalid PBES2 iterations: must be >= 1, got ${iterationsValue}`);
	}
	if (ivValue.length !== 16) {
		throw new Error(`Invalid PBES2 IV: must be exactly 16 bytes, got ${ivValue.length}`);
	}

	return {
		salt: saltValue,
		iterations: iterationsValue,
		iv: ivValue,
		cipher: encryption.name,
		prf,
	};
}

/** Extracts the KDF and encryption-scheme fields from a PBES2 AlgorithmIdentifier. */
function parsePbes2OuterFields(algorithmIdentifierDer: Uint8Array): {
	readonly paramsDer: Uint8Array;
	readonly kdf: ReturnType<typeof readSequenceChildren>[number];
	readonly scheme: ReturnType<typeof readSequenceChildren>[number];
} {
	const topLevel = readSequenceChildren(algorithmIdentifierDer);
	const oid = topLevel[0];
	const params = topLevel[1];
	if (oid === undefined || params === undefined) {
		throw new Error('Malformed PBES2 algorithm identifier');
	}
	if (decodeObjectIdentifier(oid.value) !== OIDS.pbes2) {
		throw new Error('Unsupported encryption algorithm');
	}
	const paramsDer = algorithmIdentifierDer.slice(params.start - params.headerLength, params.end);
	const pbes2Params = readSequenceChildren(paramsDer);
	const kdf = pbes2Params[0];
	const scheme = pbes2Params[1];
	if (kdf === undefined || scheme === undefined) {
		throw new Error('Malformed PBES2 params');
	}
	return { paramsDer, kdf, scheme };
}

function parsePbes2KdfFields(
	paramsDer: Uint8Array,
	kdf: ReturnType<typeof readSequenceChildren>[number],
): {
	readonly pbkdf2Der: Uint8Array;
	readonly pbkdf2Params: ReturnType<typeof readSequenceChildren>;
} {
	const kdfDer = paramsDer.slice(kdf.start - kdf.headerLength, kdf.end);
	const kdfChildren = readSequenceChildren(kdfDer);
	const kdfOid = kdfChildren[0];
	const kdfParams = kdfChildren[1];
	if (kdfOid === undefined || kdfParams === undefined) {
		throw new Error('Malformed KDF params');
	}
	if (decodeObjectIdentifier(kdfOid.value) !== OIDS.pbkdf2) {
		throw new Error('Unsupported KDF');
	}
	const pbkdf2Der = kdfDer.slice(kdfParams.start - kdfParams.headerLength, kdfParams.end);
	return { pbkdf2Der, pbkdf2Params: readSequenceChildren(pbkdf2Der) };
}

/** Derives an AES-CBC `CryptoKey` from a password via PBKDF2. */
async function deriveAesKey(
	password: string,
	salt: Uint8Array,
	iterations: number,
	encryptionName: Pbes2EncryptionScheme,
	prfName: Pbes2Prf,
	usages: KeyUsage[],
): Promise<CryptoKey> {
	const encryption = resolveEncryptionProfile(encryptionName);
	const prf = resolvePrfProfile(prfName);
	const passwordKey = await getCrypto().subtle.importKey(
		'raw',
		new TextEncoder().encode(password),
		'PBKDF2',
		false,
		['deriveKey'],
	);
	return getCrypto().subtle.deriveKey(
		{
			name: 'PBKDF2',
			salt: toArrayBuffer(salt),
			iterations,
			hash: prf.hash,
		},
		passwordKey,
		{ name: 'AES-CBC', length: encryption.keyLengthBits },
		false,
		usages,
	);
}

/** Parses the optional PRF AlgorithmIdentifier from PBKDF2 params. Absent means HMAC-SHA-1. */
function parsePbkdf2Prf(
	pbkdf2Der: Uint8Array,
	element: ReturnType<typeof readSequenceChildren>[number] | undefined,
): Pbes2Prf {
	if (element === undefined) {
		return 'HMAC-SHA-1';
	}
	if (element.tag !== 0x30) {
		throw new Error('Malformed PBKDF2 PRF');
	}
	const prfDer = readSequenceChildren(
		pbkdf2Der.slice(element.start - element.headerLength, element.end),
	);
	const oid = prfDer[0];
	if (oid === undefined) {
		throw new Error('Malformed PBKDF2 PRF');
	}
	const prf = prfFromOid(decodeObjectIdentifier(oid.value));
	if (prf === undefined) {
		throw new Error('Unsupported PBKDF2 PRF');
	}
	return prf;
}

/** Maps an AES-CBC OID to the encryption profile, or `undefined` if unsupported. */
function encryptionSchemeFromOid(oid: string):
	| {
			readonly name: Pbes2EncryptionScheme;
			readonly oid: string;
			readonly keyLengthBits: 128 | 192 | 256;
			readonly keyLengthBytes: 16 | 24 | 32;
	  }
	| undefined {
	switch (oid) {
		case OIDS.aes128Cbc:
			return { name: 'AES-128-CBC', oid, keyLengthBits: 128, keyLengthBytes: 16 };
		case OIDS.aes192Cbc:
			return { name: 'AES-192-CBC', oid, keyLengthBits: 192, keyLengthBytes: 24 };
		case OIDS.aes256Cbc:
			return { name: 'AES-256-CBC', oid, keyLengthBits: 256, keyLengthBytes: 32 };
	}
	return undefined;
}

/** Maps an HMAC OID to the PRF name, or `undefined` if unsupported. */
function prfFromOid(oid: string): Pbes2Prf | undefined {
	switch (oid) {
		case OIDS.hmacWithSHA1:
			return 'HMAC-SHA-1';
		case OIDS.hmacWithSHA256:
			return 'HMAC-SHA-256';
	}
	return undefined;
}

/** Looks up the full encryption profile for a scheme name. Throws if unsupported. */
function resolveEncryptionProfile(name: Pbes2EncryptionScheme): {
	readonly name: Pbes2EncryptionScheme;
	readonly oid: string;
	readonly keyLengthBits: 128 | 192 | 256;
	readonly keyLengthBytes: 16 | 24 | 32;
} {
	const profile = encryptionSchemeFromOid(
		name === 'AES-128-CBC'
			? OIDS.aes128Cbc
			: name === 'AES-192-CBC'
				? OIDS.aes192Cbc
				: OIDS.aes256Cbc,
	);
	if (profile === undefined) {
		throw new Error('Unsupported content encryption scheme');
	}
	return profile;
}

/** Looks up OID and WebCrypto hash name for a PRF. */
function resolvePrfProfile(name: Pbes2Prf): {
	readonly oid: string;
	readonly hash: 'SHA-1' | 'SHA-256';
} {
	switch (name) {
		case 'HMAC-SHA-1':
			return { oid: OIDS.hmacWithSHA1, hash: 'SHA-1' };
		case 'HMAC-SHA-256':
			return { oid: OIDS.hmacWithSHA256, hash: 'SHA-256' };
		default: {
			const _exhaustive: never = name;
			throw new Error(`Unhandled Pbes2Prf: ${String(_exhaustive)}`);
		}
	}
}
