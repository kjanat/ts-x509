/**
 * PKCS#12 MAC data creation and verification.
 *
 * Computes and verifies the password-based HMAC-SHA-256 integrity check
 * defined in PKCS#12 (RFC 7292), using the PKCS#12 key-derivation scheme.
 *
 * @module
 */

import {
	decodeNonNegativeIntegerNumber,
	decodeObjectIdentifier,
	toArrayBuffer,
	toHex,
} from '#micro509/internal/asn1/asn1';
import {
	concatBytes,
	integerFromNumber,
	nullValue,
	objectIdentifier,
	octetString,
	readSequenceChildren,
	sequence,
} from '#micro509/internal/asn1/der';
import { OIDS } from '#micro509/internal/asn1/oids';
import { describeHashAlgorithm } from '#micro509/internal/crypto/algorithm-names';
import {
	chargeKdfBudget,
	createKdfBudget,
	DEFAULT_MAX_PKCS12_MAC_ITERATIONS,
	isKdfIterationLimitError,
	type KdfLimitOptions,
} from '#micro509/internal/crypto/pbes2';
import { getCrypto } from '#micro509/internal/crypto/webcrypto';
import type { ErrorResult, Micro509Error } from '#micro509/result/result';
import { failureResult, rethrowIfInvariant, successResult } from '#micro509/result/result';

/** Input for {@linkcode createPkcs12MacData}. */
export interface Pkcs12MacOptions {
	/** Password used to derive the HMAC key via the PKCS#12 KDF. */
	readonly password: string;
	/** PKCS#12 KDF iteration count. Default: `2048`. */
	readonly iterations?: number;
	/** Random salt. Default: 16 cryptographically random bytes. */
	readonly salt?: Uint8Array;
}

/** Decoded PKCS#12 MacData block returned by {@linkcode parsePkcs12MacData}. */
export interface ParsedPkcs12MacData {
	/** OID of the digest algorithm (currently always SHA-256). */
	readonly digestAlgorithmOid: string;
	/** Human-readable digest algorithm name (currently `"SHA-256"`). */
	readonly digestAlgorithmName: string;
	/** Hex-encoded MAC digest value. */
	readonly digestHex: string;
	/** Hex-encoded salt bytes used during key derivation. */
	readonly saltHex: string;
	/** Number of PKCS#12 KDF iterations. */
	readonly iterations: number;
	/**
	 * MAC verification outcome: `'unchecked'` when no password was supplied
	 * during parsing, otherwise `'valid'` or `'invalid'`.
	 */
	readonly verification: 'valid' | 'invalid' | 'unchecked';
}

/**
 * Computes a PKCS#12 HMAC-SHA-256 MAC over the AuthenticatedSafe and returns
 * the DER-encoded MacData block alongside its parsed representation.
 */
export async function createPkcs12MacData(
	authenticatedSafe: Uint8Array,
	options: Pkcs12MacOptions,
): Promise<{
	/** DER-encoded MacData SEQUENCE. */
	readonly der: Uint8Array;
	/** Structured representation of the MAC parameters and digest. */
	readonly parsed: ParsedPkcs12MacData;
}> {
	const iterations = options.iterations ?? 2048;
	assertPkcs12MacIterations(iterations);
	const salt = options.salt ?? getCrypto().getRandomValues(new Uint8Array(16));
	const mac = await computePkcs12Mac(authenticatedSafe, options.password, salt, iterations);
	const der = sequence([
		sequence([sequence([objectIdentifier(OIDS.sha256), nullValue()]), octetString(mac)]),
		octetString(salt),
		// iterations INTEGER DEFAULT 1 — X.690 §11.5 forbids encoding the default.
		...(iterations === 1 ? [] : [integerFromNumber(iterations)]),
	]);
	return {
		der,
		parsed: {
			digestAlgorithmOid: OIDS.sha256,
			digestAlgorithmName: describeHashAlgorithm(OIDS.sha256),
			digestHex: toHex(mac),
			saltHex: toHex(salt),
			iterations,
			verification: 'valid',
		},
	};
}

/** Machine-readable failure reason for {@linkcode parsePkcs12MacData}. */
export type ParsePkcs12MacDataErrorCode = 'malformed' | 'kdf_iterations_exceeded';

/** Options for {@linkcode parsePkcs12MacData} and {@linkcode parsePkcs12MacDataOrThrow}. */
export type ParsePkcs12MacDataOptions = KdfLimitOptions;

/** Structured failure payload for MacData parsing. */
export interface ParsePkcs12MacDataFailure extends Micro509Error<ParsePkcs12MacDataErrorCode> {
	/** Always `false` for failures. */
	readonly ok: false;
}

/** Success-or-failure result from {@linkcode parsePkcs12MacData}. */
export type ParsePkcs12MacDataResult =
	| { readonly ok: true; readonly value: ParsedPkcs12MacData }
	| ErrorResult<ParsePkcs12MacDataErrorCode, Record<never, never>, ParsePkcs12MacDataFailure>;

/**
 * Throwing core for {@linkcode parsePkcs12MacData}. When `password` is
 * provided, verifies the MAC and reports the outcome in `verification`.
 * Throws before deriving when the iteration count exceeds
 * `options.maxKdfIterations`.
 */
export async function parsePkcs12MacDataOrThrow(
	der: Uint8Array,
	authenticatedSafe: Uint8Array,
	password?: string,
	options?: ParsePkcs12MacDataOptions,
): Promise<ParsedPkcs12MacData> {
	const top = readSequenceChildren(der);
	const digestInfo = top[0];
	const salt = top[1];
	const iterations = top[2];
	if (
		(top.length !== 2 && top.length !== 3) ||
		digestInfo === undefined ||
		salt === undefined ||
		salt.tag !== 0x04 ||
		(iterations !== undefined && iterations.tag !== 0x02)
	) {
		throw new Error('Malformed MacData');
	}
	const digestInfoDer = der.slice(digestInfo.start - digestInfo.headerLength, digestInfo.end);
	const digestInfoChildren = readSequenceChildren(digestInfoDer);
	const algorithm = digestInfoChildren[0];
	const digest = digestInfoChildren[1];
	if (
		digestInfoChildren.length !== 2 ||
		algorithm === undefined ||
		digest === undefined ||
		digest.tag !== 0x04
	) {
		throw new Error('Malformed DigestInfo');
	}
	const algorithmDer = digestInfoDer.slice(algorithm.start - algorithm.headerLength, algorithm.end);
	const algorithmChildren = readSequenceChildren(algorithmDer);
	const algorithmOid = algorithmChildren[0];
	if (
		algorithmOid === undefined ||
		(algorithmChildren.length !== 1 && algorithmChildren.length !== 2)
	) {
		throw new Error('MacData algorithm missing');
	}
	const digestAlgorithmOid = decodeObjectIdentifier(algorithmOid.value);
	if (digestAlgorithmOid !== OIDS.sha256) {
		throw new Error('Only SHA-256 PKCS#12 MAC is supported');
	}
	const parsedIterations =
		iterations === undefined
			? 1
			: decodeNonNegativeIntegerNumber(iterations.value, 'MacData iterations');
	assertPkcs12MacIterations(parsedIterations);
	if (password === undefined) {
		return {
			digestAlgorithmOid,
			digestAlgorithmName: describeHashAlgorithm(digestAlgorithmOid),
			digestHex: toHex(digest.value),
			saltHex: toHex(salt.value),
			iterations: parsedIterations,
			verification: 'unchecked',
		};
	}
	chargeKdfBudget(createKdfBudget(options, DEFAULT_MAX_PKCS12_MAC_ITERATIONS), parsedIterations);
	const expected = await computePkcs12Mac(
		authenticatedSafe,
		password,
		salt.value,
		parsedIterations,
	);
	return {
		digestAlgorithmOid,
		digestAlgorithmName: describeHashAlgorithm(digestAlgorithmOid),
		digestHex: toHex(digest.value),
		saltHex: toHex(salt.value),
		iterations: parsedIterations,
		verification: equalBytes(expected, digest.value) ? 'valid' : 'invalid',
	};
}

/**
 * Decodes a DER-encoded MacData block. When `password` is provided, verifies
 * the MAC and reports the outcome in `verification`.
 *
 * Returns a typed failure (`code: 'malformed'`) on malformed input and
 * `code: 'kdf_iterations_exceeded'` when the iteration count exceeds
 * `options.maxKdfIterations`. For the throwing form use
 * {@linkcode parsePkcs12MacDataOrThrow}.
 */
export async function parsePkcs12MacData(
	der: Uint8Array,
	authenticatedSafe: Uint8Array,
	password?: string,
	options?: ParsePkcs12MacDataOptions,
): Promise<ParsePkcs12MacDataResult> {
	try {
		return successResult(
			await parsePkcs12MacDataOrThrow(der, authenticatedSafe, password, options),
		);
	} catch (error) {
		rethrowIfInvariant(error);
		if (isKdfIterationLimitError(error)) {
			return failureResult('kdf_iterations_exceeded', error.message);
		}
		return failureResult('malformed', error instanceof Error ? error.message : 'Malformed MacData');
	}
}

function assertPkcs12MacIterations(iterations: number): void {
	if (!Number.isSafeInteger(iterations) || iterations <= 0) {
		throw new Error('MacData iterations must be a positive safe integer');
	}
}

/** Derives an HMAC-SHA-256 key via the PKCS#12 KDF and signs the AuthenticatedSafe. */
async function computePkcs12Mac(
	authenticatedSafe: Uint8Array,
	password: string,
	salt: Uint8Array,
	iterations: number,
): Promise<Uint8Array> {
	const keyBytes = await derivePkcs12Key(password, salt, iterations, 3, 32);
	const key = await getCrypto().subtle.importKey(
		'raw',
		toArrayBuffer(keyBytes),
		{ name: 'HMAC', hash: 'SHA-256' },
		false,
		['sign'],
	);
	return new Uint8Array(
		await getCrypto().subtle.sign('HMAC', key, toArrayBuffer(authenticatedSafe)),
	);
}

/** PKCS#12 key derivation (RFC 7292 Appendix B). `id` selects the purpose (3 = MAC key). */
async function derivePkcs12Key(
	password: string,
	salt: Uint8Array,
	iterations: number,
	id: number,
	length: number,
): Promise<Uint8Array> {
	const u = 32;
	const v = 64;
	const D = new Uint8Array(v).fill(id);
	const passwordBytes = encodePkcs12Password(password);
	const S = repeatToMultiple(salt, v);
	const P = repeatToMultiple(passwordBytes, v);
	let I = concatBytes([S, P]);
	const blocks = Math.ceil(length / u);
	const output = new Uint8Array(blocks * u);
	for (let index = 0; index < blocks; index += 1) {
		let A = await digestSha256(concatBytes([D, I]));
		for (let round = 1; round < iterations; round += 1) {
			A = await digestSha256(A);
		}
		output.set(A, index * u);
		if (I.length === 0) {
			continue;
		}
		const B = repeatToLength(A, v);
		const next = new Uint8Array(I.length);
		for (let blockIndex = 0; blockIndex < I.length / v; blockIndex += 1) {
			const block = I.slice(blockIndex * v, blockIndex * v + v);
			addBlockInPlace(block, B);
			next.set(block, blockIndex * v);
		}
		I = next;
	}
	return output.slice(0, length);
}

/** SHA-256 hash via WebCrypto. */
async function digestSha256(bytes: Uint8Array): Promise<Uint8Array> {
	return new Uint8Array(await getCrypto().subtle.digest('SHA-256', toArrayBuffer(bytes)));
}

/** Encodes a password as a null-terminated UCS-2 big-endian byte array (RFC 7292 B.1). */
function encodePkcs12Password(password: string): Uint8Array {
	const out = new Uint8Array((password.length + 1) * 2);
	for (let index = 0; index < password.length; index += 1) {
		const code = password.charCodeAt(index);
		out[index * 2] = code >> 8;
		out[index * 2 + 1] = code & 0xff;
	}
	return out;
}

/** Repeats `bytes` to the nearest multiple of `size`. */
function repeatToMultiple(bytes: Uint8Array, size: number): Uint8Array {
	if (bytes.length === 0) {
		return new Uint8Array();
	}
	return repeatToLength(bytes, size * Math.ceil(bytes.length / size));
}

/** Cyclically repeats `bytes` to fill exactly `length` bytes. */
function repeatToLength(bytes: Uint8Array, length: number): Uint8Array {
	const out = new Uint8Array(length);
	for (let index = 0; index < length; index += 1) {
		out[index] = bytes[index % bytes.length] ?? 0;
	}
	return out;
}

/** Big-endian add-with-carry of `addend` into `block`, modifying `block` in place. */
function addBlockInPlace(block: Uint8Array, addend: Uint8Array): void {
	let carry = 1;
	for (let index = block.length - 1; index >= 0; index -= 1) {
		const sum = (block[index] ?? 0) + (addend[index] ?? 0) + carry;
		block[index] = sum & 0xff;
		carry = sum >> 8;
	}
}

/** Constant-time byte comparison to avoid timing side-channels in MAC checks. */
function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
	if (left.length !== right.length) {
		return false;
	}
	let result = 0;
	for (let index = 0; index < left.length; index += 1) {
		result |= (left[index] ?? 0) ^ (right[index] ?? 0);
	}
	return result === 0;
}
