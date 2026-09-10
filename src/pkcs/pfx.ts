/**
 * PKCS#12/PFX container creation and parsing.
 *
 * Builds and decodes PFX archives containing certificate bags, private-key bags,
 * optional PBES2 encryption, and PKCS#12 MAC integrity verification.
 *
 * @module
 */

import {
	childrenOf,
	decodeIntegerNumber,
	decodeObjectIdentifier,
	toHex,
} from '#micro509/internal/asn1/asn1';
import type { DerElement } from '#micro509/internal/asn1/der';
import {
	DEFAULT_MAX_DER_DEPTH,
	explicitContext,
	integerFromNumber,
	objectIdentifier,
	octetString,
	readElement,
	readSequenceChildren,
	sequence,
	setOf,
	tlv,
} from '#micro509/internal/asn1/der';
import { OIDS } from '#micro509/internal/asn1/oids';
import {
	createKdfBudget,
	decryptPbes2,
	encryptPbes2,
	isKdfIterationLimitError,
	isWrongPasswordError,
	type KdfBudget,
	type KdfLimitOptions,
} from '#micro509/internal/crypto/pbes2';
import { base64Encode } from '#micro509/internal/shared/base64';
import type { EncryptedPkcs8Options } from '#micro509/keys/keys';
import { exportPkcs8Der } from '#micro509/keys/keys';
import { pemEncode, splitPemBlocksOrThrow } from '#micro509/pem/pem';
import type { ParsedPkcs12MacData, Pkcs12MacOptions } from '#micro509/pkcs/pkcs12-mac';
import { createPkcs12MacData, parsePkcs12MacData } from '#micro509/pkcs/pkcs12-mac';
import type { ErrorResult, Micro509Error } from '#micro509/result/result';
import { failureResult, rethrowIfInvariant } from '#micro509/result/result';
import type { ParsedCertificate } from '#micro509/x509/parse';
import { parseCertificateDerOrThrow } from '#micro509/x509/parse';

export type * from '#micro509/pkcs/pkcs12-mac';

/** PEM string or DER bytes for a certificate to include in a PFX bag. */
export type PfxCertificateSource = string | Uint8Array | ParsedCertificate;
/** A WebCrypto private key or raw PKCS#8 DER bytes for a PFX key bag. */
export type PfxPrivateKeySource = CryptoKey | Uint8Array;

/** Optional metadata attached to a certificate or key bag inside a PFX. */
export interface PfxBagAttributesInput {
	/** Human-readable label stored as a BMPString attribute. */
	readonly friendlyName?: string;
	/** Opaque identifier linking a certificate bag to its corresponding key bag. */
	readonly localKeyId?: Uint8Array;
}

/** A certificate to embed in a PFX container. Input for {@linkcode createPfx}. */
export interface PfxCertificateBagInput {
	/** Certificate as PEM text or DER bytes. */
	readonly certificate: PfxCertificateSource;
	/** Optional bag-level attributes (friendly name, local key ID). */
	readonly attributes?: PfxBagAttributesInput;
}

/** A private key to embed in a PFX container. Input for {@linkcode createPfx}. */
export interface PfxPrivateKeyBagInput {
	/** Private key as a WebCrypto `CryptoKey` or raw PKCS#8 DER bytes. */
	readonly privateKey: PfxPrivateKeySource;
	/** Optional bag-level attributes (friendly name, local key ID). */
	readonly attributes?: PfxBagAttributesInput;
}

/** Input for {@linkcode createPfx}. */
export interface CreatePfxInput {
	/** Certificates to include as certBag entries. */
	readonly certificates?: readonly PfxCertificateBagInput[];
	/** Private keys to include as keyBag entries. */
	readonly privateKeys?: readonly PfxPrivateKeyBagInput[];
	/** PBES2 encryption settings for the key-bag ContentInfo. Omit for unencrypted. */
	readonly encryption?: PfxEncryptionOptions;
	/** PKCS#12 MAC integrity settings. Omit to skip MAC generation. */
	readonly mac?: Pkcs12MacOptions;
}

/** PBES2 encryption settings for PFX key-bag protection. Alias of {@linkcode EncryptedPkcs8Options}. */
export type PfxEncryptionOptions = EncryptedPkcs8Options;

export type { KdfLimitOptions } from '#micro509/internal/crypto/pbes2';

/** Options for {@linkcode parsePfxDer} and {@linkcode parsePfxPem}. */
export interface ParsePfxOptions extends KdfLimitOptions {
	/** Password used to decrypt PBES2-encrypted ContentInfo entries. Also used for MAC verification when `macPassword` is omitted. */
	readonly password?: string;
	/** Separate password for MAC verification. Falls back to `password` when omitted. */
	readonly macPassword?: string;
}

/** DER, PEM, and base64 encodings of a PFX container produced by {@linkcode createPfx}. */
export interface PfxMaterial {
	/** Raw DER-encoded PFX bytes. */
	readonly der: Uint8Array;
	/** PEM-armored PFX (`-----BEGIN PKCS12-----`). */
	readonly pem: string;
	/** Base64-encoded DER (no PEM armor). */
	readonly base64: string;
}

/** A single PKCS#12 bag attribute as decoded by {@linkcode parsePfxDer}. */
export interface ParsedPfxAttribute {
	/** Dotted-decimal OID identifying this attribute type. */
	readonly oid: string;
	/** Hex-encoded DER of each attribute value. */
	readonly valuesHex: readonly string[];
}

/** Decoded bag attributes for a single SafeBag inside a PFX. */
export interface ParsedPfxBagAttributes {
	/** All raw attributes as OID + hex-encoded values. */
	readonly entries: readonly ParsedPfxAttribute[];
	/** Decoded BMPString friendly-name attribute, if present. */
	readonly friendlyName?: string;
	/** Hex-encoded localKeyId attribute, if present. */
	readonly localKeyId?: string;
}

/**
 * Discriminated union of SafeBag types decoded from a PFX container.
 *
 * Use `kind` to narrow: `'certificate'` | `'privateKey'` | `'unknown'`.
 */
export type ParsedPfxBag =
	| {
			/** Bag contains an X.509 certificate. */
			readonly kind: 'certificate';
			/** Dotted-decimal OID of the bag type. */
			readonly bagId: string;
			/** Decoded bag-level attributes. */
			readonly attributes: ParsedPfxBagAttributes;
			/** Parsed certificate from the certBag. */
			readonly certificate: ParsedCertificate;
	  }
	| {
			/** Bag contains a PKCS#8 private key. */
			readonly kind: 'privateKey';
			/** Dotted-decimal OID of the bag type. */
			readonly bagId: string;
			/** Decoded bag-level attributes. */
			readonly attributes: ParsedPfxBagAttributes;
			/** Raw DER-encoded PKCS#8 PrivateKeyInfo. */
			readonly pkcs8Der: Uint8Array;
	  }
	| {
			/** Bag type not recognized by this library. */
			readonly kind: 'unknown';
			/** Dotted-decimal OID of the bag type. */
			readonly bagId: string;
			/** Decoded bag-level attributes. */
			readonly attributes: ParsedPfxBagAttributes;
			/** Raw DER of the unrecognized bag value. */
			readonly valueDer: Uint8Array;
	  };

/** Fully decoded PFX container returned by {@linkcode parsePfxDer} / {@linkcode parsePfxPem}. */
export interface ParsedPfx {
	/** All SafeBags in the PFX, including unknown types. */
	readonly bags: readonly ParsedPfxBag[];
	/** Convenience: only the parsed certificates extracted from certBag entries. */
	readonly certificates: readonly ParsedCertificate[];
	/** Convenience: raw PKCS#8 DER of each private key extracted from keyBag entries. */
	readonly privateKeys: readonly Uint8Array[];
	/** MAC verification metadata, present when the PFX includes a MacData block. */
	readonly macData?: ParsedPkcs12MacData;
}

// Result types for PFX parsing

/** Error codes returned by {@linkcode parsePfxDer} and {@linkcode parsePfxPem}. */
export type ParsePfxErrorCode =
	| 'malformed'
	| 'invalid_password'
	| 'password_required'
	| 'kdf_iterations_exceeded';

/** Error payload for a failed PFX parse. */
export interface ParsePfxFailure extends Micro509Error<ParsePfxErrorCode> {
	/** Always `false` for failures. */
	readonly ok: false;
}

/** Success-or-failure result from {@linkcode parsePfxDer} / {@linkcode parsePfxPem}. */
export type ParsePfxResult =
	| {
			/** Parse succeeded. */
			readonly ok: true;
			/** Decoded PFX container. */
			readonly value: ParsedPfx;
	  }
	| ErrorResult<ParsePfxErrorCode, Record<never, never>, ParsePfxFailure>;

// Result types for PFX creation

/**
 * Caller-correctable failure code from {@linkcode createPfx}.
 *
 * The only parse boundary in creation is the certificate source: it is
 * normalized from untrusted PEM/DER. Private keys are either a WebCrypto
 * `CryptoKey` (platform errors stay throws) or raw PKCS#8 bytes passed through
 * unvalidated, so there is no distinct `invalid_private_key` failure to model.
 */
export type CreatePfxErrorCode = 'invalid_certificate';

/** Error payload for a failed PFX creation. */
export interface CreatePfxFailure extends Micro509Error<CreatePfxErrorCode> {
	/** Always `false` for failures. */
	readonly ok: false;
}

/** Success-or-failure result from {@linkcode createPfx}. */
export type CreatePfxResult =
	| {
			/** Creation succeeded. */
			readonly ok: true;
			/** DER, PEM, and base64 forms of the PFX container. */
			readonly value: PfxMaterial;
	  }
	| ErrorResult<CreatePfxErrorCode, Record<never, never>, CreatePfxFailure>;

// createPfx

/**
 * Builds a PKCS#12/PFX archive containing certificates and/or private keys.
 *
 * When `encryption` is provided, the key-bag ContentInfo is PBES2-encrypted.
 * When `mac` is provided, a PKCS#12 MAC integrity block is appended.
 *
 * Returns a {@linkcode CreatePfxResult}: the container material on success, or a
 * typed `invalid_certificate` failure when a certificate source is not a single
 * PEM/DER certificate.
 *
 * @example
 * ```ts
 * import { createPfx, unwrap } from 'micro509';
 *
 * const result = await createPfx({
 *   certificates: [{ certificate: certPem }],
 *   privateKeys: [{ privateKey: keyPair.privateKey }],
 *   encryption: { password: 's3cret' },
 *   mac: { password: 's3cret' },
 * });
 * if (result.ok) {
 *   const pfx = result.value; // pfx.der, pfx.pem, pfx.base64
 * }
 * // or, when inputs are already validated: const pfx = unwrap(result);
 * ```
 */
export async function createPfx(input: CreatePfxInput): Promise<CreatePfxResult> {
	const certificateBags: Uint8Array[] = [];
	const privateKeyBags: Uint8Array[] = [];
	for (const certificate of input.certificates ?? []) {
		// normalizeCertificate parses untrusted PEM/DER and throws on malformed
		// input — a caller-correctable trust boundary, so map it to a typed failure.
		let certificateDer: Uint8Array;
		try {
			certificateDer = normalizeCertificate(certificate.certificate);
		} catch {
			return pfxCreationFailure(
				'invalid_certificate',
				'Each PFX certificate source must be a single PEM or DER certificate',
			);
		}
		certificateBags.push(createCertificateBag(certificateDer, certificate.attributes));
	}
	for (const privateKey of input.privateKeys ?? []) {
		privateKeyBags.push(
			createPrivateKeyBag(await normalizePrivateKey(privateKey.privateKey), privateKey.attributes),
		);
	}
	const contentInfos: Uint8Array[] = [];
	if (certificateBags.length > 0) {
		contentInfos.push(createDataContentInfo(sequence(certificateBags)));
	}
	if (privateKeyBags.length > 0) {
		const safeContents = sequence(privateKeyBags);
		contentInfos.push(
			input.encryption === undefined
				? createDataContentInfo(safeContents)
				: await createEncryptedDataContentInfo(safeContents, input.encryption),
		);
	}
	const authenticatedSafe = sequence(contentInfos);
	const macData =
		input.mac === undefined ? undefined : await createPkcs12MacData(authenticatedSafe, input.mac);
	const der = sequence([
		integerFromNumber(3),
		createDataContentInfo(authenticatedSafe),
		...(macData === undefined ? [] : [macData.der]),
	]);
	return {
		ok: true,
		value: {
			der,
			pem: pemEncode('PKCS12', der),
			base64: base64Encode(der),
		},
	};
}

/** Shorthand for constructing a PFX creation failure result. */
function pfxCreationFailure(
	code: CreatePfxErrorCode,
	message: string,
): ErrorResult<CreatePfxErrorCode, Record<never, never>, CreatePfxFailure> {
	return failureResult(code, message);
}

// parsePfxDer / parsePfxPem — Result-returning

/**
 * Decodes a DER-encoded PKCS#12/PFX container into its constituent bags.
 *
 * Returns a result union — check `ok` before accessing `value`.
 * Encrypted containers require `options.password`. MAC verification uses
 * `options.macPassword` (falls back to `options.password`).
 *
 * @example
 * ```ts
 * import { parsePfxDer } from 'micro509';
 *
 * const result = await parsePfxDer(pfxBytes, { password: 's3cret' });
 * if (result.ok) {
 *   console.log(result.value.certificates.length);
 * }
 * ```
 */
export async function parsePfxDer(
	der: Uint8Array,
	options?: ParsePfxOptions,
): Promise<ParsePfxResult> {
	try {
		const topLevel = readSequenceChildren(der, { maxDepth: DEFAULT_MAX_DER_DEPTH });
		if (topLevel.length < 2 || topLevel.length > 3) {
			return pfxFailure('malformed', 'Malformed PFX structure');
		}
		const version = topLevel[0];
		const authSafe = topLevel[1];
		if (version === undefined || authSafe === undefined || version.tag !== 0x02) {
			return pfxFailure('malformed', 'Malformed PFX structure');
		}
		if (decodeIntegerNumber(version.value) !== 3) {
			return pfxFailure('malformed', 'Unsupported PFX version');
		}
		const authSafeDer = der.slice(authSafe.start - authSafe.headerLength, authSafe.end);
		const authenticatedSafeOctets = extractContentInfoData(authSafeDer);
		const macElement = topLevel[2];
		let macData: ParsedPkcs12MacData | undefined;
		if (macElement !== undefined) {
			const macResult = await verifyPfxMacData(
				der.slice(macElement.start - macElement.headerLength, macElement.end),
				authenticatedSafeOctets,
				options,
			);
			if (macResult.error !== undefined) {
				return macResult.error;
			}
			macData = macResult.macData;
		}
		const authenticatedSafe = readSequenceChildren(authenticatedSafeOctets);
		const bags: ParsedPfxBag[] = [];
		// One budget for the whole file: entries that each sit under the ceiling
		// must not be able to sum past it.
		const budget = createKdfBudget(options);
		for (const contentInfo of authenticatedSafe) {
			const contentInfoDer = authenticatedSafeOctets.slice(
				contentInfo.start - contentInfo.headerLength,
				contentInfo.end,
			);
			const safeContentsResult = await extractSafeContents(contentInfoDer, options, budget);
			if (safeContentsResult.error !== undefined) {
				return safeContentsResult.error;
			}
			const safeContents = safeContentsResult.data;
			for (const bag of readSequenceChildren(safeContents)) {
				const bagDer = safeContents.slice(bag.start - bag.headerLength, bag.end);
				bags.push(parseSafeBag(bagDer));
			}
		}
		return {
			ok: true,
			value: {
				bags,
				certificates: bags.flatMap((bag) => (bag.kind === 'certificate' ? [bag.certificate] : [])),
				privateKeys: bags.flatMap((bag) => (bag.kind === 'privateKey' ? [bag.pkcs8Der] : [])),
				...(macData === undefined ? {} : { macData }),
			},
		};
	} catch (error) {
		rethrowIfInvariant(error);
		return pfxFailure('malformed', 'Malformed PFX structure');
	}
}

/**
 * Decodes a PEM-armored PKCS#12/PFX container. Expects exactly one `PKCS12` block.
 *
 * Delegates to {@linkcode parsePfxDer} after PEM decoding.
 *
 * @example
 * ```ts
 * import { parsePfxPem } from 'micro509';
 *
 * const result = await parsePfxPem(pfxPemString, { password: 's3cret' });
 * if (result.ok) {
 *   console.log(result.value.privateKeys.length);
 * }
 * ```
 */
export function parsePfxPem(pem: string, options?: ParsePfxOptions): Promise<ParsePfxResult> {
	let bytes: Uint8Array;
	try {
		const blocks = splitPemBlocksOrThrow(pem).filter((block) => block.label === 'PKCS12');
		const block = blocks[0];
		if (block === undefined || blocks.length !== 1) {
			return Promise.resolve(pfxFailure('malformed', 'Expected exactly one PKCS12 PEM block'));
		}
		bytes = block.bytes;
	} catch {
		return Promise.resolve(pfxFailure('malformed', 'Expected exactly one PKCS12 PEM block'));
	}
	return parsePfxDer(bytes, options);
}

// Private: PFX helpers

/** Shorthand for constructing a PFX parse failure result. */
function pfxFailure(
	code: ParsePfxErrorCode,
	message: string,
): ErrorResult<ParsePfxErrorCode, Record<never, never>, ParsePfxFailure> {
	return failureResult(code, message);
}

/** Unwraps a `data` ContentInfo to its inner OCTET STRING payload. */
function extractContentInfoData(contentInfoDer: Uint8Array): Uint8Array {
	const contentInfoChildren = readSequenceChildren(contentInfoDer);
	const contentType = contentInfoChildren[0];
	const content = contentInfoChildren[1];
	if (
		contentType === undefined ||
		content === undefined ||
		contentInfoChildren.length !== 2 ||
		contentType.tag !== 0x06
	) {
		throw new Error('Malformed ContentInfo');
	}
	if (decodeObjectIdentifier(contentType.value) !== OIDS.pkcs7Data) {
		throw new Error('Only passwordless data ContentInfo is supported');
	}
	return extractContextOctetString(contentInfoDer, content);
}

/** Extracts SafeContents bytes from a ContentInfo, decrypting if EncryptedData. */
async function extractSafeContents(
	contentInfoDer: Uint8Array,
	options: ParsePfxOptions | undefined,
	budget: KdfBudget,
): Promise<
	| {
			readonly data: Uint8Array;
			readonly error?: undefined;
	  }
	| {
			readonly data?: undefined;
			readonly error: ErrorResult<ParsePfxErrorCode, Record<never, never>, ParsePfxFailure>;
	  }
> {
	const contentInfoChildren = readSequenceChildren(contentInfoDer);
	const contentType = contentInfoChildren[0];
	const content = contentInfoChildren[1];
	if (
		contentType === undefined ||
		content === undefined ||
		contentInfoChildren.length !== 2 ||
		contentType.tag !== 0x06
	) {
		return { error: pfxFailure('malformed', 'Malformed ContentInfo') };
	}
	const oid = decodeObjectIdentifier(contentType.value);
	if (oid === OIDS.pkcs7Data) {
		return { data: extractContextOctetString(contentInfoDer, content) };
	}
	if (oid !== OIDS.pkcs7EncryptedData) {
		return {
			error: pfxFailure('malformed', 'Unsupported PFX ContentInfo type'),
		};
	}
	if (options?.password === undefined) {
		return {
			error: pfxFailure('password_required', 'Password required for encrypted PFX content'),
		};
	}
	const encryptedData = extractContextChild(contentInfoDer, content);
	let decrypted: Uint8Array;
	try {
		decrypted = await decryptEncryptedData(
			contentInfoDer.slice(encryptedData.start - encryptedData.headerLength, encryptedData.end),
			options.password,
			budget,
		);
	} catch (error) {
		rethrowIfInvariant(error);
		if (isWrongPasswordError(error)) {
			return {
				error: pfxFailure('invalid_password', 'Invalid PFX password or encrypted content'),
			};
		}
		if (isKdfIterationLimitError(error)) {
			return { error: pfxFailure('kdf_iterations_exceeded', error.message) };
		}
		return {
			error: pfxFailure('malformed', 'Malformed PFX encrypted content'),
		};
	}
	try {
		readSequenceChildren(decrypted);
	} catch {
		// AES-CBC padding is unauthenticated: a wrong key passes the padding
		// check ~1/256 of the time and "decrypts" to random bytes that are not
		// a SafeContents SEQUENCE — a wrong password, not malformed input.
		return {
			error: pfxFailure('invalid_password', 'Invalid PFX password or encrypted content'),
		};
	}
	return { data: decrypted };
}

/** Encodes a certBag SafeBag wrapping a DER certificate with optional attributes. */
function createCertificateBag(
	certificateDer: Uint8Array,
	attributes: PfxBagAttributesInput | undefined,
): Uint8Array {
	const certBag = sequence([
		objectIdentifier(OIDS.x509CertificateBagType),
		explicitContext(0, octetString(certificateDer)),
	]);
	return sequence([
		objectIdentifier(OIDS.pkcs12CertBag),
		explicitContext(0, certBag),
		...encodeBagAttributes(attributes),
	]);
}

/** Encodes a keyBag SafeBag wrapping PKCS#8 DER with optional attributes. */
function createPrivateKeyBag(
	pkcs8Der: Uint8Array,
	attributes: PfxBagAttributesInput | undefined,
): Uint8Array {
	return sequence([
		objectIdentifier(OIDS.pkcs12KeyBag),
		explicitContext(0, pkcs8Der),
		...encodeBagAttributes(attributes),
	]);
}

/** Wraps raw bytes in a `pkcs7-data` ContentInfo SEQUENCE. */
function createDataContentInfo(data: Uint8Array): Uint8Array {
	return sequence([objectIdentifier(OIDS.pkcs7Data), explicitContext(0, octetString(data))]);
}

/** PBES2-encrypts data and wraps it in a `pkcs7-encryptedData` ContentInfo. */
async function createEncryptedDataContentInfo(
	data: Uint8Array,
	options: PfxEncryptionOptions,
): Promise<Uint8Array> {
	const encryption = await encryptPbes2(data, options);
	const encryptedData = sequence([
		integerFromNumber(0),
		sequence([
			objectIdentifier(OIDS.pkcs7Data),
			encryption.algorithmIdentifierDer,
			tlv(0x80, encryption.encryptedData),
		]),
	]);
	return sequence([objectIdentifier(OIDS.pkcs7EncryptedData), explicitContext(0, encryptedData)]);
}

/** DER-encodes optional friendlyName / localKeyId into a SET OF SEQUENCE. */
function encodeBagAttributes(attributes: PfxBagAttributesInput | undefined): readonly Uint8Array[] {
	if (attributes === undefined) {
		return [];
	}
	const out: Uint8Array[] = [];
	if (attributes.friendlyName !== undefined) {
		out.push(
			sequence([objectIdentifier(OIDS.friendlyName), setOf([bmpString(attributes.friendlyName)])]),
		);
	}
	if (attributes.localKeyId !== undefined) {
		out.push(
			sequence([objectIdentifier(OIDS.localKeyId), setOf([octetString(attributes.localKeyId)])]),
		);
	}
	return out.length === 0 ? [] : [setOf(out)];
}

/** Decodes a single SafeBag from DER into a {@linkcode ParsedPfxBag} discriminated union. */
function parseSafeBag(der: Uint8Array): ParsedPfxBag {
	const children = readSequenceChildren(der);
	const bagId = children[0];
	const bagValue = children[1];
	const attributeSet = children[2];
	if (bagId === undefined || bagValue === undefined || children.length > 3) {
		throw new Error('Malformed SafeBag');
	}
	const bagOid = decodeObjectIdentifier(bagId.value);
	const attributes = parseBagAttributes(der, attributeSet);
	if (bagOid === OIDS.pkcs12CertBag) {
		const certBag = extractContextChild(der, bagValue);
		const certBagDer = der.slice(certBag.start - certBag.headerLength, certBag.end);
		const certBagChildren = readSequenceChildren(certBagDer);
		const certType = certBagChildren[0];
		const certValue = certBagChildren[1];
		if (
			certType === undefined ||
			certValue === undefined ||
			certBagChildren.length !== 2 ||
			decodeObjectIdentifier(certType.value) !== OIDS.x509CertificateBagType
		) {
			throw new Error('Malformed certBag');
		}
		const certificateDer = extractContextOctetString(certBagDer, certValue);
		return {
			kind: 'certificate',
			bagId: bagOid,
			attributes,
			certificate: parseCertificateDerOrThrow(certificateDer),
		};
	}
	if (bagOid === OIDS.pkcs12KeyBag) {
		const pkcs8 = extractContextChild(der, bagValue);
		return {
			kind: 'privateKey',
			bagId: bagOid,
			attributes,
			pkcs8Der: der.slice(pkcs8.start - pkcs8.headerLength, pkcs8.end),
		};
	}
	const value = extractContextChild(der, bagValue);
	return {
		kind: 'unknown',
		bagId: bagOid,
		attributes,
		valueDer: der.slice(value.start - value.headerLength, value.end),
	};
}

/** Decodes the SET OF attributes attached to a SafeBag. */
function parseBagAttributes(
	source: Uint8Array,
	attributeSet: DerElement | undefined,
): ParsedPfxBagAttributes {
	if (attributeSet === undefined) {
		return { entries: [] };
	}
	const entries: ParsedPfxAttribute[] = [];
	let friendlyName: string | undefined;
	let localKeyId: string | undefined;
	for (const attribute of childrenOf(source, attributeSet)) {
		const attributeDer = source.slice(attribute.start - attribute.headerLength, attribute.end);
		const parts = readSequenceChildren(attributeDer);
		const oid = parts[0];
		const values = parts[1];
		if (oid === undefined || values === undefined || parts.length !== 2 || values.tag !== 0x31) {
			throw new Error('Malformed PFX bag attribute');
		}
		const attrOid = decodeObjectIdentifier(oid.value);
		const rawValues = childrenOf(attributeDer, values).map((value) =>
			attributeDer.slice(value.start - value.headerLength, value.end),
		);
		entries.push({
			oid: attrOid,
			valuesHex: rawValues.map((value) => toHex(value)),
		});
		if (attrOid === OIDS.friendlyName) {
			const firstValue = rawValues[0];
			if (friendlyName !== undefined || rawValues.length !== 1 || firstValue === undefined) {
				throw new Error('Malformed friendlyName attribute');
			}
			friendlyName = decodeBmpString(firstValue);
			continue;
		}
		if (attrOid === OIDS.localKeyId) {
			const firstValue = rawValues[0];
			if (localKeyId !== undefined || rawValues.length !== 1 || firstValue === undefined) {
				throw new Error('Malformed localKeyId attribute');
			}
			localKeyId = decodeLocalKeyId(firstValue);
		}
	}
	return {
		entries,
		...(friendlyName === undefined ? {} : { friendlyName }),
		...(localKeyId === undefined ? {} : { localKeyId }),
	};
}

function decodeLocalKeyId(der: Uint8Array): string {
	const element = readElement(der);
	if (element.tag !== 0x04) {
		throw new Error('localKeyId must use OCTET STRING');
	}
	return toHex(element.value);
}

/** Exports a `CryptoKey` to PKCS#8 DER, or passes raw bytes through. */
function normalizePrivateKey(source: PfxPrivateKeySource): Promise<Uint8Array> {
	return source instanceof CryptoKey
		? exportPkcs8Der(source)
		: Promise.resolve(new Uint8Array(source));
}

/** Extracts DER bytes from a PEM string, or passes raw DER through. */
function normalizeCertificate(source: PfxCertificateSource): Uint8Array {
	if (typeof source === 'string') {
		const block = splitPemBlocksOrThrow(source).find(
			(candidate) => candidate.label === 'CERTIFICATE',
		);
		if (block === undefined) {
			throw new Error('Certificate PEM required');
		}
		return new Uint8Array(block.bytes);
	}
	if (source instanceof Uint8Array) {
		return new Uint8Array(source);
	}
	return new Uint8Array(source.der);
}

/** Parses the MacData block and verifies it against the AuthenticatedSafe when a password is given. */
async function verifyPfxMacData(
	macDataDer: Uint8Array,
	authenticatedSafe: Uint8Array,
	options: ParsePfxOptions | undefined,
): Promise<
	| { readonly macData: ParsedPkcs12MacData; readonly error?: undefined }
	| {
			readonly macData?: undefined;
			readonly error: ErrorResult<ParsePfxErrorCode, Record<never, never>, ParsePfxFailure>;
	  }
> {
	const macResult = await parsePkcs12MacData(
		macDataDer,
		authenticatedSafe,
		options?.macPassword ?? options?.password,
		options,
	);
	if (!macResult.ok) {
		return {
			error:
				macResult.code === 'kdf_iterations_exceeded'
					? pfxFailure('kdf_iterations_exceeded', macResult.message)
					: pfxFailure('malformed', 'Malformed PFX MacData'),
		};
	}
	if (macResult.value.verification === 'invalid') {
		return {
			error: pfxFailure('invalid_password', 'Invalid PFX MAC password or corrupted content'),
		};
	}
	return { macData: macResult.value };
}

/** Decrypts a PKCS#7 EncryptedData structure using PBES2 with the given password. */
function decryptEncryptedData(
	encryptedDataDer: Uint8Array,
	password: string,
	budget: KdfBudget,
): Promise<Uint8Array> {
	const topLevel = readSequenceChildren(encryptedDataDer);
	const encryptedContentInfo = topLevel[1];
	if (topLevel.length !== 2 || encryptedContentInfo === undefined) {
		throw new Error('Malformed EncryptedData');
	}
	const version = topLevel[0];
	if (version === undefined || version.tag !== 0x02 || decodeIntegerNumber(version.value) !== 0) {
		throw new Error('Malformed EncryptedData');
	}
	const contentInfoDer = encryptedDataDer.slice(
		encryptedContentInfo.start - encryptedContentInfo.headerLength,
		encryptedContentInfo.end,
	);
	const contentInfoChildren = readSequenceChildren(contentInfoDer);
	const algorithm = contentInfoChildren[1];
	const encryptedContent = contentInfoChildren[2];
	if (
		algorithm === undefined ||
		encryptedContent === undefined ||
		contentInfoChildren.length !== 3 ||
		contentInfoChildren[0]?.tag !== 0x06
	) {
		throw new Error('Malformed EncryptedContentInfo');
	}
	if (encryptedContent.tag !== 0x80) {
		throw new Error('Malformed encrypted content');
	}
	return decryptPbes2(
		contentInfoDer.slice(algorithm.start - algorithm.headerLength, algorithm.end),
		encryptedContent.value,
		password,
		budget,
	);
}

/** Reads the first child of a context-tagged element, expecting an OCTET STRING. */
function extractContextOctetString(source: Uint8Array, element: DerElement): Uint8Array {
	const child = extractContextChild(source, element);
	if (child.tag !== 0x04) {
		throw new Error('Expected OCTET STRING in context value');
	}
	return child.value;
}

/** Reads the first child element inside a context-specific constructed wrapper. */
function extractContextChild(source: Uint8Array, element: DerElement): DerElement {
	if ((element.tag & 0xe0) !== 0xa0) {
		throw new Error('Expected context-specific constructed value');
	}
	const children = childrenOf(source, element);
	const child = children[0];
	if (children.length !== 1 || child === undefined) {
		throw new Error('Expected context-specific wrapper with exactly one value');
	}
	return child;
}

/** Encodes a JS string as an ASN.1 BMPString (UCS-2 big-endian, tag 0x1e). */
function bmpString(value: string): Uint8Array {
	const bytes = new Uint8Array(value.length * 2);
	for (let index = 0; index < value.length; index += 1) {
		const codePoint = value.charCodeAt(index);
		bytes[index * 2] = codePoint >> 8;
		bytes[index * 2 + 1] = codePoint & 0xff;
	}
	return tlv(0x1e, bytes);
}

/** Decodes a DER-encoded BMPString (tag 0x1e) back to a JS string. */
function decodeBmpString(der: Uint8Array): string {
	const element = readElement(der);
	if (element.tag !== 0x1e) {
		throw new Error('Expected BMPString');
	}
	if (element.value.length % 2 !== 0) {
		throw new Error('BMPString must use an even number of bytes');
	}
	let value = '';
	for (let index = 0; index < element.value.length; index += 2) {
		const left = element.value[index] ?? 0;
		const right = element.value[index + 1] ?? 0;
		value += String.fromCharCode((left << 8) | right);
	}
	return value;
}
