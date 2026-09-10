/**
 * Full CRL lifecycle: create, parse, verify, validate, and revocation check.
 *
 * Supports complete and delta CRLs, issuing distribution point scoping,
 * indirect CRL processing, per-entry reason codes, and invalidity dates.
 *
 * @module
 */

import {
	childrenOf,
	decodeBoolean,
	decodeIntegerNumber,
	decodeObjectIdentifier,
	decodeString,
	extractBitStringValue,
	hexToBytes,
	parseTime,
	requireElement,
	toHex,
} from '#micro509/internal/asn1/asn1';
import type { DerElement } from '#micro509/internal/asn1/der';
import {
	bitString,
	concatBytes,
	DEFAULT_MAX_DER_DEPTH,
	explicitContext,
	generalizedTime,
	implicitConstructedContext,
	implicitPrimitiveContext,
	integer,
	integerFromNumber,
	optionalBytesEqual,
	readElement,
	readRootElement,
	readSequenceChildren,
	sequence,
	time,
	tlv,
} from '#micro509/internal/asn1/der';
import { OIDS } from '#micro509/internal/asn1/oids';
import { describeSignatureAlgorithm } from '#micro509/internal/crypto/algorithm-names';
import { verifySignedDataDetailed } from '#micro509/internal/crypto/sig-verify';
import {
	encodeAlgorithmIdentifier,
	getSignatureAlgorithm,
	signBytes,
} from '#micro509/internal/crypto/signing';
import { base64Encode } from '#micro509/internal/shared/base64';
import { compareDistinguishedNames, compareNameAttributeValue } from '#micro509/internal/shared/dn';
import type { ParsedBitFlags } from '#micro509/internal/x509/extension-bits';
import {
	encodeDistributionPointReasonFlagsContent,
	parseDistributionPointReasonFlagsContent,
} from '#micro509/internal/x509/extension-bits';
import { parseGeneralName, parseGeneralNames } from '#micro509/internal/x509/general-name';
import { exportSpkiDer } from '#micro509/keys/keys';
import { pemDecodeOrThrow, pemEncode } from '#micro509/pem/pem';
import type { ErrorResult, Micro509Error } from '#micro509/result/result';
import {
	failureResult,
	rethrowIfInvariant,
	successResult,
	throwMicro509Error,
} from '#micro509/result/result';
import type {
	DistributionPoint,
	DistributionPointReason,
	GeneralName,
	IssuingDistributionPoint,
} from '#micro509/x509/extensions';
import {
	buildSubjectKeyIdentifier,
	encodeCrlDistributionPoints,
	encodeExtension,
	encodeSubjectAltName,
} from '#micro509/x509/extensions';
import type { NameFieldKey, NameInput } from '#micro509/x509/name';
import {
	encodeName,
	encodeRelativeDistinguishedName,
	isNameInputEmpty,
	nameFieldKeyFromOid,
} from '#micro509/x509/name';
import type {
	ParsedCertificate,
	ParsedDistributionPoint,
	ParsedDistributionPointName,
	ParsedIssuingDistributionPoint,
	ParsedIssuingDistributionPointScope,
	ParsedName,
	ParsedNameAttribute,
	ParsedRelativeDistinguishedName,
} from '#micro509/x509/parse';
import { parseCertificateDerOrThrow, parseCertificateFromSource } from '#micro509/x509/parse';

/**
 * Single revoked certificate entry for {@linkcode createCertificateRevocationList}.
 */
export interface RevokedCertificateInput {
	/** DER-encoded certificate serial number to revoke. */
	readonly serialNumber: Uint8Array;
	/** When the certificate was revoked. Defaults to `thisUpdate` of the CRL. */
	readonly revocationDate?: Date;
	/** RFC 5280 CRLReason code. Omit for `unspecified`. */
	readonly reasonCode?: RevocationReason;
	/** When the key or certificate became suspect — may predate `revocationDate`. */
	readonly invalidityDate?: Date;
}

/**
 * RFC 5280 [§5.3.1](https://datatracker.ietf.org/doc/html/rfc5280#section-5.3.1) CRLReason code values.
 *
 * `removeFromCRL` is used in delta CRLs to un-hold a certificate.
 */
export type RevocationReason =
	| 'unspecified'
	| 'keyCompromise'
	| 'cACompromise'
	| 'affiliationChanged'
	| 'superseded'
	| 'cessationOfOperation'
	| 'certificateHold'
	| 'removeFromCRL'
	| 'privilegeWithdrawn'
	| 'aACompromise';

/**
 * Input for {@linkcode createCertificateRevocationList}.
 */
export interface CreateCertificateRevocationListInput {
	/** Distinguished name of the CRL issuer (typically the signing CA). */
	readonly issuer: NameInput;
	/** Private key used to sign the CRL. Algorithm is inferred from the key. */
	readonly signerPrivateKey: CryptoKey;
	/** Issuer public key — used to embed an Authority Key Identifier extension. */
	readonly issuerPublicKey?: CryptoKey;
	/** Issuance timestamp. Defaults to `new Date()`. */
	readonly thisUpdate?: Date;
	/** Planned next issuance. Omit for an open-ended CRL. */
	readonly nextUpdate?: Date;
	/** Certificates to list as revoked in this CRL. */
	readonly revokedCertificates?: readonly RevokedCertificateInput[];
	/** Monotonically-increasing CRL sequence number (CRLNumber extension). */
	readonly crlNumber?: number;
	/** If set, marks this CRL as a delta CRL referencing the given base CRL number. */
	readonly baseCrlNumber?: number;
	/** Issuing distribution point extension — scopes this CRL to a subset of certificates. */
	readonly issuingDistributionPoint?: IssuingDistributionPoint;
	/** Freshest CRL distribution points — tells relying parties where to find delta CRLs. */
	readonly freshestCrlDistributionPoints?: readonly DistributionPoint[];
}

/**
 * Encoded CRL in multiple serialisation formats, returned by {@linkcode createCertificateRevocationList}.
 */
export interface CertificateRevocationListMaterial {
	/** Raw DER bytes of the signed CRL. */
	readonly der: Uint8Array;
	/** PEM-encoded CRL (`-----BEGIN X509 CRL-----`). */
	readonly pem: string;
	/** Base64-encoded DER (no PEM armour). */
	readonly base64: string;
}

/**
 * A single revoked-certificate entry decoded from a CRL.
 */
export interface ParsedRevokedCertificate {
	/** Hex-encoded serial number of the revoked certificate. */
	readonly serialNumberHex: string;
	/** When the CA declared this certificate revoked. */
	readonly revocationDate: Date;
	/** RFC 5280 CRLReason, if the entry carries one. */
	readonly reasonCode?: RevocationReason;
	/** When the key or certificate actually became suspect, if present. */
	readonly invalidityDate?: Date;
	/** Indirect-CRL certificate issuer override (RFC 5280 §5.3.3). */
	readonly certificateIssuer?: readonly GeneralName[];
}

/**
 * Decoded X.509 CRL, returned by {@linkcode parseCertificateRevocationListDer}
 * and {@linkcode parseCertificateRevocationListPem}.
 */
export interface ParsedCertificateRevocationList {
	/** Original DER bytes when this object came from {@linkcode parseCertificateRevocationListDer} or PEM parsing. */
	readonly der?: Uint8Array;
	/** CRL version (1 = v1, 2 = v2 with extensions). */
	readonly version: number;
	/** DER-encoded TBSCertList — the signed payload for signature verification. */
	readonly tbsCertListDer: Uint8Array;
	/** Raw signature bytes from the CRL outer wrapper. */
	readonly signatureValue: Uint8Array;
	/** CRL issuer distinguished name. */
	readonly issuer: ParsedName;
	/** Start of the CRL validity window. */
	readonly thisUpdate: Date;
	/** End of the CRL validity window. Absent if the CA does not commit to a schedule. */
	readonly nextUpdate?: Date;
	/** OID of the algorithm used to sign this CRL. */
	readonly signatureAlgorithmOid: string;
	/** Human-readable signature algorithm name (e.g. `"ECDSA with SHA-256"`). */
	readonly signatureAlgorithmName: string;
	/** DER-encoded signature algorithm parameters (e.g. DER NULL for RSA PKCS#1 v1.5). */
	readonly signatureAlgorithmParametersDer?: Uint8Array;
	/** OID of the issuer's public key algorithm, when available. */
	readonly issuerPublicKeyAlgorithmOid?: string;
	/** OID of the issuer's public key parameters (e.g. named curve), when available. */
	readonly issuerPublicKeyParametersOid?: string;
	/** Hex-encoded Authority Key Identifier, if the extension is present. */
	readonly authorityKeyIdentifier?: string;
	/** CRLNumber extension value — monotonically increasing sequence number. */
	readonly crlNumber?: number;
	/** Delta CRL indicator — present only on delta CRLs, referencing the base CRL number. */
	readonly baseCrlNumber?: number;
	/** Issuing distribution point extension — scopes this CRL to a certificate subset. */
	readonly issuingDistributionPoint?: ParsedIssuingDistributionPoint;
	/** Freshest CRL extension — points to delta CRL locations. */
	readonly freshestCrlDistributionPoints?: readonly ParsedDistributionPoint[];
	/** All revoked certificate entries (empty array if none). */
	readonly revokedCertificates: readonly ParsedRevokedCertificate[];
}

/** RFC 5280 §5.3.1 CRLReason integer codes, keyed by reason name. */
const REVOCATION_REASON_CODES: Record<RevocationReason, number> = {
	unspecified: 0,
	keyCompromise: 1,
	cACompromise: 2,
	affiliationChanged: 3,
	superseded: 4,
	cessationOfOperation: 5,
	certificateHold: 6,
	removeFromCRL: 8,
	privilegeWithdrawn: 9,
	aACompromise: 10,
};

/** PEM string, DER bytes, or already-parsed CRL. */
export type CrlSource = string | Uint8Array | ParsedCertificateRevocationList;
/** PEM string, DER bytes, or already-parsed certificate. */
export type CrlCertificateSource = string | Uint8Array | ParsedCertificate;

/** Failure detail when CRL signature verification fails. */
export interface VerifyCertificateRevocationListSignatureFailure
	extends Micro509Error<'signature_invalid'> {
	/** Always `false` for failures. */
	readonly ok: false;
}

/**
 * Result of {@linkcode verifyCertificateRevocationListSignature}.
 *
 * On success, `value` is the parsed CRL whose signature has been verified.
 */
export type VerifyCertificateRevocationListSignatureResult =
	| {
			readonly ok: true;
			/** Parsed CRL with a verified signature. */
			readonly value: ParsedCertificateRevocationList;
	  }
	| ErrorResult<
			'signature_invalid',
			Record<never, never>,
			VerifyCertificateRevocationListSignatureFailure
	  >;

/**
 * Input for {@linkcode validateCertificateRevocationList}.
 */
export interface ValidateCertificateRevocationListInput {
	/** The CRL to validate. */
	readonly crl: CrlSource;
	/** Certificate of the CA that should have signed the CRL. */
	readonly issuerCertificate: CrlCertificateSource;
	/** Evaluation time for freshness checks. Defaults to `new Date()`. */
	readonly at?: Date;
	/** Tolerance in milliseconds for clock skew when checking `thisUpdate`/`nextUpdate`. */
	readonly clockSkewMs?: number;
	/**
	 * Maximum age of `thisUpdate` at `at`, in milliseconds. A CRL older than
	 * this fails with `stale_crl` even when `nextUpdate` is absent or later.
	 * Unbounded by default.
	 */
	readonly maxAgeMs?: number;
}

/**
 * Failure detail for {@linkcode validateCertificateRevocationList}.
 *
 * Possible codes: `signature_invalid`, `issuer_mismatch`, `stale_crl`, `crl_sign_not_permitted`.
 */
export interface ValidateCertificateRevocationListFailure
	extends Micro509Error<
		'signature_invalid' | 'issuer_mismatch' | 'stale_crl' | 'crl_sign_not_permitted'
	> {
	/** Always `false` for failures. */
	readonly ok: false;
}

/**
 * Result of {@linkcode validateCertificateRevocationList}.
 *
 * On success, the CRL has passed signature, issuer, key-usage, and freshness checks.
 */
export type ValidateCertificateRevocationListResult =
	| {
			readonly ok: true;
			/** Validated and parsed CRL. */
			readonly value: ParsedCertificateRevocationList;
	  }
	| ErrorResult<
			'signature_invalid' | 'issuer_mismatch' | 'stale_crl' | 'crl_sign_not_permitted',
			Record<never, never>,
			ValidateCertificateRevocationListFailure
	  >;

/**
 * Input for {@linkcode checkCertificateRevocationAgainstCrl}.
 */
export interface CheckCertificateRevocationAgainstCrlInput {
	/** Certificate whose revocation status to check. */
	readonly certificate: CrlCertificateSource;
	/** Issuer of `certificate` — also expected signer of the CRL. */
	readonly issuerCertificate: CrlCertificateSource;
	/** Complete (base) CRL to check against. */
	readonly crl: CrlSource;
	/** Optional delta CRL for more recent revocation information. */
	readonly deltaCrl?: CrlSource;
	/** Evaluation time. Defaults to `new Date()`. */
	readonly at?: Date;
	/** Clock-skew tolerance in milliseconds for freshness checks. */
	readonly clockSkewMs?: number;
	/** Maximum age of each CRL's `thisUpdate` in milliseconds. See {@linkcode ValidateCertificateRevocationListInput.maxAgeMs}. */
	readonly maxAgeMs?: number;
}

/** Error codes that {@linkcode checkCertificateRevocationAgainstCrl} may return. */
export type CheckCertificateRevocationAgainstCrlErrorCode =
	| 'signature_invalid'
	| 'issuer_mismatch'
	| 'stale_crl'
	| 'crl_sign_not_permitted'
	| 'non_applicable';

/** Structured reason why a CRL was deemed non-applicable to a given certificate. */
export type CrlApplicabilityFailureReason =
	| 'certificate_scope_mismatch'
	| 'delta_crl_incompatible'
	| 'unsupported_delta_crl'
	| 'distribution_point_mismatch'
	| 'unsupported_indirect_crl'
	| 'issuer_mismatch'
	| 'reasons_mismatch';

/** Internal result of looking up a serial number in a CRL's revoked entries. */
type RevokedCertificateLookupResult =
	| {
			readonly ok: true;
			/** Matching revoked entry, if found. */
			readonly entry?: ParsedRevokedCertificate;
	  }
	| ErrorResult<
			CheckCertificateRevocationAgainstCrlErrorCode,
			CheckCertificateRevocationAgainstCrlFailureDetails,
			CheckCertificateRevocationAgainstCrlFailure
	  >;

/** Structured details attached to a {@linkcode CheckCertificateRevocationAgainstCrlFailure}. */
export interface CheckCertificateRevocationAgainstCrlFailureDetails {
	/** Why the CRL was non-applicable, when the error code is `non_applicable`. */
	readonly reason?: CrlApplicabilityFailureReason;
}

/** Failure detail for {@linkcode checkCertificateRevocationAgainstCrl}. */
export interface CheckCertificateRevocationAgainstCrlFailure
	extends Micro509Error<
		CheckCertificateRevocationAgainstCrlErrorCode,
		CheckCertificateRevocationAgainstCrlFailureDetails
	> {
	/** Always `false` for failures. */
	readonly ok: false;
}

/** Success value when the certificate is not found in the CRL. */
export interface CheckCertificateRevocationAgainstCrlGoodValue {
	/** Certificate is not revoked. */
	readonly status: 'good';
	/** The validated CRL that was checked. */
	readonly crl: ParsedCertificateRevocationList;
	/**
	 * Revocation reasons this check covered, the RFC 5280 §6.3.3 (d)
	 * interim_reasons_mask: the matched distribution point's reasons intersected
	 * with the CRL's `onlySomeReasons`, either alone when the other is absent,
	 * or every reason when both are.
	 */
	readonly coveredReasons: readonly DistributionPointReason[];
}

/** Success value when the certificate is found as revoked in the CRL. */
export interface CheckCertificateRevocationAgainstCrlRevokedValue {
	/** Certificate is revoked. */
	readonly status: 'revoked';
	/** The validated CRL that contained the revocation entry. */
	readonly crl: ParsedCertificateRevocationList;
	/** When the CA declared this certificate revoked. */
	readonly revocationDate: Date;
	/** CRLReason from the entry, if present. */
	readonly reasonCode?: RevocationReason;
}

/** Discriminated union of `good` and `revoked` outcomes. */
export type CheckCertificateRevocationAgainstCrlValue =
	| CheckCertificateRevocationAgainstCrlGoodValue
	| CheckCertificateRevocationAgainstCrlRevokedValue;

/**
 * Result of {@linkcode checkCertificateRevocationAgainstCrl}.
 *
 * On success `value.status` is `'good'` or `'revoked'`.
 * On failure the CRL could not be validated or was non-applicable.
 */
export type CheckCertificateRevocationAgainstCrlResult =
	| {
			readonly ok: true;
			readonly value: CheckCertificateRevocationAgainstCrlValue;
	  }
	| ErrorResult<
			CheckCertificateRevocationAgainstCrlErrorCode,
			CheckCertificateRevocationAgainstCrlFailureDetails,
			CheckCertificateRevocationAgainstCrlFailure
	  >;

type CrlApplicabilityFailure = ErrorResult<
	CheckCertificateRevocationAgainstCrlErrorCode,
	CheckCertificateRevocationAgainstCrlFailureDetails,
	CheckCertificateRevocationAgainstCrlFailure
>;

type CrlDistributionPointScanResult =
	| 'matched'
	| 'reasons_mismatch'
	| 'unsupported_indirect_crl_issuer'
	| 'indirect_issuer_mismatch'
	| 'distribution_point_mismatch'
	| 'indirect_distribution_point'
	| 'scope_mismatch';

type CrlDistributionPointScanFailure = Exclude<CrlDistributionPointScanResult, 'matched'>;

type CrlApplicabilityOutcome =
	| { readonly ok: true; readonly coveredReasons: readonly DistributionPointReason[] }
	| { readonly ok: false; readonly failure: CrlApplicabilityFailure };

/**
 * RFC 5280 §4.2.1.13 ReasonFlags, excluding the reserved `unused` bit.
 *
 * Frozen so a `coveredReasons` result that aliases it cannot corrupt later completeness checks.
 */
export const ALL_DISTRIBUTION_POINT_REASONS: readonly DistributionPointReason[] = Object.freeze([
	'keyCompromise',
	'cACompromise',
	'affiliationChanged',
	'superseded',
	'cessationOfOperation',
	'certificateHold',
	'privilegeWithdrawn',
	'aACompromise',
] as const);

/** True when `reasons` covers every RFC 5280 §4.2.1.13 reason — a complete-scope CRL verdict. */
export function coversAllDistributionPointReasons(reasons: Iterable<string>): boolean {
	const set = reasons instanceof Set ? reasons : new Set(reasons);
	return ALL_DISTRIBUTION_POINT_REASONS.every((reason) => set.has(reason));
}

interface MutableIssuingDistributionPointFields {
	distributionPoint?: ParsedDistributionPointName;
	onlyContainsUserCerts?: boolean;
	onlyContainsCACerts?: boolean;
	onlySomeReasons?: ParsedBitFlags<DistributionPointReason>;
	indirectCrl?: boolean;
	onlyContainsAttributeCerts?: boolean;
}

interface ParsedCrlVersionField {
	readonly version: number;
	readonly nextIndex: number;
}

interface ParsedCrlExtensionFields {
	readonly authorityKeyIdentifier?: string;
	readonly crlNumber?: number;
	readonly baseCrlNumber?: number;
	readonly issuingDistributionPoint?: ParsedIssuingDistributionPoint;
	readonly freshestCrlDistributionPoints?: readonly ParsedDistributionPoint[];
}

interface MutableParsedCrlExtensionFields {
	authorityKeyIdentifier?: string;
	crlNumber?: number;
	baseCrlNumber?: number;
	issuingDistributionPoint?: ParsedIssuingDistributionPoint;
	freshestCrlDistributionPoints?: readonly ParsedDistributionPoint[];
}

interface MutableRevokedCertificateExtensionFields {
	reasonCode?: RevocationReason;
	invalidityDate?: Date;
	certificateIssuer?: readonly GeneralName[];
}

interface MutableDistributionPointFields {
	distributionPoint?: ParsedDistributionPointName;
	reasons?: ParsedBitFlags<DistributionPointReason>;
	crlIssuer?: readonly GeneralName[];
}

interface MutableAuthorityKeyIdentifierState {
	keyIdentifier?: string;
	sawAuthorityCertIssuer: boolean;
	sawAuthorityCertSerialNumber: boolean;
	lastFieldOrder: number;
}

/**
 * Signs and encodes an X.509 v2 CRL.
 *
 * Embeds Authority Key Identifier, CRLNumber, delta CRL indicator,
 * issuing distribution point, and freshest-CRL extensions as configured.
 *
 * @example
 * ```ts
 * import { createCertificateRevocationList } from 'micro509';
 *
 * const crl = await createCertificateRevocationList({
 *   issuer: { commonName: 'Example CA' },
 *   signerPrivateKey: caPrivateKey,
 *   issuerPublicKey: caPublicKey,
 *   thisUpdate: new Date('2025-01-01'),
 *   nextUpdate: new Date('2025-02-01'),
 *   crlNumber: 42,
 *   revokedCertificates: [
 *     { serialNumber: revokedSerial, reasonCode: 'keyCompromise' },
 *   ],
 * });
 * // crl.pem, crl.der, crl.base64
 * ```
 */
export async function createCertificateRevocationList(
	input: CreateCertificateRevocationListInput,
): Promise<CertificateRevocationListMaterial> {
	if (isNameInputEmpty(input.issuer)) {
		throwCrlEncoderError(
			'issuer_distinguished_name_empty',
			'issuer must be a non-empty distinguished name',
		);
	}
	const signatureAlgorithm = getSignatureAlgorithm(input.signerPrivateKey);
	const thisUpdate = input.thisUpdate ?? new Date();
	const nextUpdate = input.nextUpdate;
	const extensions = await buildCrlExtensions(
		input.issuerPublicKey,
		input.crlNumber,
		input.baseCrlNumber,
		input.issuingDistributionPoint,
		input.freshestCrlDistributionPoints,
	);
	const revoked = input.revokedCertificates ?? [];
	const revokedSequence =
		revoked.length === 0
			? []
			: [sequence(revoked.map((entry) => createRevokedCertificate(entry, thisUpdate)))];
	const tbsCertList = sequence([
		integerFromNumber(1),
		encodeAlgorithmIdentifier(signatureAlgorithm),
		encodeName(input.issuer),
		time(thisUpdate),
		...(nextUpdate === undefined ? [] : [time(nextUpdate)]),
		...revokedSequence,
		...(extensions.length === 0 ? [] : [explicitContext(0, sequence(extensions))]),
	]);
	const signatureValue = await signBytes(input.signerPrivateKey, signatureAlgorithm, tbsCertList);
	const der = sequence([
		tbsCertList,
		encodeAlgorithmIdentifier(signatureAlgorithm),
		bitString(signatureValue),
	]);
	return {
		der,
		pem: pemEncode('X509 CRL', der),
		base64: base64Encode(der),
	};
}

/** Machine-readable failure reason for the CRL parsers. */
export type ParseCertificateRevocationListErrorCode = 'malformed';

/** Structured failure payload for CRL parsing. */
export interface ParseCertificateRevocationListFailure
	extends Micro509Error<ParseCertificateRevocationListErrorCode> {
	/** Always `false` for failures. */
	readonly ok: false;
}

/** Success-or-failure result from {@linkcode parseCertificateRevocationListDer} / {@linkcode parseCertificateRevocationListPem}. */
export type ParseCertificateRevocationListResult =
	| { readonly ok: true; readonly value: ParsedCertificateRevocationList }
	| ErrorResult<
			ParseCertificateRevocationListErrorCode,
			Record<never, never>,
			ParseCertificateRevocationListFailure
	  >;

/**
 * Throwing core for {@linkcode parseCertificateRevocationListDer}.
 *
 * Does not verify the signature — call {@linkcode verifyCertificateRevocationListSignature} or
 * {@linkcode validateCertificateRevocationList} for that.
 */
export function parseCertificateRevocationListDerOrThrow(
	der: Uint8Array,
): ParsedCertificateRevocationList {
	const top = readSequenceChildren(der, { maxDepth: DEFAULT_MAX_DER_DEPTH });
	if (top.length !== 3) {
		throw new Error('Malformed CRL');
	}
	const tbsCertList = requireElement(top[0], 'TBSCertList');
	const signatureAlgorithm = requireElement(top[1], 'signatureAlgorithm');
	const signatureValue = requireElement(top[2], 'signatureValue');
	const signedFields = parseSignedCrlFields(
		der.slice(tbsCertList.start - tbsCertList.headerLength, tbsCertList.end),
	);
	const parsedSignatureAlgorithm = parseAlgorithmIdentifier(der, signatureAlgorithm);
	assertMatchingCrlSignatureAlgorithms(signedFields.signature, parsedSignatureAlgorithm);
	return {
		der: new Uint8Array(der),
		version: signedFields.version,
		tbsCertListDer: der.slice(tbsCertList.start - tbsCertList.headerLength, tbsCertList.end),
		signatureValue: extractBitStringValue(signatureValue),
		issuer: signedFields.issuer,
		thisUpdate: signedFields.thisUpdate,
		...(signedFields.nextUpdate === undefined ? {} : { nextUpdate: signedFields.nextUpdate }),
		signatureAlgorithmOid: parsedSignatureAlgorithm.oid,
		signatureAlgorithmName: describeSignatureAlgorithm(
			parsedSignatureAlgorithm.oid,
			parsedSignatureAlgorithm.parametersDer,
		),
		...(parsedSignatureAlgorithm.parametersDer === undefined
			? {}
			: { signatureAlgorithmParametersDer: parsedSignatureAlgorithm.parametersDer }),
		...(signedFields.authorityKeyIdentifier === undefined
			? {}
			: { authorityKeyIdentifier: signedFields.authorityKeyIdentifier }),
		...(signedFields.crlNumber === undefined ? {} : { crlNumber: signedFields.crlNumber }),
		...(signedFields.baseCrlNumber === undefined
			? {}
			: { baseCrlNumber: signedFields.baseCrlNumber }),
		...(signedFields.issuingDistributionPoint === undefined
			? {}
			: { issuingDistributionPoint: signedFields.issuingDistributionPoint }),
		...(signedFields.freshestCrlDistributionPoints === undefined
			? {}
			: { freshestCrlDistributionPoints: signedFields.freshestCrlDistributionPoints }),
		revokedCertificates: signedFields.revokedCertificates,
	};
}

/**
 * Decodes a PEM-encoded X.509 CRL (`-----BEGIN X509 CRL-----`).
 *
 * @example
 * ```ts
 * import { parseCertificateRevocationListPemOrThrow } from 'micro509';
 *
 * const crl = parseCertificateRevocationListPemOrThrow(pemString); // throws if malformed
 * console.log(crl.issuer.values.commonName, crl.revokedCertificates.length);
 * ```
 */
export function parseCertificateRevocationListPemOrThrow(
	pem: string,
): ParsedCertificateRevocationList {
	return parseCertificateRevocationListDerOrThrow(pemDecodeOrThrow('X509 CRL', pem));
}

/**
 * Decodes a DER-encoded X.509 CRL into a structured {@linkcode ParsedCertificateRevocationList}.
 *
 * Returns a typed failure (`code: 'malformed'`) on malformed input. For the
 * throwing form use {@linkcode parseCertificateRevocationListDerOrThrow}.
 * Does not verify the signature — call {@linkcode verifyCertificateRevocationListSignature} or
 * {@linkcode validateCertificateRevocationList} for that.
 */
export function parseCertificateRevocationListDer(
	der: Uint8Array,
): ParseCertificateRevocationListResult {
	try {
		return successResult(parseCertificateRevocationListDerOrThrow(der));
	} catch (error) {
		rethrowIfInvariant(error);
		return failureResult('malformed', error instanceof Error ? error.message : 'Malformed CRL');
	}
}

/**
 * Decodes a PEM-encoded X.509 CRL (`-----BEGIN X509 CRL-----`).
 *
 * Returns a typed failure (`code: 'malformed'`) on malformed input. For the
 * throwing form use {@linkcode parseCertificateRevocationListPemOrThrow}.
 */
export function parseCertificateRevocationListPem(
	pem: string,
): ParseCertificateRevocationListResult {
	try {
		return successResult(parseCertificateRevocationListPemOrThrow(pem));
	} catch (error) {
		rethrowIfInvariant(error);
		return failureResult('malformed', error instanceof Error ? error.message : 'Malformed CRL');
	}
}

/**
 * Verifies the CRL signature against the issuer certificate's public key.
 *
 * Does **not** check issuer name match, key-usage, or freshness — use
 * {@linkcode validateCertificateRevocationList} for full validation.
 */
export async function verifyCertificateRevocationListSignature(
	crl: string | Uint8Array,
	issuerCertificate: string | Uint8Array,
): Promise<VerifyCertificateRevocationListSignatureResult> {
	let parsedCrl: ParsedCertificateRevocationList;
	let issuer: ParsedCertificate;
	try {
		parsedCrl =
			typeof crl === 'string'
				? parseCertificateRevocationListPemOrThrow(crl)
				: parseCertificateRevocationListDerOrThrow(new Uint8Array(crl));
		issuer =
			typeof issuerCertificate === 'string'
				? parseIssuerCertificatePem(issuerCertificate)
				: parseIssuerCertificateDer(new Uint8Array(issuerCertificate));
	} catch {
		return verifyCertificateRevocationListFailureResult(
			'signature_invalid',
			'certificate revocation list or issuer certificate input is malformed',
		);
	}
	let verifiedResult: Awaited<ReturnType<typeof verifySignedDataDetailed>>;
	try {
		verifiedResult = await verifySignedDataDetailed(
			parsedCrl.signatureAlgorithmOid,
			parsedCrl.signatureAlgorithmParametersDer,
			issuer.publicKeyAlgorithmOid,
			issuer.publicKeyParametersOid,
			issuer.subjectPublicKeyInfoDer,
			parsedCrl.signatureValue,
			parsedCrl.tbsCertListDer,
		);
	} catch {
		return verifyCertificateRevocationListFailureResult(
			'signature_invalid',
			'certificate revocation list signature verification failed',
		);
	}
	if (!verifiedResult.ok) {
		if (verifiedResult.code === 'verification_error') {
			return verifyCertificateRevocationListFailureResult(
				'signature_invalid',
				'certificate revocation list signature verification failed',
			);
		}
		return verifyCertificateRevocationListFailureResult(
			'signature_invalid',
			'certificate revocation list signature uses unsupported algorithm parameters',
		);
	}
	return verifiedResult.valid
		? { ok: true, value: parsedCrl }
		: verifyCertificateRevocationListFailureResult(
				'signature_invalid',
				'certificate revocation list signature does not verify',
			);
}

/**
 * Full CRL validation: issuer name match, authority key identifier match,
 * cRLSign key-usage check, signature verification, and `thisUpdate`/`nextUpdate`
 * freshness check (with optional clock-skew tolerance).
 */
export async function validateCertificateRevocationList(
	input: ValidateCertificateRevocationListInput,
): Promise<ValidateCertificateRevocationListResult> {
	let parsedCrl: ParsedCertificateRevocationList;
	try {
		parsedCrl = normalizeCrl(input.crl);
	} catch {
		return validateCertificateRevocationListFailureResult(
			'signature_invalid',
			'certificate revocation list signed content is malformed',
		);
	}
	let issuer: ParsedCertificate;
	try {
		issuer = normalizeCrlCertificate(input.issuerCertificate);
	} catch {
		return validateCertificateRevocationListFailureResult(
			'signature_invalid',
			'issuer certificate input is malformed',
		);
	}
	if (!compareDistinguishedNames(parsedCrl.issuer, issuer.subject)) {
		return validateCertificateRevocationListFailureResult(
			'issuer_mismatch',
			'CRL issuer name does not match certificate subject',
		);
	}
	if (
		parsedCrl.authorityKeyIdentifier !== undefined &&
		issuer.subjectKeyIdentifier !== undefined &&
		parsedCrl.authorityKeyIdentifier !== issuer.subjectKeyIdentifier
	) {
		return validateCertificateRevocationListFailureResult(
			'issuer_mismatch',
			'CRL authority key identifier does not match issuer subject key identifier',
		);
	}
	if (issuer.keyUsage !== undefined && !issuer.keyUsage.flags.includes('cRLSign')) {
		return validateCertificateRevocationListFailureResult(
			'crl_sign_not_permitted',
			'issuer certificate key usage does not permit CRL signing',
		);
	}
	let verifiedResult: Awaited<ReturnType<typeof verifySignedDataDetailed>>;
	try {
		verifiedResult = await verifySignedDataDetailed(
			parsedCrl.signatureAlgorithmOid,
			parsedCrl.signatureAlgorithmParametersDer,
			issuer.publicKeyAlgorithmOid,
			issuer.publicKeyParametersOid,
			issuer.subjectPublicKeyInfoDer,
			parsedCrl.signatureValue,
			parsedCrl.tbsCertListDer,
		);
	} catch {
		return validateCertificateRevocationListFailureResult(
			'signature_invalid',
			'certificate revocation list signature verification failed',
		);
	}
	if (!verifiedResult.ok) {
		if (verifiedResult.code === 'verification_error') {
			return validateCertificateRevocationListFailureResult(
				'signature_invalid',
				'certificate revocation list signature verification failed',
			);
		}
		return validateCertificateRevocationListFailureResult(
			'signature_invalid',
			'certificate revocation list signature uses unsupported algorithm parameters',
		);
	}
	if (!verifiedResult.valid) {
		return validateCertificateRevocationListFailureResult(
			'signature_invalid',
			'certificate revocation list signature does not verify',
		);
	}
	const at = input.at ?? new Date();
	const skew = input.clockSkewMs ?? 0;
	if (
		parsedCrl.thisUpdate.getTime() - skew > at.getTime() ||
		(parsedCrl.nextUpdate !== undefined && parsedCrl.nextUpdate.getTime() + skew < at.getTime())
	) {
		return validateCertificateRevocationListFailureResult(
			'stale_crl',
			'CRL is not valid at requested time',
		);
	}
	if (exceedsCrlMaxAge(parsedCrl, at, skew, input.maxAgeMs)) {
		return validateCertificateRevocationListFailureResult(
			'stale_crl',
			'CRL thisUpdate is older than the maximum age',
		);
	}
	return { ok: true, value: parsedCrl };
}

function exceedsCrlMaxAge(
	crl: ParsedCertificateRevocationList,
	at: Date,
	skew: number,
	maxAgeMs: number | undefined,
): boolean {
	if (maxAgeMs === undefined) {
		return false;
	}
	if (!Number.isFinite(maxAgeMs) || maxAgeMs < 0) {
		throw new RangeError(`Invalid maxAgeMs: must be a non-negative number, got ${maxAgeMs}`);
	}
	return at.getTime() - crl.thisUpdate.getTime() > maxAgeMs + skew;
}

/**
 * End-to-end revocation check: validates the CRL (and optional delta CRL),
 * verifies applicability via distribution-point and scope matching, then
 * resolves the certificate's revocation status.
 *
 * Returns `good` if the serial is absent, `revoked` with date/reason if present,
 * or an error if the CRL cannot be validated or is non-applicable.
 *
 * @example
 * ```ts
 * import { checkCertificateRevocationAgainstCrl } from 'micro509';
 *
 * const result = await checkCertificateRevocationAgainstCrl({
 *   certificate: leafPem,
 *   issuerCertificate: caPem,
 *   crl: crlPem,
 * });
 * if (result.ok && result.value.status === 'revoked') {
 *   console.log('revoked on', result.value.revocationDate);
 * }
 * ```
 */
export async function checkCertificateRevocationAgainstCrl(
	input: CheckCertificateRevocationAgainstCrlInput,
): Promise<CheckCertificateRevocationAgainstCrlResult> {
	let certificate: ParsedCertificate;
	try {
		certificate = normalizeCrlCertificate(input.certificate);
	} catch {
		return checkCertificateRevocationAgainstCrlFailureResult(
			'non_applicable',
			'certificate input is malformed',
		);
	}
	const validated = await validateCertificateRevocationList({
		crl: input.crl,
		issuerCertificate: input.issuerCertificate,
		...(input.at === undefined ? {} : { at: input.at }),
		...(input.clockSkewMs === undefined ? {} : { clockSkewMs: input.clockSkewMs }),
		...(input.maxAgeMs === undefined ? {} : { maxAgeMs: input.maxAgeMs }),
	});
	if (!validated.ok) {
		return checkCertificateRevocationAgainstCrlFailureResult(validated.code, validated.message);
	}
	const deltaResult = await validateOptionalDeltaCrl(input, validated.value);
	if (!deltaResult.ok) return deltaResult;
	const applicability = checkCrlAndDeltaApplicability(
		certificate,
		validated.value,
		deltaResult.value,
	);
	if (!applicability.ok) return applicability.failure;
	const coveredReasons = applicability.coveredReasons;
	const completeRevoked = findRevokedCertificateEntry(certificate, validated.value);
	if (!completeRevoked.ok) {
		return completeRevoked;
	}
	let deltaRevoked: ParsedRevokedCertificate | undefined;
	if (deltaResult.value !== undefined) {
		const deltaLookup = findRevokedCertificateEntry(certificate, deltaResult.value);
		if (!deltaLookup.ok) {
			return deltaLookup;
		}
		deltaRevoked = deltaLookup.entry;
	}
	return resolveCertificateRevocationStatus(
		certificate,
		deltaResult.value?.thisUpdate,
		validated.value,
		completeRevoked.entry,
		deltaRevoked,
		coveredReasons,
	);
}

/** RFC 5280 §6.3.3 (d): interim_reasons_mask from the matched DP and the CRL's IDP. */
function interimReasonsMask(
	distributionPoint: ParsedDistributionPoint | undefined,
	issuingDistributionPoint: ParsedIssuingDistributionPoint | undefined,
): readonly DistributionPointReason[] {
	const distributionPointReasons = distributionPoint?.reasons?.flags;
	const crlReasons = issuingDistributionPoint?.onlySomeReasons?.flags;
	if (distributionPointReasons !== undefined && crlReasons !== undefined) {
		return distributionPointReasons.filter((reason) => crlReasons.includes(reason));
	}
	if (distributionPointReasons !== undefined) {
		return [...distributionPointReasons];
	}
	if (crlReasons !== undefined) {
		return [...crlReasons];
	}
	return ALL_DISTRIBUTION_POINT_REASONS;
}

/** Validates an optional delta CRL and checks compatibility with its complete CRL. */
async function validateOptionalDeltaCrl(
	input: CheckCertificateRevocationAgainstCrlInput,
	completeCrl: ParsedCertificateRevocationList,
): Promise<
	{ readonly ok: true; readonly value?: ParsedCertificateRevocationList } | CrlApplicabilityFailure
> {
	if (input.deltaCrl === undefined) return { ok: true };
	const deltaValidation = await validateCertificateRevocationList({
		crl: input.deltaCrl,
		issuerCertificate: input.issuerCertificate,
		...(input.at === undefined ? {} : { at: input.at }),
		...(input.clockSkewMs === undefined ? {} : { clockSkewMs: input.clockSkewMs }),
		...(input.maxAgeMs === undefined ? {} : { maxAgeMs: input.maxAgeMs }),
	});
	if (!deltaValidation.ok) {
		return checkCertificateRevocationAgainstCrlFailureResult(
			deltaValidation.code,
			deltaValidation.message,
		);
	}
	const compatibilityFailure = checkDeltaCrlCompatibility(completeCrl, deltaValidation.value);
	return compatibilityFailure ?? { ok: true, value: deltaValidation.value };
}

function checkCrlAndDeltaApplicability(
	certificate: ParsedCertificate,
	crl: ParsedCertificateRevocationList,
	deltaCrl: ParsedCertificateRevocationList | undefined,
): CrlApplicabilityOutcome {
	const outcome = checkCrlApplicability(certificate, crl);
	if (!outcome.ok || deltaCrl === undefined) {
		return outcome;
	}
	const deltaOutcome = checkCrlApplicability(certificate, deltaCrl, true);
	return deltaOutcome.ok ? outcome : deltaOutcome;
}

/** Builds a `VerifyCertificateRevocationListSignatureFailureResult`. */
function verifyCertificateRevocationListFailureResult(
	code: 'signature_invalid',
	message: string,
): ErrorResult<
	'signature_invalid',
	Record<never, never>,
	VerifyCertificateRevocationListSignatureFailure
> {
	return failureResult(code, message);
}

/** Builds a `ValidateCertificateRevocationListFailureResult`. */
function validateCertificateRevocationListFailureResult(
	code: 'signature_invalid' | 'issuer_mismatch' | 'stale_crl' | 'crl_sign_not_permitted',
	message: string,
): ErrorResult<
	'signature_invalid' | 'issuer_mismatch' | 'stale_crl' | 'crl_sign_not_permitted',
	Record<never, never>,
	ValidateCertificateRevocationListFailure
> {
	return failureResult(code, message);
}

/** Builds a `CheckCertificateRevocationAgainstCrlFailureResult`. */
function checkCertificateRevocationAgainstCrlFailureResult(
	code: CheckCertificateRevocationAgainstCrlErrorCode,
	message: string,
	details?: CheckCertificateRevocationAgainstCrlFailureDetails,
): ErrorResult<
	CheckCertificateRevocationAgainstCrlErrorCode,
	CheckCertificateRevocationAgainstCrlFailureDetails,
	CheckCertificateRevocationAgainstCrlFailure
> {
	return failureResult(code, message, details);
}

/** Wraps a success value into a `CheckCertificateRevocationAgainstCrlResult`. */
function checkCertificateRevocationAgainstCrlSuccess(
	value: CheckCertificateRevocationAgainstCrlValue,
): CheckCertificateRevocationAgainstCrlResult {
	return { ok: true, value };
}

/**
 * Quick serial-number lookup — returns `true` if the serial appears in the
 * CRL's revoked entries. Does **not** validate the CRL or check applicability.
 */
export function isCertificateRevoked(
	certificateSerialNumber: Uint8Array | string,
	crl: ParsedCertificateRevocationList,
): boolean {
	const serialNumberHex =
		typeof certificateSerialNumber === 'string'
			? normalizeHex(certificateSerialNumber)
			: toHex(certificateSerialNumber);
	return crl.revokedCertificates.some(
		(entry) => normalizeHex(entry.serialNumberHex) === serialNumberHex,
	);
}

/** Searches CRL entries for the certificate's serial, respecting indirect-CRL issuer overrides. */
function findRevokedCertificateEntry(
	certificate: ParsedCertificate,
	crl: ParsedCertificateRevocationList,
): RevokedCertificateLookupResult {
	const serialNumberHex = normalizeHex(certificate.serialNumberHex);
	let effectiveIssuer: readonly GeneralName[] | undefined;
	let sawUnsupportedIssuer = false;
	let matchedEntry: ParsedRevokedCertificate | undefined;
	for (const entry of crl.revokedCertificates) {
		if (entry.certificateIssuer !== undefined) {
			effectiveIssuer = entry.certificateIssuer;
		}
		if (normalizeHex(entry.serialNumberHex) !== serialNumberHex) {
			continue;
		}
		const issuerMatch = matchesRevokedEntryIssuer(certificate, crl, effectiveIssuer);
		if (issuerMatch === 'match') {
			if (matchedEntry !== undefined) {
				return checkCertificateRevocationAgainstCrlFailureResult(
					'signature_invalid',
					'CRL contains multiple revoked entries for certificate',
				);
			}
			matchedEntry = entry;
			continue;
		}
		if (issuerMatch === 'unsupported') {
			sawUnsupportedIssuer = true;
		}
	}
	if (matchedEntry !== undefined) {
		return { ok: true, entry: matchedEntry };
	}
	if (sawUnsupportedIssuer) {
		return nonApplicable(
			'unsupported_indirect_crl',
			'indirect CRL entry certificateIssuer must include a directoryName',
		);
	}
	return { ok: true };
}

/** RFC 5280 §6.3 CRL applicability: scope, distribution-point, reason, and indirect-CRL checks. */
function checkCrlApplicability(
	certificate: ParsedCertificate,
	crl: ParsedCertificateRevocationList,
	allowDeltaCrl = false,
): CrlApplicabilityOutcome {
	if (!allowDeltaCrl && crl.baseCrlNumber !== undefined) {
		return notApplicableOutcome(
			'unsupported_delta_crl',
			'a delta CRL cannot be used as the primary complete CRL input',
		);
	}
	const issuingDistributionPoint = crl.issuingDistributionPoint;
	const isIndirectCrl = issuingDistributionPoint?.indirectCrl === true;
	if (!isIndirectCrl && !compareDistinguishedNames(certificate.issuer, crl.issuer)) {
		return notApplicableOutcome(
			'issuer_mismatch',
			'CRL issuer does not match certificate issuer for direct CRL processing',
		);
	}
	if (issuingDistributionPoint?.onlyContainsAttributeCerts === true) {
		return notApplicableOutcome(
			'certificate_scope_mismatch',
			'attribute-certificate-only CRLs are not applicable to public-key certificates',
		);
	}
	const isCaCertificate = certificate.basicConstraints?.ca === true;
	if (issuingDistributionPoint?.onlyContainsUserCerts === true && isCaCertificate) {
		return notApplicableOutcome(
			'certificate_scope_mismatch',
			'CRL only applies to end-entity certificates',
		);
	}
	if (issuingDistributionPoint?.onlyContainsCACerts === true && !isCaCertificate) {
		return notApplicableOutcome(
			'certificate_scope_mismatch',
			'CRL only applies to CA certificates',
		);
	}
	const distributionPoints = certificate.crlDistributionPoints ?? [];
	if (distributionPoints.length === 0) {
		if (
			issuingDistributionPoint?.distributionPoint !== undefined &&
			!matchesDistributionPointName(
				issuerFallbackDistributionPointName(certificate),
				issuingDistributionPoint.distributionPoint,
				crl.issuer,
				undefined,
			)
		) {
			return notApplicableOutcome(
				'distribution_point_mismatch',
				'CRL issuing distribution point does not name the certificate issuer',
			);
		}
		if (isIndirectCrl && !compareDistinguishedNames(certificate.issuer, crl.issuer)) {
			return notApplicableOutcome(
				'issuer_mismatch',
				'indirect CRLs for alternate certificate issuers require matching CRLIssuer distribution points',
			);
		}
		return { ok: true, coveredReasons: interimReasonsMask(undefined, issuingDistributionPoint) };
	}
	const scanResult = scanCrlDistributionPoints(
		distributionPoints,
		certificate,
		crl,
		issuingDistributionPoint,
		isIndirectCrl,
	);
	if (typeof scanResult === 'string') {
		return { ok: false, failure: crlDistributionPointScanFailure(scanResult) };
	}
	return { ok: true, coveredReasons: scanResult.coveredReasons };
}

/** Wraps a non-applicability failure into a {@linkcode CrlApplicabilityOutcome}. */
function notApplicableOutcome(
	reason: CrlApplicabilityFailureReason,
	message: string,
): CrlApplicabilityOutcome {
	return { ok: false, failure: nonApplicable(reason, message) };
}

/**
 * RFC 5280 §6.3.3 final paragraph: for a certificate without a CRLDP extension,
 * assume a distribution point named by the certificate issuer and its
 * issuerAltName entries, with reasons and cRLIssuer omitted.
 */
function issuerFallbackDistributionPointName(
	certificate: ParsedCertificate,
): ParsedDistributionPointName {
	return {
		type: 'fullName',
		fullName: [
			{ type: 'directoryName', derHex: certificate.issuer.derHex },
			...(certificate.issuerAltNames ?? []),
		],
	};
}

/**
 * Aggregates distribution-point matching across a certificate.
 *
 * RFC 5280 §6.3.3 processes every corresponding DP, so when several match the same CRL their
 * interim reason masks (d) are unioned rather than stopping at the first.
 */
function scanCrlDistributionPoints(
	distributionPoints: readonly ParsedDistributionPoint[],
	certificate: ParsedCertificate,
	crl: ParsedCertificateRevocationList,
	issuingDistributionPoint: ParsedIssuingDistributionPoint | undefined,
	isIndirectCrl: boolean,
):
	| { readonly coveredReasons: readonly DistributionPointReason[] }
	| CrlDistributionPointScanFailure {
	const coveredReasons = new Set<DistributionPointReason>();
	const failures = new Set<CrlDistributionPointScanFailure>();
	let sawMatch = false;
	for (const distributionPoint of distributionPoints) {
		const result = scanCrlDistributionPoint(
			distributionPoint,
			certificate,
			crl,
			issuingDistributionPoint,
			isIndirectCrl,
		);
		if (result === 'matched') {
			sawMatch = true;
			for (const reason of interimReasonsMask(distributionPoint, issuingDistributionPoint)) {
				coveredReasons.add(reason);
			}
			continue;
		}
		failures.add(result);
	}
	return sawMatch ? { coveredReasons: [...coveredReasons] } : resolveScanFailure(failures);
}

/** Reports the highest-precedence distribution-point scan failure. */
function resolveScanFailure(
	failures: ReadonlySet<CrlDistributionPointScanFailure>,
): CrlDistributionPointScanFailure {
	const precedence: readonly CrlDistributionPointScanFailure[] = [
		'reasons_mismatch',
		'unsupported_indirect_crl_issuer',
		'indirect_issuer_mismatch',
		'distribution_point_mismatch',
		'indirect_distribution_point',
	];
	return precedence.find((failure) => failures.has(failure)) ?? 'scope_mismatch';
}

function scanCrlDistributionPoint(
	distributionPoint: ParsedDistributionPoint,
	certificate: ParsedCertificate,
	crl: ParsedCertificateRevocationList,
	issuingDistributionPoint: ParsedIssuingDistributionPoint | undefined,
	isIndirectCrl: boolean,
): CrlDistributionPointScanResult {
	const issuerResult = scanCrlDistributionPointIssuer(
		distributionPoint,
		certificate,
		crl,
		isIndirectCrl,
	);
	if (issuerResult !== undefined) return issuerResult;
	if (
		!matchesDistributionPointName(
			distributionPoint.distributionPoint,
			issuingDistributionPoint?.distributionPoint,
			crl.issuer,
			distributionPoint.crlIssuer,
		)
	) {
		return 'distribution_point_mismatch';
	}
	return hasOverlappingReasons(distributionPoint.reasons, issuingDistributionPoint?.onlySomeReasons)
		? 'matched'
		: 'reasons_mismatch';
}

function scanCrlDistributionPointIssuer(
	distributionPoint: ParsedDistributionPoint,
	certificate: ParsedCertificate,
	crl: ParsedCertificateRevocationList,
	isIndirectCrl: boolean,
): CrlDistributionPointScanResult | undefined {
	if (!isIndirectCrl) {
		return distributionPoint.crlIssuer === undefined ? undefined : 'indirect_distribution_point';
	}
	if (
		compareDistinguishedNames(certificate.issuer, crl.issuer) &&
		distributionPoint.crlIssuer === undefined
	) {
		return undefined;
	}
	const issuerMatch = matchesIndirectCrlIssuer(distributionPoint.crlIssuer, crl);
	if (issuerMatch === 'unsupported') return 'unsupported_indirect_crl_issuer';
	return issuerMatch ? undefined : 'indirect_issuer_mismatch';
}

function crlDistributionPointScanFailure(
	result: CrlDistributionPointScanFailure,
): CrlApplicabilityFailure {
	if (result === 'reasons_mismatch') {
		return nonApplicable(
			'reasons_mismatch',
			'certificate distribution point reasons do not overlap the CRL reason scope',
		);
	}
	if (result === 'unsupported_indirect_crl_issuer') {
		return nonApplicable(
			'unsupported_indirect_crl',
			'indirect CRL distribution points must identify the CRL issuer with directoryName',
		);
	}
	if (result === 'indirect_issuer_mismatch') {
		return nonApplicable(
			'issuer_mismatch',
			'certificate distribution points do not authorize this indirect CRL issuer',
		);
	}
	if (result === 'distribution_point_mismatch') {
		return nonApplicable(
			'distribution_point_mismatch',
			'certificate distribution points do not match the CRL issuing distribution point',
		);
	}
	if (result === 'indirect_distribution_point') {
		return nonApplicable(
			'unsupported_indirect_crl',
			'certificate distribution points that name alternate CRL issuers are not supported yet',
		);
	}
	return nonApplicable(
		'distribution_point_mismatch',
		'certificate distribution points do not match the CRL scope',
	);
}

/** Verifies that a delta CRL is compatible with the given complete CRL (same issuer, AKI, IDP, and valid numbering). */
function checkDeltaCrlCompatibility(
	completeCrl: ParsedCertificateRevocationList,
	deltaCrl: ParsedCertificateRevocationList,
):
	| ErrorResult<
			CheckCertificateRevocationAgainstCrlErrorCode,
			CheckCertificateRevocationAgainstCrlFailureDetails,
			CheckCertificateRevocationAgainstCrlFailure
	  >
	| undefined {
	if (completeCrl.baseCrlNumber !== undefined) {
		return nonApplicable(
			'delta_crl_incompatible',
			'complete CRL input must not itself be a delta CRL',
		);
	}
	if (deltaCrl.baseCrlNumber === undefined) {
		return nonApplicable(
			'delta_crl_incompatible',
			'delta CRL input must include a delta CRL indicator',
		);
	}
	if (!compareDistinguishedNames(completeCrl.issuer, deltaCrl.issuer)) {
		return nonApplicable(
			'delta_crl_incompatible',
			'complete and delta CRLs must share the same issuer',
		);
	}
	if (completeCrl.authorityKeyIdentifier !== deltaCrl.authorityKeyIdentifier) {
		return nonApplicable(
			'delta_crl_incompatible',
			'complete and delta CRLs must share the same authority key identifier',
		);
	}
	if (
		!sameIssuingDistributionPoint(
			completeCrl.issuingDistributionPoint,
			deltaCrl.issuingDistributionPoint,
		)
	) {
		return nonApplicable(
			'delta_crl_incompatible',
			'complete and delta CRLs must share the same issuing distribution point scope',
		);
	}
	if (completeCrl.crlNumber === undefined || deltaCrl.crlNumber === undefined) {
		return nonApplicable(
			'delta_crl_incompatible',
			'complete and delta CRLs must both carry CRL numbers for delta processing',
		);
	}
	if (completeCrl.crlNumber < deltaCrl.baseCrlNumber) {
		return nonApplicable(
			'delta_crl_incompatible',
			'delta CRL base number must not exceed the complete CRL number',
		);
	}
	if (completeCrl.crlNumber >= deltaCrl.crlNumber) {
		return nonApplicable(
			'delta_crl_incompatible',
			'delta CRL number must be newer than the complete CRL number',
		);
	}
	return undefined;
}

/** Checks whether any `crlIssuer` GeneralName matches the CRL's issuer via directoryName DER comparison. */
function matchesIndirectCrlIssuer(
	crlIssuerNames: readonly GeneralName[] | undefined,
	crl: ParsedCertificateRevocationList,
): boolean | 'unsupported' {
	if (crlIssuerNames === undefined) {
		return false;
	}
	let sawUnsupportedName = false;
	for (const generalName of crlIssuerNames) {
		if (generalName.type === 'directoryName') {
			if (directoryNameDerHexMatchesParsedName(generalName.derHex, crl.issuer)) {
				return true;
			}
			continue;
		}
		sawUnsupportedName = true;
	}
	return sawUnsupportedName ? 'unsupported' : false;
}

/** Determines whether a revoked entry's effective issuer matches the certificate's issuer. */
function matchesRevokedEntryIssuer(
	certificate: ParsedCertificate,
	crl: ParsedCertificateRevocationList,
	effectiveIssuer: readonly GeneralName[] | undefined,
): 'match' | 'mismatch' | 'unsupported' {
	if (effectiveIssuer === undefined) {
		return compareDistinguishedNames(certificate.issuer, crl.issuer) ? 'match' : 'mismatch';
	}
	let sawUnsupportedName = false;
	for (const generalName of effectiveIssuer) {
		if (generalName.type === 'directoryName') {
			if (directoryNameDerHexMatchesParsedName(generalName.derHex, certificate.issuer)) {
				return 'match';
			}
			continue;
		}
		sawUnsupportedName = true;
	}
	return sawUnsupportedName ? 'unsupported' : 'mismatch';
}

/** Shorthand for building a `non_applicable` failure result with the given reason. */
function nonApplicable(
	reason: CrlApplicabilityFailureReason,
	message: string,
): ErrorResult<
	CheckCertificateRevocationAgainstCrlErrorCode,
	CheckCertificateRevocationAgainstCrlFailureDetails,
	CheckCertificateRevocationAgainstCrlFailure
> {
	return checkCertificateRevocationAgainstCrlFailureResult('non_applicable', message, { reason });
}

/**
 * Merges complete and delta CRL entries into a final `good`/`revoked` status
 * per the RFC 5280 §6.3.3 (i)-(k) relying-party algorithm.
 *
 * Deliberately harder than (i)-(k) on `removeFromCRL`: the entry clears a
 * revocation only in the two situations §5.2.4(b)/§5.3.1 permit an issuer to
 * emit it, a complete-CRL `certificateHold` entry or a certificate that
 * expired before the delta CRL's thisUpdate.
 */
function resolveCertificateRevocationStatus(
	certificate: ParsedCertificate,
	deltaThisUpdate: Date | undefined,
	completeCrl: ParsedCertificateRevocationList,
	completeEntry: ParsedRevokedCertificate | undefined,
	deltaEntry: ParsedRevokedCertificate | undefined,
	coveredReasons: readonly DistributionPointReason[],
): CheckCertificateRevocationAgainstCrlResult {
	if (deltaEntry !== undefined) {
		if (deltaEntry.reasonCode === 'removeFromCRL') {
			if (
				completeEntry?.reasonCode === 'certificateHold' ||
				(deltaThisUpdate !== undefined &&
					certificate.notAfter.getTime() < deltaThisUpdate.getTime())
			) {
				return checkCertificateRevocationAgainstCrlSuccess({
					status: 'good',
					crl: completeCrl,
					coveredReasons,
				});
			}
		} else {
			return checkCertificateRevocationAgainstCrlSuccess({
				status: 'revoked',
				crl: completeCrl,
				revocationDate: deltaEntry.revocationDate,
				...(deltaEntry.reasonCode === undefined ? {} : { reasonCode: deltaEntry.reasonCode }),
			});
		}
	}
	if (completeEntry === undefined) {
		return checkCertificateRevocationAgainstCrlSuccess({
			status: 'good',
			crl: completeCrl,
			coveredReasons,
		});
	}
	return checkCertificateRevocationAgainstCrlSuccess({
		status: 'revoked',
		crl: completeCrl,
		revocationDate: completeEntry.revocationDate,
		...(completeEntry.reasonCode === undefined ? {} : { reasonCode: completeEntry.reasonCode }),
	});
}

/**
 * Returns `true` if the certificate's distribution-point name matches the CRL's IDP name.
 *
 * Per RFC 5280 §4.2.1.13, when the certificate uses `nameRelativeToCRLIssuer` (relativeName),
 * the full distribution point name is formed by appending that RDN to the CRL issuer's DN.
 * This resolved name is then compared against the CRL's IDP fullName directoryName entries.
 */
function matchesDistributionPointName(
	certificatePoint: ParsedDistributionPointName | undefined,
	crlPoint: ParsedDistributionPointName | undefined,
	crlIssuer: ParsedName,
	certificateCrlIssuer: readonly GeneralName[] | undefined,
): boolean {
	if (crlPoint === undefined) {
		return true;
	}
	if (certificatePoint === undefined) {
		return matchesIdpNameAgainstCrlIssuer(crlPoint, certificateCrlIssuer, crlIssuer);
	}
	if (certificatePoint.type === 'fullName' && crlPoint.type === 'fullName') {
		return certificatePoint.fullName.some((leftName) =>
			crlPoint.fullName.some((rightName) => compareGeneralNames(leftName, rightName)),
		);
	}
	if (certificatePoint.type === 'relativeName' && crlPoint.type === 'fullName') {
		const resolvedDnHex = resolveRelativeNameToDnHex(crlIssuer, certificatePoint.relativeName);
		return crlPoint.fullName.some(
			(name) => name.type === 'directoryName' && name.derHex === resolvedDnHex,
		);
	}
	if (certificatePoint.type === 'relativeName' && crlPoint.type === 'relativeName') {
		return compareRelativeDistinguishedNames(certificatePoint.relativeName, crlPoint.relativeName);
	}
	if (certificatePoint.type === 'fullName' && crlPoint.type === 'relativeName') {
		const resolvedDnHex = resolveRelativeNameToDnHex(crlIssuer, crlPoint.relativeName);
		return certificatePoint.fullName.some(
			(name) => name.type === 'directoryName' && name.derHex === resolvedDnHex,
		);
	}
	return false;
}

/**
 * RFC 5280 §6.3.3 (b)(2)(i): when the certificate's distribution point omits the
 * distributionPoint field, match the CRL IDP's distributionPoint names against
 * the distribution point's `cRLIssuer` names.
 */
function matchesIdpNameAgainstCrlIssuer(
	crlPoint: ParsedDistributionPointName,
	certificateCrlIssuer: readonly GeneralName[] | undefined,
	crlIssuer: ParsedName,
): boolean {
	if (certificateCrlIssuer === undefined) {
		return false;
	}
	if (crlPoint.type === 'fullName') {
		return certificateCrlIssuer.some((issuerName) =>
			crlPoint.fullName.some((name) => compareGeneralNames(issuerName, name)),
		);
	}
	const resolvedDnHex = resolveRelativeNameToDnHex(crlIssuer, crlPoint.relativeName);
	return certificateCrlIssuer.some(
		(issuerName) => issuerName.type === 'directoryName' && issuerName.derHex === resolvedDnHex,
	);
}

/** Constructs a full DN by appending an RDN to an existing Name, returning hex-encoded DER. */
function resolveRelativeNameToDnHex(
	issuer: ParsedName,
	relativeName: ParsedRelativeDistinguishedName,
): string {
	// Collect existing RDN DER bytes from issuer
	const rdnDerParts = issuer.rdns.map((rdn) => hexToBytes(rdn.derHex));
	// The relativeName.derHex has implicit tag [1] (0xa1) from the CHOICE encoding.
	// Extract the content and re-wrap as a proper RDN SET (tag 0x31).
	const relativeNameDer = hexToBytes(relativeName.derHex);
	const relativeNameRdnDer = rebuildRelativeNameAsSet(relativeNameDer);
	rdnDerParts.push(relativeNameRdnDer);
	// Wrap in a Name SEQUENCE
	return toHex(sequence(rdnDerParts));
}

/** Converts an implicit-tagged [1] relativeName to a proper SET-tagged RDN. */
function rebuildRelativeNameAsSet(implicitTaggedDer: Uint8Array): Uint8Array {
	// The implicit tag [1] is 0xa1 (context-specific constructed).
	// Parse the element to get content, then re-wrap with SET tag 0x31.
	const element = readRootElement(implicitTaggedDer, { maxDepth: DEFAULT_MAX_DER_DEPTH });
	return tlv(0x31, element.value);
}

/** Deep-compares two issuing distribution point extensions for delta-CRL compatibility. */
function sameIssuingDistributionPoint(
	left: ParsedIssuingDistributionPoint | undefined,
	right: ParsedIssuingDistributionPoint | undefined,
): boolean {
	if (left === undefined || right === undefined) {
		return left === right;
	}
	return (
		sameDistributionPointName(left.distributionPoint, right.distributionPoint) &&
		(left.onlyContainsUserCerts === true) === (right.onlyContainsUserCerts === true) &&
		(left.onlyContainsCACerts === true) === (right.onlyContainsCACerts === true) &&
		(left.indirectCrl === true) === (right.indirectCrl === true) &&
		(left.onlyContainsAttributeCerts === true) === (right.onlyContainsAttributeCerts === true) &&
		sameReasonSet(left.onlySomeReasons, right.onlySomeReasons)
	);
}

/** Compares two DistributionPointName values (fullName set or relativeName). */
function sameDistributionPointName(
	left: ParsedDistributionPointName | undefined,
	right: ParsedDistributionPointName | undefined,
): boolean {
	if (left === undefined || right === undefined) {
		return left === right;
	}
	if (left.type === 'fullName' && right.type === 'fullName') {
		return sameGeneralNameSet(left.fullName, right.fullName);
	}
	if (left.type === 'relativeName' && right.type === 'relativeName') {
		return compareRelativeDistinguishedNames(left.relativeName, right.relativeName);
	}
	return false;
}

/** Set-equality comparison for GeneralName arrays (order-independent). */
function sameGeneralNameSet(left: readonly GeneralName[], right: readonly GeneralName[]): boolean {
	if (left.length !== right.length) {
		return false;
	}
	const matched = Array.from({ length: right.length }, () => false);
	for (const leftName of left) {
		let found = false;
		for (let index = 0; index < right.length; index += 1) {
			const rightName = right[index];
			if (rightName === undefined || matched[index]) {
				continue;
			}
			if (!compareGeneralNames(leftName, rightName)) {
				continue;
			}
			matched[index] = true;
			found = true;
			break;
		}
		if (!found) {
			return false;
		}
	}
	return true;
}

/** Set-equality comparison for DistributionPointReason arrays. */
function sameReasonSet(
	left: ParsedBitFlags<DistributionPointReason> | undefined,
	right: ParsedBitFlags<DistributionPointReason> | undefined,
): boolean {
	if (left === undefined || right === undefined) {
		return left === right;
	}
	if (left.flags.length !== right.flags.length) {
		return false;
	}
	return left.flags.every((reason) => right.flags.includes(reason));
}

/** Returns `true` if the certificate's DP reasons overlap the CRL's `onlySomeReasons`, or if either is absent (= all reasons). */
function hasOverlappingReasons(
	certificateReasons: ParsedBitFlags<DistributionPointReason> | undefined,
	crlReasons: ParsedBitFlags<DistributionPointReason> | undefined,
): boolean {
	if (certificateReasons === undefined || crlReasons === undefined) {
		return true;
	}
	return certificateReasons.flags.some((reason) => crlReasons.flags.includes(reason));
}

/** Value-equality for two GeneralName entries, using DER comparison for directoryName. */
function compareGeneralNames(left: GeneralName, right: GeneralName): boolean {
	if (left.type === 'dns' && right.type === 'dns') {
		// RFC 5280 §7.2: dNSName comparison is case-insensitive.
		return left.value.toLowerCase() === right.value.toLowerCase();
	}
	if (left.type === 'srv' && right.type === 'srv') {
		// RFC 4985 §2: the SRVName Service and the DNS Name both compare case-insensitively.
		return left.value.toLowerCase() === right.value.toLowerCase();
	}
	if (left.type === 'email' && right.type === 'email') {
		return compareRfc822Names(left.value, right.value);
	}
	if (left.type === 'ip' && right.type === 'ip') {
		return left.value === right.value;
	}
	if (left.type === 'uri' && right.type === 'uri') {
		return compareUniformResourceIdentifiers(left.value, right.value);
	}
	if (left.type === 'directoryName' && right.type === 'directoryName') {
		const leftName = parseDerHexName(left.derHex);
		const rightName = parseDerHexName(right.derHex);
		if (leftName === undefined || rightName === undefined) {
			return false;
		}
		return compareDistinguishedNames(leftName, rightName);
	}
	if (left.type === 'unknown' && right.type === 'unknown') {
		return left.tag === right.tag && bytesEqual(left.value, right.value);
	}
	return false;
}

/** RFC 5280 §7.5: rfc822Name local-part is case-sensitive, the host-part case-insensitive. */
function compareRfc822Names(left: string, right: string): boolean {
	const leftAt = left.lastIndexOf('@');
	const rightAt = right.lastIndexOf('@');
	if (leftAt < 0 || rightAt < 0) {
		return left.toLowerCase() === right.toLowerCase();
	}
	return (
		left.slice(0, leftAt) === right.slice(0, rightAt) &&
		left.slice(leftAt + 1).toLowerCase() === right.slice(rightAt + 1).toLowerCase()
	);
}

/** RFC 5280 §7.4: URIs compare only after syntax-based and scheme-based normalization. */
function compareUniformResourceIdentifiers(left: string, right: string): boolean {
	if (left === right) {
		return true;
	}
	const normalizedLeft = normalizeUriForComparison(left);
	if (normalizedLeft === undefined) {
		return false;
	}
	return normalizedLeft === normalizeUriForComparison(right);
}

/**
 * The schemes RFC 5280 §7.4 step 5 requires implementations to recognise, with
 * the default port that scheme-based normalization elides. `ldaps` is included
 * as the TLS form of the mandatory `ldap` scheme.
 */
const URI_DEFAULT_PORT_BY_SCHEME: ReadonlyMap<string, string> = new Map([
	['ftp', '21'],
	['http', '80'],
	['https', '443'],
	['ldap', '389'],
	['ldaps', '636'],
]);

/**
 * Applies the RFC 5280 §7.4 comparison preparation: IDN labels to ASCII
 * Compatible Encoding, lowercased scheme and host, percent-encoding and path
 * segment normalization, and scheme-based normalization. The URL parser covers
 * path segments for every scheme and the scheme case; the remaining steps are
 * applied here because it leaves the host of a non-special scheme such as
 * `ldap` untouched and never normalizes percent-encoding.
 *
 * @returns `undefined` when the value does not parse as an absolute URI.
 */
function normalizeUriForComparison(value: string): string | undefined {
	let url: URL;
	try {
		url = new URL(value);
	} catch {
		return undefined;
	}
	if (url.hostname !== '') {
		const host = normalizeUriHost(url.hostname);
		if (host === undefined) {
			return undefined;
		}
		url.hostname = host;
	}
	if (url.port === URI_DEFAULT_PORT_BY_SCHEME.get(url.protocol.slice(0, -1))) {
		url.port = '';
	}
	return normalizePercentEncoding(url.href);
}

/**
 * Reparses a host under a special scheme so the URL parser applies IDNA and
 * lowercasing to it, which it skips for opaque hosts.
 *
 * @returns `undefined` when the host does not survive the round trip intact.
 */
function normalizeUriHost(hostname: string): string | undefined {
	try {
		const probe = new URL(`https://${decodeHostPercentEncoding(hostname)}`);
		return probe.href === `https://${probe.hostname}/` ? probe.hostname : undefined;
	} catch {
		return undefined;
	}
}

/** Recovers the Unicode host an opaque-host URI carries as percent-encoded UTF-8. */
function decodeHostPercentEncoding(hostname: string): string {
	try {
		return decodeURIComponent(hostname);
	} catch {
		return hostname;
	}
}

const PERCENT_TRIPLET = /%[0-9A-Fa-f]{2}/g;

/** RFC 3986 §6.2.2.2: unreserved triplets decode, every other triplet uppercases. */
function normalizePercentEncoding(value: string): string {
	return value.replace(PERCENT_TRIPLET, (triplet) => {
		const code = Number.parseInt(triplet.slice(1), 16);
		return isUnreservedUriCharacter(code) ? String.fromCharCode(code) : triplet.toUpperCase();
	});
}

/** RFC 3986 §2.3 unreserved set: `ALPHA / DIGIT / "-" / "." / "_" / "~"`. */
function isUnreservedUriCharacter(code: number): boolean {
	return (
		(code >= 0x41 && code <= 0x5a) ||
		(code >= 0x61 && code <= 0x7a) ||
		(code >= 0x30 && code <= 0x39) ||
		code === 0x2d ||
		code === 0x2e ||
		code === 0x5f ||
		code === 0x7e
	);
}

/** Constant-length byte-array equality check. */
function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
	if (left.length !== right.length) {
		return false;
	}
	for (let index = 0; index < left.length; index += 1) {
		if (left[index] !== right[index]) {
			return false;
		}
	}
	return true;
}

/** Set-equality comparison for RDN attribute sets (order-independent, RFC 4518 string prep). */
function compareRelativeDistinguishedNames(
	left: ParsedRelativeDistinguishedName,
	right: ParsedRelativeDistinguishedName,
): boolean {
	if (left.attributes.length !== right.attributes.length) {
		return false;
	}
	const matched = Array.from({ length: right.attributes.length }, () => false);
	for (const leftAttribute of left.attributes) {
		let found = false;
		for (let index = 0; index < right.attributes.length; index += 1) {
			const rightAttribute = right.attributes[index];
			if (rightAttribute === undefined || matched[index]) {
				continue;
			}
			if (!compareNameAttributeValue(leftAttribute, rightAttribute)) {
				continue;
			}
			matched[index] = true;
			found = true;
			break;
		}
		if (!found) {
			return false;
		}
	}
	return true;
}

/** Assembles the CRL-level v2 extensions (AKI, CRLNumber, deltaCRLIndicator, IDP, freshestCRL). */
async function buildCrlExtensions(
	issuerPublicKey: CryptoKey | undefined,
	crlNumber: number | undefined,
	baseCrlNumber?: number,
	issuingDistributionPoint?: IssuingDistributionPoint,
	freshestCrlDistributionPoints?: readonly DistributionPoint[],
): Promise<Uint8Array[]> {
	const extensions: Uint8Array[] = [];
	if (issuerPublicKey !== undefined) {
		const spki = await exportSpkiDer(issuerPublicKey);
		extensions.push(
			encodeExtension(
				OIDS.authorityKeyIdentifier,
				sequence([implicitPrimitiveContext(0, buildSubjectKeyIdentifier(spki))]),
			),
		);
	}
	if (crlNumber !== undefined) {
		extensions.push(encodeExtension(OIDS.cRLNumber, integerFromNumber(crlNumber)));
	}
	if (baseCrlNumber !== undefined) {
		extensions.push(
			encodeExtension(OIDS.deltaCRLIndicator, integerFromNumber(baseCrlNumber), true),
		);
	}
	if (issuingDistributionPoint !== undefined) {
		extensions.push(
			encodeExtension(
				OIDS.issuingDistributionPoint,
				encodeIssuingDistributionPoint(issuingDistributionPoint),
				true,
			),
		);
	}
	if (freshestCrlDistributionPoints !== undefined && freshestCrlDistributionPoints.length > 0) {
		extensions.push(
			encodeExtension(OIDS.freshestCRL, encodeCrlDistributionPoints(freshestCrlDistributionPoints)),
		);
	}
	return extensions;
}

/** DER-encodes a single revokedCertificate SEQUENCE (serial, date, optional extensions). */
function createRevokedCertificate(entry: RevokedCertificateInput, thisUpdate: Date): Uint8Array {
	const extensions = buildRevokedCertificateExtensions(entry);
	return sequence([
		integer(entry.serialNumber),
		time(entry.revocationDate ?? thisUpdate),
		...(extensions.length === 0 ? [] : [sequence(extensions)]),
	]);
}

/** Encodes CRL entry extensions (reasonCode, invalidityDate). */
function buildRevokedCertificateExtensions(entry: RevokedCertificateInput): Uint8Array[] {
	const extensions: Uint8Array[] = [];
	if (entry.reasonCode !== undefined) {
		extensions.push(
			encodeExtension(
				OIDS.cRLReason,
				tlv(0x0a, Uint8Array.of(REVOCATION_REASON_CODES[entry.reasonCode])),
			),
		);
	}
	if (entry.invalidityDate !== undefined) {
		extensions.push(encodeExtension(OIDS.invalidityDate, generalizedTime(entry.invalidityDate)));
	}
	return extensions;
}

/** Decodes per-entry CRL extensions (reasonCode, invalidityDate, certificateIssuer). */
function parseRevokedCertificateExtensions(
	entryDer: Uint8Array | undefined,
	element: DerElement | undefined,
): {
	readonly reasonCode?: RevocationReason;
	readonly invalidityDate?: Date;
	readonly certificateIssuer?: readonly GeneralName[];
} {
	if (entryDer === undefined || element === undefined) {
		return {};
	}
	const fields: MutableRevokedCertificateExtensionFields = {};
	const seenOids = new Set<string>();
	for (const extension of childrenOf(entryDer, element)) {
		parseRevokedCertificateExtension(entryDer, extension, seenOids, fields);
	}
	return {
		...(fields.reasonCode === undefined ? {} : { reasonCode: fields.reasonCode }),
		...(fields.invalidityDate === undefined ? {} : { invalidityDate: fields.invalidityDate }),
		...(fields.certificateIssuer === undefined
			? {}
			: { certificateIssuer: fields.certificateIssuer }),
	};
}

function parseRevokedCertificateExtension(
	entryDer: Uint8Array,
	extension: DerElement,
	seenOids: Set<string>,
	fields: MutableRevokedCertificateExtensionFields,
): void {
	const parts = childrenOf(entryDer, extension);
	if (parts.length < 2 || parts.length > 3) {
		throw new Error('Malformed revoked certificate extension');
	}
	if (parts.length === 3 && parts[1]?.tag !== 0x01) {
		throw new Error('Malformed revoked certificate extension');
	}
	const oid = decodeObjectIdentifier(
		requireElement(parts[0], 'revoked certificate extension OID').value,
	);
	if (seenOids.has(oid)) {
		throw new Error(`Duplicate revoked certificate extension OID: ${oid}`);
	}
	seenOids.add(oid);
	const valueElement = requireElement(
		parts[parts.length - 1],
		'revoked certificate extension value',
	);
	if (valueElement.tag !== 0x04) {
		throw new Error('Revoked certificate extension value must use OCTET STRING');
	}
	applyRevokedCertificateExtensionValue(oid, valueElement.value, fields);
}

function applyRevokedCertificateExtensionValue(
	oid: string,
	value: Uint8Array,
	fields: MutableRevokedCertificateExtensionFields,
): void {
	if (oid === OIDS.cRLReason) {
		const reasonCode = revocationReasonFromCode(readElement(value).value[0]);
		if (reasonCode !== undefined) fields.reasonCode = reasonCode;
	}
	if (oid === OIDS.invalidityDate) {
		fields.invalidityDate = parseTime(readElement(value));
	}
	if (oid === OIDS.certificateIssuer) {
		const generalNames = readRootElement(value, { maxDepth: DEFAULT_MAX_DER_DEPTH });
		if (generalNames.tag !== 0x30) {
			throw new Error('certificateIssuer must use SEQUENCE');
		}
		fields.certificateIssuer = parseGeneralNames(value, generalNames);
	}
}

/** Decodes the IssuingDistributionPoint extension from its OCTET STRING content. */
function parseIssuingDistributionPoint(valueDer: Uint8Array): ParsedIssuingDistributionPoint {
	const sequenceElement = readRootElement(valueDer, { maxDepth: DEFAULT_MAX_DER_DEPTH });
	const fields: MutableIssuingDistributionPointFields = {};
	for (const child of childrenOf(valueDer, sequenceElement)) {
		parseIssuingDistributionPointField(valueDer, child, fields);
	}
	return {
		...(fields.distributionPoint === undefined
			? {}
			: { distributionPoint: fields.distributionPoint }),
		...(fields.onlySomeReasons === undefined ? {} : { onlySomeReasons: fields.onlySomeReasons }),
		...(fields.indirectCrl === undefined ? {} : { indirectCrl: fields.indirectCrl }),
		...parseIssuingDistributionPointScope(fields),
	};
}

/** RFC 5280 §5.2.5: at most one `onlyContains*` flag may be TRUE. */
function parseIssuingDistributionPointScope(
	fields: MutableIssuingDistributionPointFields,
): ParsedIssuingDistributionPointScope {
	const userCerts = fields.onlyContainsUserCerts;
	const caCerts = fields.onlyContainsCACerts;
	const attributeCerts = fields.onlyContainsAttributeCerts;
	if (userCerts === true) {
		if (caCerts === true || attributeCerts === true) {
			throw new Error(IDP_SCOPE_CONFLICT);
		}
		return { onlyContainsUserCerts: true, ...unselectedScopeFlags({ caCerts, attributeCerts }) };
	}
	if (caCerts === true) {
		if (attributeCerts === true) {
			throw new Error(IDP_SCOPE_CONFLICT);
		}
		return { onlyContainsCACerts: true, ...unselectedScopeFlags({ userCerts, attributeCerts }) };
	}
	if (attributeCerts === true) {
		return { onlyContainsAttributeCerts: true, ...unselectedScopeFlags({ userCerts, caCerts }) };
	}
	return unselectedScopeFlags({ userCerts, caCerts, attributeCerts });
}

/** Keeps the explicit-FALSE flags the encoding carried, omitting the ones it left out. */
function unselectedScopeFlags(flags: {
	readonly userCerts?: false;
	readonly caCerts?: false;
	readonly attributeCerts?: false;
}): {
	readonly onlyContainsUserCerts?: false;
	readonly onlyContainsCACerts?: false;
	readonly onlyContainsAttributeCerts?: false;
} {
	return {
		...(flags.userCerts === undefined ? {} : { onlyContainsUserCerts: flags.userCerts }),
		...(flags.caCerts === undefined ? {} : { onlyContainsCACerts: flags.caCerts }),
		...(flags.attributeCerts === undefined
			? {}
			: { onlyContainsAttributeCerts: flags.attributeCerts }),
	};
}

const IDP_SCOPE_CONFLICT = 'IssuingDistributionPoint scope booleans are mutually exclusive';

function parseIssuingDistributionPointField(
	valueDer: Uint8Array,
	child: DerElement,
	fields: MutableIssuingDistributionPointFields,
): void {
	switch (child.tag) {
		case 0xa0: {
			if (fields.distributionPoint !== undefined) {
				throw new Error('IssuingDistributionPoint distributionPoint must not repeat');
			}
			const distributionPoint = parseDistributionPointName(valueDer, child);
			if (distributionPoint !== undefined) {
				fields.distributionPoint = distributionPoint;
			}
			return;
		}
		case 0x81:
			fields.onlyContainsUserCerts = parseUniqueIssuingDistributionPointBoolean(
				fields.onlyContainsUserCerts,
				child,
				'onlyContainsUserCerts',
			);
			return;
		case 0x82:
			fields.onlyContainsCACerts = parseUniqueIssuingDistributionPointBoolean(
				fields.onlyContainsCACerts,
				child,
				'onlyContainsCACerts',
			);
			return;
		case 0x83:
			if (fields.onlySomeReasons !== undefined) {
				throw new Error('IssuingDistributionPoint onlySomeReasons must not repeat');
			}
			fields.onlySomeReasons = parseDistributionPointReasonFlagsContent(child.value);
			return;
		case 0x84:
			fields.indirectCrl = parseUniqueIssuingDistributionPointBoolean(
				fields.indirectCrl,
				child,
				'indirectCrl',
			);
			return;
		case 0x85:
			fields.onlyContainsAttributeCerts = parseUniqueIssuingDistributionPointBoolean(
				fields.onlyContainsAttributeCerts,
				child,
				'onlyContainsAttributeCerts',
			);
			return;
		default:
			throw new Error(`Unsupported IssuingDistributionPoint field tag: ${String(child.tag)}`);
	}
}

function parseUniqueIssuingDistributionPointBoolean(
	existing: boolean | undefined,
	child: DerElement,
	fieldName: string,
): boolean {
	if (existing !== undefined) {
		throw new Error(`IssuingDistributionPoint ${fieldName} must not repeat`);
	}
	return parseImplicitBoolean(child);
}

/** Decodes a SEQUENCE OF DistributionPoint from DER. */
function parseDistributionPoints(valueDer: Uint8Array): readonly ParsedDistributionPoint[] {
	const sequenceElement = readRootElement(valueDer, { maxDepth: DEFAULT_MAX_DER_DEPTH });
	if (sequenceElement.tag !== 0x30) {
		throw new Error('DistributionPoints must use SEQUENCE');
	}
	const elements = childrenOf(valueDer, sequenceElement);
	if (elements.length === 0) {
		throw new Error('DistributionPoints must not be empty');
	}
	return elements.map((distributionPoint) => parseDistributionPoint(valueDer, distributionPoint));
}

/** Decodes a DistributionPointName (fullName or relativeName). */
function parseDistributionPointName(
	valueDer: Uint8Array,
	element: DerElement,
): ParsedDistributionPointName | undefined {
	const children = childrenOf(valueDer, element);
	if (children.length !== 1) {
		throw new Error('distributionPointName must contain exactly one choice');
	}
	const distributionPointName = requireElement(children[0], 'distributionPointName');
	if (distributionPointName.tag === 0xa0) {
		const fullName = childrenOf(valueDer, distributionPointName);
		if (fullName.length === 0) {
			throw new Error('distributionPointName fullName must not be empty');
		}
		for (const name of fullName) {
			if ((name.tag & 0xc0) !== 0x80) {
				throw new Error('distributionPointName fullName must contain GeneralName entries');
			}
		}
		return {
			type: 'fullName',
			fullName: fullName.map((name) => parseGeneralName(valueDer, name)),
		};
	}
	if (distributionPointName.tag === 0xa1) {
		return {
			type: 'relativeName',
			relativeName: parseRelativeName(valueDer, distributionPointName),
		};
	}
	throw new Error(`Unsupported distributionPointName tag: ${String(distributionPointName.tag)}`);
}

/** Decodes a single DistributionPoint SEQUENCE. */
function parseDistributionPoint(
	valueDer: Uint8Array,
	element: DerElement,
): ParsedDistributionPoint {
	if (element.tag !== 0x30) {
		throw new Error('DistributionPoint must use SEQUENCE');
	}
	const fields: MutableDistributionPointFields = {};
	for (const child of childrenOf(valueDer, element)) {
		parseDistributionPointField(valueDer, child, fields);
	}
	if (fields.distributionPoint === undefined && fields.crlIssuer === undefined) {
		throw new Error('DistributionPoint must include distributionPoint or crlIssuer');
	}
	return {
		...(fields.distributionPoint === undefined
			? {}
			: { distributionPoint: fields.distributionPoint }),
		...(fields.reasons === undefined ? {} : { reasons: fields.reasons }),
		...(fields.crlIssuer === undefined ? {} : { crlIssuer: fields.crlIssuer }),
	};
}

function parseDistributionPointField(
	valueDer: Uint8Array,
	child: DerElement,
	fields: MutableDistributionPointFields,
): void {
	switch (child.tag) {
		case 0xa0: {
			if (fields.distributionPoint !== undefined) {
				throw new Error('DistributionPoint distributionPoint must not repeat');
			}
			const distributionPoint = parseDistributionPointName(valueDer, child);
			if (distributionPoint !== undefined) fields.distributionPoint = distributionPoint;
			return;
		}
		case 0x81:
			if (fields.reasons !== undefined)
				throw new Error('DistributionPoint reasons must not repeat');
			fields.reasons = parseDistributionPointReasonFlagsContent(child.value);
			return;
		case 0xa2:
			if (fields.crlIssuer !== undefined)
				throw new Error('DistributionPoint crlIssuer must not repeat');
			fields.crlIssuer = parseGeneralNames(valueDer, child);
			return;
		default:
			throw new Error(`Unsupported DistributionPoint field tag: ${String(child.tag)}`);
	}
}

/** Decodes a RelativeDistinguishedName SET from an implicitly-tagged context element. */
function parseRelativeName(
	valueDer: Uint8Array,
	element: DerElement,
): ParsedRelativeDistinguishedName {
	const attributes: ParsedNameAttribute[] = [];
	const values: Partial<Record<NameFieldKey, string>> = {};
	for (const attributeSequence of childrenOf(valueDer, element)) {
		const parts = childrenOf(valueDer, attributeSequence);
		const oid = decodeObjectIdentifier(requireElement(parts[0], 'name OID').value);
		const valueElement = requireElement(parts[1], 'name value');
		const fieldKey = nameFieldKeyFromOid(oid);
		const fieldValue = decodeNameValue(valueElement);
		const attribute: ParsedNameAttribute =
			fieldKey === undefined
				? { oid, valueTag: valueElement.tag, value: fieldValue }
				: { oid, key: fieldKey, valueTag: valueElement.tag, value: fieldValue };
		attributes.push(attribute);
		if (fieldKey !== undefined && values[fieldKey] === undefined) {
			values[fieldKey] = fieldValue;
		}
	}
	return {
		derHex: toHex(valueDer.slice(element.start - element.headerLength, element.end)),
		attributes,
		values,
	};
}

/** Decodes an ASN.1 string element (UTF8String, PrintableString, etc.) to a JS string. */
function decodeNameValue(element: DerElement): string {
	return decodeString(element.tag, element.value);
}

/** Reads an implicitly-tagged BOOLEAN from a context element. Absent content → `false`. */
function parseImplicitBoolean(element: DerElement): boolean {
	return (element.value[0] ?? 0) !== 0;
}

/** Machine-readable reason a CRL encoder rejected its construction input. */
export type CrlEncoderErrorCode =
	| 'distribution_point_full_name_empty'
	| 'issuer_distinguished_name_empty';

/** Throws a {@link ResultError} for a CRL encoder input-validation failure. */
function throwCrlEncoderError(code: CrlEncoderErrorCode, message: string): never {
	throwMicro509Error(code, message);
}

/** DER-encodes an IssuingDistributionPoint extension value. Throws on mutually-exclusive scope flags. */
function encodeIssuingDistributionPoint(value: IssuingDistributionPoint): Uint8Array {
	const certificateScopeFlags = [
		value.onlyContainsUserCerts === true,
		value.onlyContainsCACerts === true,
		value.onlyContainsAttributeCerts === true,
	].filter(Boolean).length;
	if (certificateScopeFlags > 1) {
		throw new Error(
			'IssuingDistributionPoint can assert at most one of user, CA, or attribute cert scope',
		);
	}
	const fields: Uint8Array[] = [];
	if (value.distributionPoint !== undefined) {
		fields.push(
			implicitConstructedContext(0, encodeDistributionPointName(value.distributionPoint)),
		);
	}
	if (value.onlyContainsUserCerts) {
		fields.push(implicitPrimitiveContext(1, Uint8Array.of(0xff)));
	}
	if (value.onlyContainsCACerts) {
		fields.push(implicitPrimitiveContext(2, Uint8Array.of(0xff)));
	}
	if (value.onlySomeReasons !== undefined && value.onlySomeReasons.length > 0) {
		fields.push(
			implicitPrimitiveContext(3, encodeDistributionPointReasonFlagsContent(value.onlySomeReasons)),
		);
	}
	if (value.indirectCrl) {
		fields.push(implicitPrimitiveContext(4, Uint8Array.of(0xff)));
	}
	if (value.onlyContainsAttributeCerts) {
		fields.push(implicitPrimitiveContext(5, Uint8Array.of(0xff)));
	}
	return sequence(fields);
}

/** DER-encodes a DistributionPointName (fullName or relativeName). */
function encodeDistributionPointName(
	value: IssuingDistributionPoint['distributionPoint'],
): Uint8Array {
	if (value === undefined) {
		throw new Error('IssuingDistributionPoint distributionPoint is required');
	}
	switch (value.type) {
		case 'fullName': {
			if (value.fullName.length === 0) {
				throwCrlEncoderError(
					'distribution_point_full_name_empty',
					'DistributionPointName fullName must not be empty',
				);
			}
			return implicitConstructedContext(0, concatGeneralNames(value.fullName));
		}
		case 'relativeName': {
			const relativeName = encodeRelativeDistinguishedName(value.relativeName);
			const relativeNameElement = readElement(relativeName);
			return implicitConstructedContext(
				1,
				relativeName.slice(relativeNameElement.start, relativeNameElement.end),
			);
		}
		default: {
			const _exhaustive: never = value;
			throw new Error(`Unhandled DistributionPointName type: ${String(_exhaustive)}`);
		}
	}
}

/** DER-encodes and concatenates a list of GeneralName values. */
function concatGeneralNames(names: readonly GeneralName[]): Uint8Array {
	return concatBytes(names.map((name) => encodeSubjectAltName(name)));
}

/** Parses a Name SEQUENCE element into a full {@linkcode ParsedName}. */
function parseIssuer(source: Uint8Array, element: DerElement): ParsedName {
	const derHex = toHex(source.slice(element.start - element.headerLength, element.end));
	const rdns: ParsedRelativeDistinguishedName[] = [];
	const allAttributes: ParsedNameAttribute[] = [];
	const values: Partial<Record<NameFieldKey, string>> = {};
	for (const setElement of childrenOf(source, element)) {
		const rdnAttributes: ParsedNameAttribute[] = [];
		const rdnValues: Partial<Record<NameFieldKey, string>> = {};
		for (const attrSequence of childrenOf(source, setElement)) {
			const parts = childrenOf(source, attrSequence);
			const oidElement = requireElement(parts[0], 'issuer attribute OID');
			const valueElement = requireElement(parts[1], 'issuer attribute value');
			const oid = decodeObjectIdentifier(oidElement.value);
			let fieldValue: string;
			try {
				fieldValue = decodeString(valueElement.tag, valueElement.value);
			} catch {
				fieldValue = textDecoder.decode(valueElement.value);
			}
			const fieldKey = nameFieldKeyFromOid(oid);
			const attribute: ParsedNameAttribute =
				fieldKey !== undefined
					? { oid, key: fieldKey, valueTag: valueElement.tag, value: fieldValue }
					: { oid, valueTag: valueElement.tag, value: fieldValue };
			rdnAttributes.push(attribute);
			allAttributes.push(attribute);
			if (fieldKey !== undefined) {
				if (rdnValues[fieldKey] === undefined) {
					rdnValues[fieldKey] = fieldValue;
				}
				if (values[fieldKey] === undefined) {
					values[fieldKey] = fieldValue;
				}
			}
		}
		rdns.push({
			derHex: toHex(source.slice(setElement.start - setElement.headerLength, setElement.end)),
			attributes: rdnAttributes,
			values: rdnValues,
		});
	}
	return { derHex, rdns, attributes: allAttributes, values };
}

/** Re-parses a hex-encoded DER Name into a {@linkcode ParsedName}. Returns `undefined` on malformed input. */
function parseDerHexName(hex: string): ParsedName | undefined {
	try {
		const bytes = hexToBytes(hex);
		const root = readRootElement(bytes, { maxDepth: DEFAULT_MAX_DER_DEPTH });
		const element = unwrapNameElement(bytes, root);
		if (element.tag !== 0x30) {
			return undefined;
		}
		return parseIssuer(bytes, element);
	} catch {
		return undefined;
	}
}

function unwrapNameElement(source: Uint8Array, element: DerElement): DerElement {
	if (element.tag !== 0x30) {
		return element;
	}
	const children = childrenOf(source, element);
	const child = children[0];
	if (children.length === 1 && child?.tag === 0x30) {
		return child;
	}
	return element;
}

/** Semantic comparison of a GeneralName directoryName `derHex` against a {@linkcode ParsedName}. */
function directoryNameDerHexMatchesParsedName(derHex: string, name: ParsedName): boolean {
	const parsed = parseDerHexName(derHex);
	if (parsed === undefined) {
		return false;
	}
	return compareDistinguishedNames(parsed, name);
}

/** Extracts the keyIdentifier field from an AuthorityKeyIdentifier extension value. */
function parseAuthorityKeyIdentifier(bytes: Uint8Array): string | undefined {
	const sequenceElement = readRootElement(bytes, {
		maxDepth: DEFAULT_MAX_DER_DEPTH,
		allowOpaqueConstructedTags: [0xa1, 0xa2],
	});
	if (sequenceElement.tag !== 0x30) {
		throw new Error('authorityKeyIdentifier must use SEQUENCE');
	}
	const state: MutableAuthorityKeyIdentifierState = {
		sawAuthorityCertIssuer: false,
		sawAuthorityCertSerialNumber: false,
		lastFieldOrder: -1,
	};
	for (const child of childrenOf(bytes, sequenceElement)) {
		parseAuthorityKeyIdentifierField(bytes, child, state);
	}
	return state.keyIdentifier;
}

function parseAuthorityKeyIdentifierField(
	bytes: Uint8Array,
	child: DerElement,
	state: MutableAuthorityKeyIdentifierState,
): void {
	switch (child.tag) {
		case 0x80:
			parseAuthorityKeyIdentifierKeyId(child, state);
			return;
		case 0xa1:
			parseAuthorityKeyIdentifierIssuer(bytes, child, state);
			return;
		case 0x82:
			parseAuthorityKeyIdentifierSerial(child, state);
			return;
		default:
			throw new Error(`Unsupported authorityKeyIdentifier field tag: ${String(child.tag)}`);
	}
}

function parseAuthorityKeyIdentifierKeyId(
	child: DerElement,
	state: MutableAuthorityKeyIdentifierState,
): void {
	if (state.keyIdentifier !== undefined)
		throw new Error('authorityKeyIdentifier keyIdentifier must not repeat');
	if (state.lastFieldOrder >= 0)
		throw new Error('authorityKeyIdentifier fields must preserve DER order');
	state.keyIdentifier = toHex(child.value);
	state.lastFieldOrder = 0;
}

function parseAuthorityKeyIdentifierIssuer(
	bytes: Uint8Array,
	child: DerElement,
	state: MutableAuthorityKeyIdentifierState,
): void {
	if (state.sawAuthorityCertIssuer) {
		throw new Error('authorityKeyIdentifier authorityCertIssuer must not repeat');
	}
	if (state.lastFieldOrder >= 1)
		throw new Error('authorityKeyIdentifier fields must preserve DER order');
	parseGeneralNames(bytes, child);
	state.sawAuthorityCertIssuer = true;
	state.lastFieldOrder = 1;
}

function parseAuthorityKeyIdentifierSerial(
	child: DerElement,
	state: MutableAuthorityKeyIdentifierState,
): void {
	if (state.sawAuthorityCertSerialNumber) {
		throw new Error('authorityKeyIdentifier authorityCertSerialNumber must not repeat');
	}
	if (state.lastFieldOrder >= 2 || !state.sawAuthorityCertIssuer) {
		throw new Error('authorityKeyIdentifier fields must preserve DER order');
	}
	validateImplicitSerialNumberEncoding(
		child.value,
		'authorityKeyIdentifier authorityCertSerialNumber',
	);
	state.sawAuthorityCertSerialNumber = true;
	state.lastFieldOrder = 2;
}

function validateImplicitSerialNumberEncoding(bytes: Uint8Array, label: string): void {
	const first = bytes[0];
	if (first === undefined) {
		throw new Error(`${label} must not be empty`);
	}
	if ((first & 0x80) !== 0) {
		throw new Error(`${label} must be non-negative`);
	}
	if (bytes.length > 1 && first === 0 && ((bytes[1] ?? 0) & 0x80) === 0) {
		throw new Error(`${label} must use minimal encoding`);
	}
}

/** An AlgorithmIdentifier decoded to its OID and the DER of its parameters. */
interface ParsedCrlAlgorithmIdentifier {
	readonly oid: string;
	readonly parametersDer?: Uint8Array;
}

/** RFC 5280 §5.1.1.2: signatureAlgorithm MUST equal the tbsCertList signature field. */
function assertMatchingCrlSignatureAlgorithms(
	signature: ParsedCrlAlgorithmIdentifier,
	signatureAlgorithm: ParsedCrlAlgorithmIdentifier,
): void {
	if (
		signature.oid !== signatureAlgorithm.oid ||
		!optionalBytesEqual(signature.parametersDer, signatureAlgorithm.parametersDer)
	) {
		throw new Error('CRL signatureAlgorithm must match TBSCertList signature');
	}
}

/** Extracts the algorithm OID from an AlgorithmIdentifier SEQUENCE. */
function parseAlgorithmIdentifier(
	source: Uint8Array,
	element: DerElement,
): ParsedCrlAlgorithmIdentifier {
	const children = childrenOf(source, element);
	const oid = requireElement(children[0], 'algorithm OID');
	const parameters = children[1];
	return parameters === undefined
		? { oid: decodeObjectIdentifier(oid.value) }
		: {
				oid: decodeObjectIdentifier(oid.value),
				parametersDer: source.slice(parameters.start - parameters.headerLength, parameters.end),
			};
}

/** Lowercases a hex string for bytewise serial-number comparison. */
function normalizeHex(value: string): string {
	return value.toLowerCase();
}

/** Maps an integer CRLReason code back to its {@linkcode RevocationReason} string, or `undefined` for unknown codes. */
export function revocationReasonFromCode(code: number | undefined): RevocationReason | undefined {
	switch (code) {
		case 0:
			return 'unspecified';
		case 1:
			return 'keyCompromise';
		case 2:
			return 'cACompromise';
		case 3:
			return 'affiliationChanged';
		case 4:
			return 'superseded';
		case 5:
			return 'cessationOfOperation';
		case 6:
			return 'certificateHold';
		case 8:
			return 'removeFromCRL';
		case 9:
			return 'privilegeWithdrawn';
		case 10:
			return 'aACompromise';
	}
	return undefined;
}

/** Thin wrapper — parses a DER-encoded certificate for use as a CRL issuer. */
function parseIssuerCertificateDer(der: Uint8Array): ParsedCertificate {
	return parseCertificateFromSource(der);
}

/** Thin wrapper — parses a PEM-encoded certificate for use as a CRL issuer. */
function parseIssuerCertificatePem(pem: string): ParsedCertificate {
	return parseCertificateFromSource(pem);
}

/** Accepts PEM, DER, or already-parsed CRL and returns a parsed CRL. */
function normalizeCrl(source: CrlSource): ParsedCertificateRevocationList {
	if (typeof source === 'string') {
		return parseCertificateRevocationListPemOrThrow(source);
	}
	if (source instanceof Uint8Array) {
		return parseCertificateRevocationListDerOrThrow(new Uint8Array(source));
	}
	if (hasReparseableCrlShape(source)) {
		return parseCertificateRevocationListDerOrThrow(new Uint8Array(source.der));
	}
	throw new Error('certificate revocation list input is malformed');
}

function parseSignedCrlFields(tbsCertListDer: Uint8Array): {
	readonly version: number;
	readonly signature: ParsedCrlAlgorithmIdentifier;
	readonly issuer: ParsedName;
	readonly thisUpdate: Date;
	readonly nextUpdate?: Date;
	readonly authorityKeyIdentifier?: string;
	readonly crlNumber?: number;
	readonly baseCrlNumber?: number;
	readonly issuingDistributionPoint?: ParsedIssuingDistributionPoint;
	readonly freshestCrlDistributionPoints?: readonly ParsedDistributionPoint[];
	readonly revokedCertificates: readonly ParsedRevokedCertificate[];
} {
	const tbsCertList = readRootElement(tbsCertListDer, { maxDepth: DEFAULT_MAX_DER_DEPTH });
	const tbsChildren = childrenOf(tbsCertListDer, tbsCertList);
	const versionField = parseCrlVersionField(tbsChildren);
	const version = versionField.version;
	const signatureElement = requireElement(tbsChildren[versionField.nextIndex], 'signature');
	const index = versionField.nextIndex + 1;
	const issuerElement = requireElement(tbsChildren[index], 'issuer');
	const thisUpdateElement = requireElement(tbsChildren[index + 1], 'thisUpdate');
	let cursor = index + 2;
	const maybeNextUpdate = tbsChildren[cursor];
	const nextUpdate =
		maybeNextUpdate !== undefined && (maybeNextUpdate.tag === 0x17 || maybeNextUpdate.tag === 0x18)
			? parseTime(maybeNextUpdate)
			: undefined;
	if (nextUpdate !== undefined) {
		cursor += 1;
	}
	const maybeRevoked = tbsChildren[cursor];
	const revokedCertificates =
		maybeRevoked?.tag === 0x30
			? parseRevokedCertificates(tbsCertListDer, maybeRevoked, version)
			: [];
	if (maybeRevoked?.tag === 0x30) {
		cursor += 1;
	}
	const maybeExtensions = tbsChildren[cursor];
	const parsedExtensions = parseCrlExtensionFields(tbsCertListDer, maybeExtensions, version);
	return {
		version,
		signature: parseAlgorithmIdentifier(tbsCertListDer, signatureElement),
		issuer: parseIssuer(tbsCertListDer, issuerElement),
		thisUpdate: parseTime(thisUpdateElement),
		...(nextUpdate === undefined ? {} : { nextUpdate }),
		...(parsedExtensions.authorityKeyIdentifier === undefined
			? {}
			: { authorityKeyIdentifier: parsedExtensions.authorityKeyIdentifier }),
		...(parsedExtensions.crlNumber === undefined ? {} : { crlNumber: parsedExtensions.crlNumber }),
		...(parsedExtensions.baseCrlNumber === undefined
			? {}
			: { baseCrlNumber: parsedExtensions.baseCrlNumber }),
		...(parsedExtensions.issuingDistributionPoint === undefined
			? {}
			: { issuingDistributionPoint: parsedExtensions.issuingDistributionPoint }),
		...(parsedExtensions.freshestCrlDistributionPoints === undefined
			? {}
			: { freshestCrlDistributionPoints: parsedExtensions.freshestCrlDistributionPoints }),
		revokedCertificates,
	};
}

function parseCrlVersionField(tbsChildren: readonly DerElement[]): ParsedCrlVersionField {
	const firstChild = tbsChildren[0];
	if (firstChild !== undefined && firstChild.tag !== 0x02 && firstChild.tag !== 0x30) {
		throw new Error('version must use INTEGER');
	}
	if (firstChild?.tag !== 0x02) {
		return { version: 1, nextIndex: 0 };
	}
	const version = decodeIntegerNumber(firstChild.value) + 1;
	if (version !== 2) {
		throw new Error(`Unsupported CRL version: ${String(version)}`);
	}
	return { version, nextIndex: 1 };
}

function parseRevokedCertificates(
	tbsCertListDer: Uint8Array,
	revokedSequence: DerElement,
	version: number,
): readonly ParsedRevokedCertificate[] {
	return childrenOf(tbsCertListDer, revokedSequence).map((entry) =>
		parseRevokedCertificateEntry(tbsCertListDer, entry, version),
	);
}

function parseRevokedCertificateEntry(
	tbsCertListDer: Uint8Array,
	entry: DerElement,
	version: number,
): ParsedRevokedCertificate {
	const entryDer = tbsCertListDer.slice(entry.start - entry.headerLength, entry.end);
	const parts = readSequenceChildren(entryDer);
	const serialNumber = requireElement(parts[0], 'revoked serialNumber');
	if (serialNumber.tag !== 0x02) {
		throw new Error('revoked serialNumber must use INTEGER');
	}
	const entryExtensions = parts[2];
	if (entryExtensions !== undefined && version !== 2) {
		throw new Error('revoked certificate extensions require CRL version 2');
	}
	const parsedEntryExtensions = parseRevokedCertificateExtensions(entryDer, entryExtensions);
	return {
		serialNumberHex: toHex(serialNumber.value),
		revocationDate: parseTime(requireElement(parts[1], 'revocationDate')),
		...(parsedEntryExtensions.reasonCode === undefined
			? {}
			: { reasonCode: parsedEntryExtensions.reasonCode }),
		...(parsedEntryExtensions.invalidityDate === undefined
			? {}
			: { invalidityDate: parsedEntryExtensions.invalidityDate }),
		...(parsedEntryExtensions.certificateIssuer === undefined
			? {}
			: { certificateIssuer: parsedEntryExtensions.certificateIssuer }),
	};
}

function parseCrlExtensionFields(
	tbsCertListDer: Uint8Array,
	maybeExtensions: DerElement | undefined,
	version: number,
): ParsedCrlExtensionFields {
	if (maybeExtensions?.tag !== 0xa0) {
		return {};
	}
	if (version !== 2) {
		throw new Error('CRL extensions require version 2');
	}
	const fields: MutableParsedCrlExtensionFields = {};
	const seenOids = new Set<string>();
	const extensionSequence = requireElement(
		childrenOf(tbsCertListDer, maybeExtensions)[0],
		'crl extensions',
	);
	for (const extension of childrenOf(tbsCertListDer, extensionSequence)) {
		parseCrlExtensionField(tbsCertListDer, extension, seenOids, fields);
	}
	return fields;
}

function parseCrlExtensionField(
	tbsCertListDer: Uint8Array,
	extension: DerElement,
	seenOids: Set<string>,
	fields: MutableParsedCrlExtensionFields,
): void {
	const parts = childrenOf(tbsCertListDer, extension);
	if (parts.length < 2 || parts.length > 3) {
		throw new Error('Malformed CRL extension');
	}
	if (parts.length === 3 && parts[1]?.tag !== 0x01) {
		throw new Error('Malformed CRL extension');
	}
	const oid = decodeObjectIdentifier(requireElement(parts[0], 'extension OID').value);
	if (seenOids.has(oid)) {
		throw new Error(`Duplicate CRL extension OID: ${oid}`);
	}
	seenOids.add(oid);
	const critical =
		parts.length === 3
			? decodeBoolean(requireElement(parts[1], 'extension critical').value)
			: false;
	const valueElement = requireElement(parts[parts.length - 1], 'extension value');
	if (valueElement.tag !== 0x04) {
		throw new Error('CRL extension value must use OCTET STRING');
	}
	if (!isSupportedCrlExtensionOid(oid) && critical) {
		throw new Error(`Unsupported critical CRL extension OID: ${oid}`);
	}
	applyParsedCrlExtensionField(oid, valueElement.value, fields);
}

function isSupportedCrlExtensionOid(oid: string): boolean {
	return (
		oid === OIDS.authorityKeyIdentifier ||
		oid === OIDS.cRLNumber ||
		oid === OIDS.deltaCRLIndicator ||
		oid === OIDS.issuingDistributionPoint ||
		oid === OIDS.freshestCRL
	);
}

function applyParsedCrlExtensionField(
	oid: string,
	value: Uint8Array,
	fields: MutableParsedCrlExtensionFields,
): void {
	if (oid === OIDS.authorityKeyIdentifier) {
		const authorityKeyIdentifier = parseAuthorityKeyIdentifier(value);
		if (authorityKeyIdentifier !== undefined) {
			fields.authorityKeyIdentifier = authorityKeyIdentifier;
		}
	}
	if (oid === OIDS.cRLNumber) {
		fields.crlNumber = decodeIntegerNumber(readElement(value).value);
	}
	if (oid === OIDS.deltaCRLIndicator) {
		fields.baseCrlNumber = decodeIntegerNumber(readElement(value).value);
	}
	if (oid === OIDS.issuingDistributionPoint) {
		fields.issuingDistributionPoint = parseIssuingDistributionPoint(value);
	}
	if (oid === OIDS.freshestCRL) {
		fields.freshestCrlDistributionPoints = parseDistributionPoints(value);
	}
}

/** Accepts PEM, DER, or already-parsed certificate and returns a parsed certificate. */
function normalizeCrlCertificate(source: CrlCertificateSource): ParsedCertificate {
	return hasParsedCertificateShape(source)
		? parseCertificateDerOrThrow(new Uint8Array(source.der))
		: parseCertificateFromSource(source);
}

function hasParsedCertificateShape(value: CrlCertificateSource): value is ParsedCertificate {
	return typeof value !== 'string' && 'subjectPublicKeyInfoDer' in value;
}

function hasReparseableCrlShape(
	crl: ParsedCertificateRevocationList,
): crl is ParsedCertificateRevocationList & { readonly der: Uint8Array } {
	return 'der' in crl && crl.der instanceof Uint8Array;
}

/** Shared UTF-8 decoder instance. */
const textDecoder = new TextDecoder();
