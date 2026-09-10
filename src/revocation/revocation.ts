/**
 * Revocation orchestration: evaluates CRL and OCSP evidence to produce a
 * unified `good`/`revoked`/`indeterminate` status for a certificate.
 *
 * @module
 */

import type { Result } from '#micro509/result/result';
import { rethrowIfInvariant } from '#micro509/result/result';
import type {
	CrlApplicabilityFailureReason,
	CrlSource,
	RevocationReason,
} from '#micro509/revocation/crl';
import {
	checkCertificateRevocationAgainstCrl,
	coversAllDistributionPointReasons,
} from '#micro509/revocation/crl';
import type {
	OcspCertificateSource,
	OcspRequestSource,
	ParsedOcspResponse,
} from '#micro509/revocation/ocsp';
import { validateOcspResponse } from '#micro509/revocation/ocsp';
import type { DistributionPointReason } from '#micro509/x509/extensions';
import type { ParsedCertificate } from '#micro509/x509/parse';
import { parseCertificateDerOrThrow, parseCertificateFromSource } from '#micro509/x509/parse';

export type * from '#micro509/revocation/crl';
export type * from '#micro509/revocation/ocsp';

/** Unified revocation outcome across CRL and OCSP evidence. */
export type RevocationStatus = 'good' | 'revoked' | 'indeterminate';

/** Which revocation mechanism produced the evidence. */
export type RevocationEvidenceKind = 'crl' | 'ocsp';
/** PEM string, DER bytes, or already-parsed certificate. */
export type RevocationCertificateSource = string | Uint8Array | ParsedCertificate;
/** Where the OCSP responder URI came from. */
export type OcspResponderSource = 'configured' | 'authorityInfoAccess';
/** PEM or DER bytes of a pre-configured OCSP responder certificate. */
export type ConfiguredOcspResponderCertificate = string | Uint8Array;

/** A manually-configured OCSP responder endpoint. */
export interface ConfiguredOcspResponder {
	/** OCSP responder URI (typically `http://...`). */
	readonly uri: string;
	/** Known responder certificate — skips embedded-certificate discovery. */
	readonly responderCertificate?: ConfiguredOcspResponderCertificate;
}

/** One candidate OCSP responder resolved by {@linkcode resolveOcspResponderCandidates}. */
export interface OcspResponderCandidate {
	/** Whether this candidate came from configuration or the certificate's AIA extension. */
	readonly source: OcspResponderSource;
	/** OCSP responder URI. */
	readonly uri: string;
	/** Pre-known responder certificate, if available. */
	readonly responderCertificate?: ConfiguredOcspResponderCertificate;
}

/** Input for {@linkcode resolveOcspResponderCandidates}. */
export interface ResolveOcspResponderCandidatesInput {
	/** Certificate whose AIA extension will be inspected for OCSP URIs. */
	readonly certificate: RevocationCertificateSource;
	/** Manually-configured responders — checked before AIA-derived ones. */
	readonly configuredResponders?: readonly ConfiguredOcspResponder[];
}

/** CRL-based revocation evidence for {@linkcode CheckCertificateRevocationInput.evidence}. */
export interface RevocationCrlEvidenceInput {
	/** Discriminator for the CRL evidence variant. */
	readonly kind: 'crl';
	/** Complete (base) CRL. */
	readonly crl: CrlSource;
	/** Optional delta CRL for more recent revocation information. */
	readonly deltaCrl?: CrlSource;
}

/** OCSP-based revocation evidence for {@linkcode CheckCertificateRevocationInput.evidence}. */
export interface RevocationOcspEvidenceInput {
	/** Discriminator for the OCSP evidence variant. */
	readonly kind: 'ocsp';
	/** OCSP response to validate. */
	readonly response: string | Uint8Array | ParsedOcspResponse;
	/** Original OCSP request — enables nonce and coverage checks. */
	readonly request?: OcspRequestSource;
	/** Explicit responder certificate — overrides embedded certificate discovery. */
	readonly responderCertificate?: OcspCertificateSource;
}

/** Discriminated union of CRL and OCSP evidence inputs. */
export type RevocationEvidenceInput = RevocationCrlEvidenceInput | RevocationOcspEvidenceInput;

/** Input for {@linkcode checkCertificateRevocation}. */
export interface CheckCertificateRevocationInput {
	/** Certificate whose revocation status to determine. */
	readonly certificate: RevocationCertificateSource;
	/** Issuer of `certificate`. */
	readonly issuerCertificate: RevocationCertificateSource;
	/** CRL and/or OCSP evidence to evaluate. Returns `indeterminate` if empty. */
	readonly evidence?: readonly RevocationEvidenceInput[];
	/** Evaluation time. Defaults to `new Date()`. */
	readonly at?: Date;
	/** Clock-skew tolerance in milliseconds. */
	readonly clockSkewMs?: number;
	/** Maximum age of each CRL's `thisUpdate` in milliseconds. See {@linkcode ValidateCertificateRevocationListInput.maxAgeMs}. */
	readonly crlMaxAgeMs?: number;
}

/** Error codes that {@linkcode checkCertificateRevocation} may surface inside an `indeterminate` result. */
export type CheckCertificateRevocationErrorCode =
	| 'revocation_evidence_missing'
	| 'revocation_status_indeterminate';

/** Every {@linkcode RevocationIndeterminateReasonCode}, as a runtime array. */
export const REVOCATION_INDETERMINATE_REASON_CODES = [
	'certificate_status_missing',
	'certificate_status_unknown',
	'crl_sign_not_permitted',
	'issuer_mismatch',
	'non_applicable',
	'nonce_mismatch',
	'ocsp_signing_missing',
	'reason_coverage_incomplete',
	'request_mismatch',
	'responder_id_mismatch',
	'responder_chain_invalid',
	'responder_revoked',
	'responder_revocation_unknown',
	'response_status_invalid',
	'signature_invalid',
	'stale_crl',
	'stale_response',
] as const;

/** Why a particular piece of evidence could not produce a definitive `good`/`revoked` answer. */
export type RevocationIndeterminateReasonCode =
	(typeof REVOCATION_INDETERMINATE_REASON_CODES)[number];

/** One piece of evidence that failed to produce a definitive revocation answer. */
export interface RevocationIndeterminateEvidence {
	/** Whether this evidence was CRL or OCSP. */
	readonly kind: RevocationEvidenceKind;
	/** Machine-readable reason code. */
	readonly code: RevocationIndeterminateReasonCode;
	/** Human-readable explanation. */
	readonly message: string;
	/** CRL-specific applicability failure reason, when `kind` is `'crl'`. */
	readonly reason?: CrlApplicabilityFailureReason;
}

/** Diagnostic details attached to an `indeterminate` revocation result. */
export interface CheckCertificateRevocationFailureDetails {
	/** Which evidence kinds were attempted (`'crl'`, `'ocsp'`, or both). */
	readonly checkedSources: readonly RevocationEvidenceKind[];
	/** Per-evidence explanations of why no definitive answer was reached. */
	readonly indeterminateEvidence: readonly RevocationIndeterminateEvidence[];
}

/** Revocation status could not be determined from the provided evidence. */
export interface RevocationCheckIndeterminateValue {
	/** Status is indeterminate. */
	readonly status: Extract<RevocationStatus, 'indeterminate'>;
	/** Why revocation status is indeterminate. */
	readonly code: CheckCertificateRevocationErrorCode;
	/** Human-readable diagnostic message. */
	readonly message: string;
	/** What evidence was attempted and why each failed. */
	readonly details: CheckCertificateRevocationFailureDetails;
}

/** Certificate is not revoked according to the checked evidence. */
export interface RevocationCheckGoodValue {
	/** Certificate is not revoked. */
	readonly status: Extract<RevocationStatus, 'good'>;
	/** Which evidence kind confirmed the good status. */
	readonly kind: RevocationEvidenceKind;
	/** Human-readable diagnostic message. */
	readonly message: string;
}

/** Certificate is revoked according to the checked evidence. */
export interface RevocationCheckRevokedValue {
	/** Certificate is revoked. */
	readonly status: Extract<RevocationStatus, 'revoked'>;
	/** Which evidence kind reported the revocation. */
	readonly kind: RevocationEvidenceKind;
	/** Human-readable diagnostic message. */
	readonly message: string;
	/** When the certificate was revoked (from CRL entry or OCSP response). */
	readonly revokedAt?: Date;
	/** CRL reason string (from CRL evidence). */
	readonly revocationReason?: RevocationReason;
	/** CRL reason integer code (from OCSP evidence). */
	readonly revocationReasonCode?: number;
}

/** Discriminated union of `good`, `revoked`, and `indeterminate` revocation outcomes. */
export type CheckCertificateRevocationValue =
	| RevocationCheckGoodValue
	| RevocationCheckRevokedValue
	| RevocationCheckIndeterminateValue;

/**
 * Result of {@linkcode checkCertificateRevocation}. Always succeeds (`ok: true`) —
 * the `value.status` discriminator carries the actual outcome.
 */
export type CheckCertificateRevocationResult = Result<CheckCertificateRevocationValue, never>;

/** Internal intermediate result from evaluating a single piece of revocation evidence. */
type RevocationEvidenceCheck =
	| {
			readonly status: 'good';
			readonly result: RevocationCheckGoodValue;
			/** RFC 5280 §6.3.3(d) reasons this CRL covered; absent for OCSP (which is definitive). */
			readonly coveredReasons?: readonly DistributionPointReason[];
	  }
	| { readonly status: 'revoked'; readonly result: RevocationCheckRevokedValue }
	| { readonly status: 'indeterminate'; readonly detail: RevocationIndeterminateEvidence };

/** Extracts OCSP responder URIs from the certificate's Authority Information Access extension. */
export function getCertificateOcspResponderUris(
	certificate: RevocationCertificateSource,
): readonly string[] {
	let parsedCertificate: ParsedCertificate;
	try {
		parsedCertificate = normalizeCertificate(certificate);
	} catch {
		return [];
	}
	const uris: string[] = [];
	const seen = new Set<string>();
	for (const accessDescription of parsedCertificate.authorityInfoAccess ?? []) {
		if (accessDescription.method !== 'ocsp' || accessDescription.location.type !== 'uri') {
			continue;
		}
		const uri = accessDescription.location.value;
		if (seen.has(uri)) {
			continue;
		}
		seen.add(uri);
		uris.push(uri);
	}
	return uris;
}

/**
 * Merges configured OCSP responders with those discovered from the certificate's
 * AIA extension. Configured responders take priority; duplicates are deduplicated by URI.
 */
export function resolveOcspResponderCandidates(
	input: ResolveOcspResponderCandidatesInput,
): readonly OcspResponderCandidate[] {
	const candidates: OcspResponderCandidate[] = [];
	const configuredByUri = new Map<string, ConfiguredOcspResponder>();
	for (const configuredResponder of input.configuredResponders ?? []) {
		const existing = configuredByUri.get(configuredResponder.uri);
		if (
			existing === undefined ||
			(existing.responderCertificate === undefined &&
				configuredResponder.responderCertificate !== undefined)
		) {
			configuredByUri.set(configuredResponder.uri, configuredResponder);
		}
	}
	const seen = new Set<string>();
	for (const configuredResponder of configuredByUri.values()) {
		seen.add(configuredResponder.uri);
		candidates.push({
			source: 'configured',
			uri: configuredResponder.uri,
			...(configuredResponder.responderCertificate === undefined
				? {}
				: { responderCertificate: configuredResponder.responderCertificate }),
		});
	}
	for (const uri of getCertificateOcspResponderUris(input.certificate)) {
		if (seen.has(uri)) {
			continue;
		}
		seen.add(uri);
		candidates.push({
			source: 'authorityInfoAccess',
			uri,
		});
	}
	return candidates;
}

/**
 * Evaluates all provided CRL and OCSP evidence to determine the certificate's
 * revocation status. Returns the first `revoked` if any, else the first `good`,
 * else `indeterminate` with diagnostic details about each indeterminate evidence.
 *
 * @example
 * ```ts
 * import { checkCertificateRevocation } from 'micro509';
 *
 * const result = await checkCertificateRevocation({
 *   certificate: leafPem,
 *   issuerCertificate: caPem,
 *   evidence: [{ kind: 'crl', crl: crlPem }],
 * });
 * if (result.ok && result.value.status === 'revoked') {
 *   console.log('revoked at', result.value.revokedAt);
 * }
 * ```
 */
export async function checkCertificateRevocation(
	input: CheckCertificateRevocationInput,
): Promise<CheckCertificateRevocationResult> {
	const evidence = input.evidence ?? [];
	const checkedSources = evidence.map((entry) => entry.kind);
	if (evidence.length === 0) {
		return revocationSuccess({
			status: 'indeterminate',
			code: 'revocation_evidence_missing',
			message: 'No CRL or OCSP evidence provided',
			details: {
				checkedSources,
				indeterminateEvidence: [],
			},
		});
	}
	let normalizedCertificate: ParsedCertificate;
	try {
		normalizedCertificate = normalizeCertificate(input.certificate);
	} catch {
		return revocationSuccess({
			status: 'indeterminate',
			code: 'revocation_status_indeterminate',
			message: 'Certificate input is malformed',
			details: {
				checkedSources,
				indeterminateEvidence: [],
			},
		});
	}
	let ocspGoodResult: RevocationCheckGoodValue | undefined;
	let crlGoodResult: RevocationCheckGoodValue | undefined;
	const crlCoveredReasons = new Set<string>();
	const indeterminateEvidence: RevocationIndeterminateEvidence[] = [];
	for (const entry of evidence) {
		const result = await checkRevocationEvidenceEntry(input, entry, normalizedCertificate);
		if (result.status === 'revoked') {
			return revocationSuccess(result.result);
		}
		if (result.status === 'good') {
			if (result.coveredReasons === undefined) {
				ocspGoodResult ??= result.result;
			} else {
				crlGoodResult ??= result.result;
				for (const reason of result.coveredReasons) {
					crlCoveredReasons.add(reason);
				}
			}
			continue;
		}
		indeterminateEvidence.push(result.detail);
	}
	// An OCSP good is per-certificate and definitive. A CRL good is definitive
	// only once the applicable CRLs together cover every revocation reason.
	if (ocspGoodResult !== undefined) {
		return revocationSuccess(ocspGoodResult);
	}
	if (crlGoodResult !== undefined && coversAllDistributionPointReasons(crlCoveredReasons)) {
		return revocationSuccess(crlGoodResult);
	}
	if (crlGoodResult !== undefined) {
		indeterminateEvidence.push({
			kind: 'crl',
			code: 'reason_coverage_incomplete',
			message: 'CRL evidence covers only some revocation reasons',
		});
	}
	return revocationSuccess({
		status: 'indeterminate',
		code: 'revocation_status_indeterminate',
		message: 'No revocation evidence established certificate status',
		details: {
			checkedSources,
			indeterminateEvidence,
		},
	});
}

async function checkRevocationEvidenceEntry(
	input: CheckCertificateRevocationInput,
	evidence: RevocationEvidenceInput,
	certificate: ParsedCertificate,
): Promise<RevocationEvidenceCheck> {
	try {
		return evidence.kind === 'crl'
			? await checkCertificateRevocationWithCrl(input, evidence, certificate)
			: await checkCertificateRevocationWithOcsp(input, evidence, certificate);
	} catch (error) {
		rethrowIfInvariant(error);
		return {
			status: 'indeterminate',
			detail: {
				kind: evidence.kind,
				code: 'signature_invalid',
				message: `${evidence.kind.toUpperCase()} evidence input is malformed`,
			},
		};
	}
}

/** Evaluates a single CRL evidence entry via {@linkcode checkCertificateRevocationAgainstCrl}. */
async function checkCertificateRevocationWithCrl(
	input: CheckCertificateRevocationInput,
	evidence: RevocationCrlEvidenceInput,
	certificate: ParsedCertificate,
): Promise<RevocationEvidenceCheck> {
	const result = await checkCertificateRevocationAgainstCrl({
		certificate,
		issuerCertificate: input.issuerCertificate,
		crl: evidence.crl,
		...(evidence.deltaCrl === undefined ? {} : { deltaCrl: evidence.deltaCrl }),
		...(input.at === undefined ? {} : { at: input.at }),
		...(input.clockSkewMs === undefined ? {} : { clockSkewMs: input.clockSkewMs }),
		...(input.crlMaxAgeMs === undefined ? {} : { maxAgeMs: input.crlMaxAgeMs }),
	});
	if (result.ok) {
		if (result.value.status === 'revoked') {
			return {
				status: 'revoked',
				result: {
					status: 'revoked',
					kind: 'crl',
					message: 'Certificate is revoked according to CRL evidence',
					revokedAt: result.value.revocationDate,
					...(result.value.reasonCode === undefined
						? {}
						: { revocationReason: result.value.reasonCode }),
				},
			};
		}
		return {
			status: 'good',
			result: {
				status: 'good',
				kind: 'crl',
				message: 'Certificate is not revoked according to CRL evidence',
			},
			coveredReasons: result.value.coveredReasons,
		};
	}
	return {
		status: 'indeterminate',
		detail: {
			kind: 'crl',
			code: result.code,
			message: result.message,
			...(result.details?.reason === undefined ? {} : { reason: result.details.reason }),
		},
	};
}

/** Evaluates a single OCSP evidence entry via {@linkcode validateOcspResponse}. */
async function checkCertificateRevocationWithOcsp(
	input: CheckCertificateRevocationInput,
	evidence: RevocationOcspEvidenceInput,
	certificate: ParsedCertificate,
): Promise<RevocationEvidenceCheck> {
	const response = await validateOcspResponse({
		response: evidence.response,
		issuerCertificate: input.issuerCertificate,
		...(evidence.request === undefined ? {} : { request: evidence.request }),
		...(evidence.responderCertificate === undefined
			? {}
			: { responderCertificate: evidence.responderCertificate }),
		...(input.at === undefined ? {} : { at: input.at }),
		...(input.clockSkewMs === undefined ? {} : { clockSkewMs: input.clockSkewMs }),
	});
	if (!response.ok) {
		return {
			status: 'indeterminate',
			detail: {
				kind: 'ocsp',
				code: response.code,
				message: response.message,
			},
		};
	}
	const matchedResponse = response.value.responses?.find(
		(entry) =>
			normalizeHex(entry.certId.serialNumberHex) === normalizeHex(certificate.serialNumberHex),
	);
	if (matchedResponse === undefined) {
		return {
			status: 'indeterminate',
			detail: {
				kind: 'ocsp',
				code: 'certificate_status_missing',
				message: 'OCSP response does not include certificate status for the target certificate',
			},
		};
	}
	if (matchedResponse.certStatus === 'revoked') {
		return {
			status: 'revoked',
			result: {
				status: 'revoked',
				kind: 'ocsp',
				message: 'Certificate is revoked according to OCSP evidence',
				...(matchedResponse.revokedAt === undefined
					? {}
					: { revokedAt: matchedResponse.revokedAt }),
				...(matchedResponse.revocationReasonCode === undefined
					? {}
					: { revocationReasonCode: matchedResponse.revocationReasonCode }),
			},
		};
	}
	if (matchedResponse.certStatus === 'good') {
		return {
			status: 'good',
			result: {
				status: 'good',
				kind: 'ocsp',
				message: 'Certificate is not revoked according to OCSP evidence',
			},
		};
	}
	return {
		status: 'indeterminate',
		detail: {
			kind: 'ocsp',
			code: 'certificate_status_unknown',
			message: 'OCSP responder returned certificate status unknown',
		},
	};
}

/** Accepts PEM, DER, or already-parsed certificate and returns a parsed certificate. */
function normalizeCertificate(certificate: RevocationCertificateSource): ParsedCertificate {
	return hasParsedCertificateShape(certificate)
		? parseCertificateDerOrThrow(new Uint8Array(certificate.der))
		: parseCertificateFromSource(certificate);
}

function hasParsedCertificateShape(value: RevocationCertificateSource): value is ParsedCertificate {
	return typeof value !== 'string' && 'subjectPublicKeyInfoDer' in value;
}

/** Lowercases a hex string for bytewise serial-number comparison. */
function normalizeHex(value: string): string {
	return value.toLowerCase();
}

/** Wraps a value into a successful `CheckCertificateRevocationResult`. */
function revocationSuccess(
	value: CheckCertificateRevocationValue,
): CheckCertificateRevocationResult {
	return { ok: true, value };
}
