import { describe, expect, it } from 'bun:test';
import {
	createCertificate,
	createSelfSignedCertificate,
	generateKeyPair,
	parseCertificatePem,
	type TrustAnchor,
	unwrap,
	verifyCertificateChain,
} from '#micro509';
import type {
	VerifyPathCallbacks,
	VerifyPathSignatureChecks,
} from '#micro509/internal/verify/verify-path';
import {
	buildChainInternal,
	verifyCertificateSignature,
	verifyTrustAnchorSignature,
} from '#micro509/internal/verify/verify-path';
import { indexedMicro509Error } from '#micro509/result/result';

const SHARED_NAME = { commonName: 'Shared Subject CA' } as const;
const VALIDITY = {
	notBefore: new Date('2020-01-01T00:00:00Z'),
	notAfter: new Date('2099-01-01T00:00:00Z'),
};

/**
 * Distinct CA certificates that share one subject and one key, so every
 * candidate-to-candidate edge is a valid signature and the search must explore
 * the whole graph before reporting that nothing anchors.
 */
async function issueSameSubjectCandidates(count: number) {
	const shared = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
	const intermediates: string[] = [];
	for (let index = 1; index <= count; index += 1) {
		const certificate = await createCertificate({
			issuer: SHARED_NAME,
			subject: SHARED_NAME,
			publicKey: shared.publicKey,
			signerPrivateKey: shared.privateKey,
			issuerPublicKey: shared.publicKey,
			serialNumber: Uint8Array.of(1, index),
			validity: VALIDITY,
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		intermediates.push(certificate.pem);
	}
	const leafKeys = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
	const leaf = await createCertificate({
		issuer: SHARED_NAME,
		subject: { commonName: 'same-subject-leaf.example' },
		publicKey: leafKeys.publicKey,
		signerPrivateKey: shared.privateKey,
		issuerPublicKey: shared.publicKey,
		serialNumber: Uint8Array.of(2, 1),
		validity: VALIDITY,
	});
	const unrelatedRoot = await createSelfSignedCertificate({
		subject: { commonName: 'Unrelated Root' },
		algorithm: { kind: 'ecdsa', curve: 'P-256' },
		validity: VALIDITY,
		extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign'] },
	});
	return { leaf: leaf.pem, intermediates, root: unrelatedRoot.certificate.pem };
}

/** A bare anchor whose subject matches the candidates but whose key verifies none of them. */
async function issueDecoyAnchor(): Promise<TrustAnchor> {
	const decoy = await createSelfSignedCertificate({
		subject: SHARED_NAME,
		algorithm: { kind: 'ecdsa', curve: 'P-256' },
		validity: VALIDITY,
		extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign'] },
	});
	const parsed = unwrap(parseCertificatePem(decoy.certificate.pem));
	return {
		subject: parsed.subject,
		subjectPublicKeyInfoDer: parsed.subjectPublicKeyInfoDer,
		publicKeyAlgorithmOid: parsed.publicKeyAlgorithmOid,
		...(parsed.publicKeyParametersOid === undefined
			? {}
			: { publicKeyParametersOid: parsed.publicKeyParametersOid }),
	};
}

const CALLBACKS: VerifyPathCallbacks = {
	failure: (code, message, index, details) => ({
		ok: false,
		...indexedMicro509Error(code, message, index, details),
	}),
	detail: (input) => ({
		...(input.subjectCommonName === undefined
			? {}
			: { subjectCommonName: input.subjectCommonName }),
		...(input.issuerCommonName === undefined ? {} : { issuerCommonName: input.issuerCommonName }),
		...(input.expected === undefined ? {} : { expected: input.expected }),
		...(input.actual === undefined ? {} : { actual: input.actual }),
		...(input.chainCommonNames === undefined ? {} : { chainCommonNames: input.chainCommonNames }),
	}),
};

/** Wraps the real checks so a single search reports how many it performed. */
function countingChecks() {
	const counts = { certificate: 0, trustAnchor: 0 };
	const checks: VerifyPathSignatureChecks = {
		certificate: (certificate, issuer) => {
			counts.certificate += 1;
			return verifyCertificateSignature(certificate, issuer);
		},
		trustAnchor: (certificate, anchor) => {
			counts.trustAnchor += 1;
			return verifyTrustAnchorSignature(certificate, anchor);
		},
	};
	return { counts, checks };
}

describe('path search cost', () => {
	it('verifies each certificate-and-key pair at most once', async () => {
		const candidateCount = 12;
		const anchorCount = 3;
		const { leaf, intermediates, root } = await issueSameSubjectCandidates(candidateCount);
		const anchors = await Promise.all(
			Array.from({ length: anchorCount }, () => issueDecoyAnchor()),
		);
		const parse = (pem: string) => unwrap(parseCertificatePem(pem));
		const { counts, checks } = countingChecks();

		const result = await buildChainInternal(
			parse(leaf),
			intermediates.map(parse),
			[parse(root)],
			anchors,
			VALIDITY.notBefore,
			CALLBACKS,
			checks,
		);

		expect(result.foundTrustedRoot).toBe(false);
		// Every candidate carries the same key, so one check per certificate
		// covers every certificate-to-certificate edge in the graph.
		expect(counts.certificate).toBeLessThanOrEqual(candidateCount + 1);
		// One check per certificate-and-anchor pair, not per visit to a state.
		expect(counts.trustAnchor).toBeLessThanOrEqual((candidateCount + 1) * anchorCount);
	});

	// The timeout is the assertion: before dead ends were memoized per
	// certificate and CA count, this bundle ran for more than ten minutes
	// through the public API. It now settles in well under a second.
	it('terminates on many same-subject CAs sharing one key', async () => {
		const { leaf, intermediates, root } = await issueSameSubjectCandidates(30);

		const result = await verifyCertificateChain({
			leaf,
			intermediates,
			roots: [root],
			at: VALIDITY.notBefore,
		});

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.code).toBe('no_trusted_root');
	}, 5_000);
});
