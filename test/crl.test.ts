import { describe, expect, it } from 'bun:test';
import {
	checkCertificateRevocation,
	checkCertificateRevocationAgainstCrl,
	createCertificate,
	createCertificateRevocationList,
	createSelfSignedCertificate,
	generateKeyPair,
	isCertificateRevoked,
	type ParsedCertificateRevocationList,
	parseCertificatePem,
	parseCertificateRevocationListDer,
	parseCertificateRevocationListDerOrThrow,
	parseCertificateRevocationListPem,
	parseCertificateRevocationListPemOrThrow,
	pemDecodeOrThrow,
	unwrap,
	validateCertificateRevocationList,
	verifyCertificateRevocationListSignature,
} from '#micro509';
import {
	bool,
	explicitContext,
	nullValue,
	objectIdentifier,
	octetString,
	readSequenceChildren,
	sequence,
	setOf,
	tlv,
} from '#micro509/internal/asn1/der';
import { OIDS } from '#micro509/internal/asn1/oids';
import { ALL_DISTRIBUTION_POINT_REASONS } from '#micro509/revocation/crl';
import { encodeSubjectAltName } from '#micro509/x509';
import {
	addRevokedEntryCertificateIssuers,
	childrenOf,
	createCertificateWithRawExtensions,
	decodeObjectIdentifier,
	encodeUncheckedCrlDistributionPoints,
	expectRejectedErrorCode,
	hexToBytes,
	sliceElement,
} from '#test/helpers';

describe('crl', () => {
	it('creates, parses, and verifies CRLs', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'CRL Issuer' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'CRL Issuer' },
			subject: { commonName: 'revoked.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
		});
		const parsedLeaf = unwrap(parseCertificatePem(leaf.pem));
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'CRL Issuer' },
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
			crlNumber: 7,
			revokedCertificates: [{ serialNumber: hexToBytes(parsedLeaf.serialNumberHex) }],
		});
		const parsedCrl = parseCertificateRevocationListPemOrThrow(crl.pem);
		expect(parsedCrl.issuer.values.commonName).toBe('CRL Issuer');
		expect(parsedCrl.crlNumber).toBe(7);
		expect(parsedCrl.signatureAlgorithmName).toBe('ECDSA with SHA-256');
		expect(parsedCrl.revokedCertificates).toHaveLength(1);
		expect(isCertificateRevoked(parsedLeaf.serialNumberHex, parsedCrl)).toBe(true);
		expect(
			await verifyCertificateRevocationListSignature(crl.pem, issuer.certificate.pem),
		).toMatchObject({
			ok: true,
		});

		const wrongSigner = await generateKeyPair();
		const badCrl = await createCertificateRevocationList({
			issuer: { commonName: 'CRL Issuer' },
			signerPrivateKey: wrongSigner.privateKey,
			revokedCertificates: [{ serialNumber: hexToBytes(parsedLeaf.serialNumberHex) }],
		});
		expect(
			await verifyCertificateRevocationListSignature(badCrl.der, issuer.certificate.der),
		).toMatchObject({
			ok: false,
			code: 'signature_invalid',
		});
	});

	it('parses CRL entry extensions and delta CRL indicator', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'Delta CRL Issuer' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Delta CRL Issuer' },
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
			crlNumber: 9,
			baseCrlNumber: 8,
			issuingDistributionPoint: {
				distributionPoint: {
					type: 'fullName',
					fullName: [{ type: 'uri', value: 'http://example.test/idp.crl' }],
				},
				onlyContainsUserCerts: true,
				onlySomeReasons: ['keyCompromise', 'cessationOfOperation'],
				indirectCrl: true,
			},
			freshestCrlDistributionPoints: [
				{
					distributionPoint: {
						type: 'fullName',
						fullName: [{ type: 'uri', value: 'http://example.test/freshest.crl' }],
					},
				},
			],
			revokedCertificates: [
				{
					serialNumber: Uint8Array.of(0x01),
					reasonCode: 'keyCompromise',
					invalidityDate: new Date('2024-01-01T00:00:00Z'),
				},
			],
		});
		const parsed = parseCertificateRevocationListPemOrThrow(crl.pem);
		expect(parsed.baseCrlNumber).toBe(8);
		expect(parsed.issuingDistributionPoint).toEqual({
			distributionPoint: {
				type: 'fullName',
				fullName: [{ type: 'uri', value: 'http://example.test/idp.crl' }],
			},
			onlyContainsUserCerts: true,
			onlySomeReasons: { flags: ['keyCompromise', 'cessationOfOperation'], nonZeroPadding: false },
			indirectCrl: true,
		});
		expect(parsed.freshestCrlDistributionPoints).toEqual([
			{
				distributionPoint: {
					type: 'fullName',
					fullName: [{ type: 'uri', value: 'http://example.test/freshest.crl' }],
				},
			},
		]);
		expect(parsed.revokedCertificates[0]).toMatchObject({
			serialNumberHex: '01',
			reasonCode: 'keyCompromise',
		});
		expect(parsed.revokedCertificates[0]?.invalidityDate?.toISOString()).toBe(
			'2024-01-01T00:00:00.000Z',
		);
	});

	it('parses structured issuing and freshest distribution points', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'Structured CRL Issuer' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const deltaIssuerDnHex = unwrap(parseCertificatePem(issuer.certificate.pem)).subject.derHex;
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Structured CRL Issuer' },
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
			issuingDistributionPoint: {
				distributionPoint: {
					type: 'relativeName',
					relativeName: [
						{ type: 'organizationalUnit', value: 'CRLs' },
						{ type: 'commonName', value: 'ca-scope' },
					],
				},
				onlyContainsCACerts: true,
				onlySomeReasons: ['cACompromise', 'superseded'],
			},
			freshestCrlDistributionPoints: [
				{
					distributionPoint: {
						type: 'fullName',
						fullName: [
							{ type: 'uri', value: 'http://example.test/delta.crl' },
							{ type: 'dns', value: 'delta.example.test' },
						],
					},
					reasons: ['cACompromise'],
					crlIssuer: [{ type: 'directoryName', derHex: deltaIssuerDnHex }],
				},
				{
					distributionPoint: {
						type: 'relativeName',
						relativeName: [{ type: 'commonName', value: 'delta-relative' }],
					},
				},
			],
		});

		const parsed = parseCertificateRevocationListPemOrThrow(crl.pem);
		expect(parsed.issuingDistributionPoint).toMatchObject({
			distributionPoint: {
				type: 'relativeName',
				relativeName: {
					values: {
						organizationalUnit: 'CRLs',
						commonName: 'ca-scope',
					},
				},
			},
			onlyContainsCACerts: true,
			onlySomeReasons: { flags: ['cACompromise', 'superseded'], nonZeroPadding: false },
		});
		expect(parsed.freshestCrlDistributionPoints).toHaveLength(2);
		expect(parsed.freshestCrlDistributionPoints?.[0]).toEqual({
			distributionPoint: {
				type: 'fullName',
				fullName: [
					{ type: 'uri', value: 'http://example.test/delta.crl' },
					{ type: 'dns', value: 'delta.example.test' },
				],
			},
			reasons: { flags: ['cACompromise'], nonZeroPadding: false },
			crlIssuer: [{ type: 'directoryName', derHex: deltaIssuerDnHex }],
		});
		expect(parsed.freshestCrlDistributionPoints?.[1]).toMatchObject({
			distributionPoint: {
				type: 'relativeName',
				relativeName: {
					values: { commonName: 'delta-relative' },
				},
			},
		});
	});

	it('roundtrips issuing distribution points without a named scope', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'Scope Only CRL Issuer' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Scope Only CRL Issuer' },
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
			issuingDistributionPoint: {
				onlyContainsAttributeCerts: true,
				indirectCrl: true,
			},
		});

		const parsed = parseCertificateRevocationListPemOrThrow(crl.pem);
		expect(parsed.issuingDistributionPoint).toEqual({
			onlyContainsAttributeCerts: true,
			indirectCrl: true,
		});
	});

	it('parses CRL general names for email, IP, and unknown tags', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'General Name CRL Issuer' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'General Name CRL Issuer' },
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
			freshestCrlDistributionPoints: [
				{
					distributionPoint: {
						type: 'fullName',
						fullName: [
							{ type: 'email', value: 'pki@example.test' },
							{ type: 'ip', value: '2001:db8::7' },
							{ type: 'unknown', tag: 0x88, value: Uint8Array.of(0xde, 0xad) },
						],
					},
				},
			],
		});

		expect(parseCertificateRevocationListPemOrThrow(crl.pem).freshestCrlDistributionPoints).toEqual(
			[
				{
					distributionPoint: {
						type: 'fullName',
						fullName: [
							{ type: 'email', value: 'pki@example.test' },
							{ type: 'ip', value: '2001:db8:0:0:0:0:0:7' },
							{ type: 'unknown', tag: 0x88, value: Uint8Array.of(0xde, 0xad) },
						],
					},
				},
			],
		);
	});

	it('validates CRL with issuer linkage and freshness', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'CRL Validate CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const otherCa = await createSelfSignedCertificate({
			subject: { commonName: 'Other CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const now = new Date();
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'CRL Validate CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			thisUpdate: now,
			nextUpdate: new Date(now.getTime() + 3_600_000),
		});
		// Valid case
		const valid = await validateCertificateRevocationList({
			crl: crl.pem,
			issuerCertificate: ca.certificate.pem,
			at: now,
		});
		expect(valid.ok).toBe(true);
		// Wrong issuer
		const wrongIssuer = await validateCertificateRevocationList({
			crl: crl.pem,
			issuerCertificate: otherCa.certificate.pem,
			at: now,
		});
		expect(wrongIssuer.ok).toBe(false);
		if (!wrongIssuer.ok) {
			expect(wrongIssuer.code).toBe('issuer_mismatch');
		}
		// Stale CRL (well past nextUpdate)
		const stale = await validateCertificateRevocationList({
			crl: crl.pem,
			issuerCertificate: ca.certificate.pem,
			at: new Date(now.getTime() + 7_200_000),
		});
		expect(stale.ok).toBe(false);
		if (!stale.ok) {
			expect(stale.code).toBe('stale_crl');
		}
		// Barely stale CRL rescued by clock skew tolerance
		// Use 5s margin to avoid ASN.1 second-truncation races
		const staleWithSkew = await validateCertificateRevocationList({
			crl: crl.pem,
			issuerCertificate: ca.certificate.pem,
			at: new Date(now.getTime() + 3_605_000),
			clockSkewMs: 10_000,
		});
		expect(staleWithSkew.ok).toBe(true);
	});

	it('validates CRL with AKI mismatch', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'AKI CRL CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const otherCa = await createSelfSignedCertificate({
			subject: { commonName: 'AKI CRL CA' }, // Same name, different key
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'AKI CRL CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const result = await validateCertificateRevocationList({
			crl: crl.pem,
			issuerCertificate: otherCa.certificate.pem,
		});
		expect(result.ok).toBe(false);
	});

	it('checks CRL distribution-point applicability before revocation lookup', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Scoped CRL CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Scoped CRL CA' },
			subject: { commonName: 'scoped.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				crlDistributionPoints: [
					{
						distributionPoint: {
							type: 'fullName',
							fullName: [{ type: 'uri', value: 'http://example.test/leaf.crl' }],
						},
					},
				],
			},
		});
		const parsedLeaf = unwrap(parseCertificatePem(leaf.pem));
		const matchingCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Scoped CRL CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			issuingDistributionPoint: {
				distributionPoint: {
					type: 'fullName',
					fullName: [{ type: 'uri', value: 'http://example.test/leaf.crl' }],
				},
			},
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: matchingCrl.pem,
			}),
		).toMatchObject({ ok: true, value: { status: 'good' } });

		const mismatchedCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Scoped CRL CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			issuingDistributionPoint: {
				distributionPoint: {
					type: 'fullName',
					fullName: [{ type: 'uri', value: 'http://example.test/other.crl' }],
				},
			},
			revokedCertificates: [{ serialNumber: hexToBytes(parsedLeaf.serialNumberHex) }],
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: parsedLeaf,
				issuerCertificate: ca.certificate.pem,
				crl: mismatchedCrl.pem,
			}),
		).toMatchObject({
			ok: false,
			code: 'non_applicable',
			message: 'certificate distribution points do not match the CRL issuing distribution point',
			details: { reason: 'distribution_point_mismatch' },
		});
	});

	it('checks CRL reason and certificate-type scope', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Reason Scope CA' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 1 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Reason Scope CA' },
			subject: { commonName: 'reason-leaf.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				crlDistributionPoints: [
					{
						distributionPoint: {
							type: 'fullName',
							fullName: [{ type: 'uri', value: 'http://example.test/reasons.crl' }],
						},
						reasons: ['keyCompromise'],
					},
				],
			},
		});
		const parsedLeaf = unwrap(parseCertificatePem(leaf.pem));
		const reasonMismatchCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Reason Scope CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			issuingDistributionPoint: {
				distributionPoint: {
					type: 'fullName',
					fullName: [{ type: 'uri', value: 'http://example.test/reasons.crl' }],
				},
				onlySomeReasons: ['cessationOfOperation'],
			},
			revokedCertificates: [{ serialNumber: hexToBytes(parsedLeaf.serialNumberHex) }],
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: parsedLeaf,
				issuerCertificate: ca.certificate.pem,
				crl: reasonMismatchCrl.pem,
			}),
		).toMatchObject({
			ok: false,
			code: 'non_applicable',
			message: 'certificate distribution point reasons do not overlap the CRL reason scope',
			details: { reason: 'reasons_mismatch' },
		});

		const caKeys = await generateKeyPair();
		const subordinateCa = await createCertificate({
			issuer: { commonName: 'Reason Scope CA' },
			subject: { commonName: 'Subordinate Reason CA' },
			publicKey: caKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
				crlDistributionPoints: [
					{
						distributionPoint: {
							type: 'fullName',
							fullName: [{ type: 'uri', value: 'http://example.test/ca-only.crl' }],
						},
					},
				],
			},
		});
		const caOnlyCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Reason Scope CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			issuingDistributionPoint: {
				distributionPoint: {
					type: 'fullName',
					fullName: [{ type: 'uri', value: 'http://example.test/ca-only.crl' }],
				},
				onlyContainsCACerts: true,
			},
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: parsedLeaf,
				issuerCertificate: ca.certificate.pem,
				crl: caOnlyCrl.pem,
			}),
		).toMatchObject({
			ok: false,
			code: 'non_applicable',
			message: 'CRL only applies to CA certificates',
			details: { reason: 'certificate_scope_mismatch' },
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: subordinateCa.pem,
				issuerCertificate: ca.certificate.pem,
				crl: caOnlyCrl.pem,
			}),
		).toMatchObject({ ok: true, value: { status: 'good' } });
	});

	it('rejects direct CRLs with mismatched issuers and unsupported alternate CRL issuers', async () => {
		const certIssuer = await createSelfSignedCertificate({
			subject: { commonName: 'Certificate Issuer CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crlIssuer = await createSelfSignedCertificate({
			subject: { commonName: 'Different CRL Issuer CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Certificate Issuer CA' },
			subject: { commonName: 'issuer-mismatch.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: certIssuer.keyPair.privateKey,
			issuerPublicKey: certIssuer.keyPair.publicKey,
			extensions: {
				crlDistributionPoints: [
					{
						distributionPoint: {
							type: 'fullName',
							fullName: [{ type: 'uri', value: 'http://example.test/direct.crl' }],
						},
					},
				],
			},
		});
		const mismatchedCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Different CRL Issuer CA' },
			signerPrivateKey: crlIssuer.keyPair.privateKey,
			issuerPublicKey: crlIssuer.keyPair.publicKey,
		});

		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: crlIssuer.certificate.pem,
				crl: mismatchedCrl.pem,
			}),
		).toMatchObject({
			ok: false,
			code: 'non_applicable',
			message: 'CRL issuer does not match certificate issuer for direct CRL processing',
			details: { reason: 'issuer_mismatch' },
		});

		const alternateIssuerLeafKeys = await generateKeyPair();
		const alternateIssuerLeaf = await createCertificateWithRawExtensions({
			issuer: { commonName: 'Certificate Issuer CA' },
			subject: { commonName: 'alternate-crl-issuer.example' },
			publicKey: alternateIssuerLeafKeys.publicKey,
			signerPrivateKey: certIssuer.keyPair.privateKey,
			issuerPublicKey: certIssuer.keyPair.publicKey,
			extensions: {
				customExtensions: [
					{
						oid: OIDS.cRLDistributionPoints,
						value: encodeUncheckedCrlDistributionPoints([
							{
								fullNameUri: 'http://example.test/direct.crl',
								crlIssuer: [{ type: 'dns', value: 'alternate.example.test' }],
							},
						]),
					},
				],
			},
		});
		const directCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Certificate Issuer CA' },
			signerPrivateKey: certIssuer.keyPair.privateKey,
			issuerPublicKey: certIssuer.keyPair.publicKey,
			issuingDistributionPoint: {
				distributionPoint: {
					type: 'fullName',
					fullName: [{ type: 'uri', value: 'http://example.test/direct.crl' }],
				},
			},
		});

		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: alternateIssuerLeaf.pem,
				issuerCertificate: certIssuer.certificate.pem,
				crl: directCrl.pem,
			}),
		).toMatchObject({
			ok: false,
			code: 'non_applicable',
			message:
				'certificate distribution points that name alternate CRL issuers are not supported yet',
			details: { reason: 'unsupported_indirect_crl' },
		});
	});

	it('accepts complete and delta CRLs without issuing distribution points when certificate has DPs', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'No IDP Delta CA' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'No IDP Delta CA' },
			subject: { commonName: 'no-idp-delta.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				crlDistributionPoints: [
					{
						distributionPoint: {
							type: 'fullName',
							fullName: [{ type: 'uri', value: 'http://example.test/no-idp-delta.crl' }],
						},
					},
				],
			},
		});
		const complete = await createCertificateRevocationList({
			issuer: { commonName: 'No IDP Delta CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 2,
		});
		const delta = await createCertificateRevocationList({
			issuer: { commonName: 'No IDP Delta CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 3,
			baseCrlNumber: 2,
		});

		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: complete.pem,
				deltaCrl: delta.pem,
			}),
		).toMatchObject({ ok: true, value: { status: 'good' } });
	});

	it('rejects attribute-only and end-entity-only CRL scopes when the certificate type mismatches', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Scope Mismatch CA' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 1 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Scope Mismatch CA' },
			subject: { commonName: 'attribute-only.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const subordinateCaKeys = await generateKeyPair();
		const subordinateCa = await createCertificate({
			issuer: { commonName: 'Scope Mismatch CA' },
			subject: { commonName: 'Scope Mismatch Subordinate CA' },
			publicKey: subordinateCaKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const attributeOnlyCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Scope Mismatch CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			issuingDistributionPoint: {
				onlyContainsAttributeCerts: true,
			},
		});
		const userOnlyCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Scope Mismatch CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			issuingDistributionPoint: {
				onlyContainsUserCerts: true,
			},
		});

		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: attributeOnlyCrl.pem,
			}),
		).toMatchObject({
			ok: false,
			code: 'non_applicable',
			message: 'attribute-certificate-only CRLs are not applicable to public-key certificates',
			details: { reason: 'certificate_scope_mismatch' },
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: subordinateCa.pem,
				issuerCertificate: ca.certificate.pem,
				crl: userOnlyCrl.pem,
			}),
		).toMatchObject({
			ok: false,
			code: 'non_applicable',
			message: 'CRL only applies to end-entity certificates',
			details: { reason: 'certificate_scope_mismatch' },
		});
	});

	it('accepts a scoped CRL whose IDP names the issuer of a certificate without CRLDP (RFC 5280 §6.3.3)', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Issuer Fallback CA' },
			extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
		});
		const caDnHex = unwrap(parseCertificatePem(ca.certificate.pem)).subject.derHex;
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Issuer Fallback CA' },
			subject: { commonName: 'fallback.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const issuerScopedCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Issuer Fallback CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			issuingDistributionPoint: {
				distributionPoint: {
					type: 'fullName',
					fullName: [{ type: 'directoryName', derHex: caDnHex }],
				},
			},
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: issuerScopedCrl.pem,
			}),
		).toMatchObject({
			ok: true,
			value: { status: 'good', coveredReasons: ALL_DISTRIBUTION_POINT_REASONS },
		});
	});

	it('matches an indirect CRL IDP name against the distribution point cRLIssuer (RFC 5280 §6.3.3 (b)(2)(i))', async () => {
		const issuerCa = await createSelfSignedCertificate({
			subject: { commonName: 'Indirect Cert CA' },
			extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
		});
		const crlCa = await createSelfSignedCertificate({
			subject: { commonName: 'Indirect CRL Issuer' },
			extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
		});
		const crlCaDnHex = unwrap(parseCertificatePem(crlCa.certificate.pem)).subject.derHex;
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Indirect Cert CA' },
			subject: { commonName: 'indirect.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuerCa.keyPair.privateKey,
			issuerPublicKey: issuerCa.keyPair.publicKey,
			extensions: {
				crlDistributionPoints: [{ crlIssuer: [{ type: 'directoryName', derHex: crlCaDnHex }] }],
			},
		});
		const indirectCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Indirect CRL Issuer' },
			signerPrivateKey: crlCa.keyPair.privateKey,
			issuerPublicKey: crlCa.keyPair.publicKey,
			issuingDistributionPoint: {
				distributionPoint: {
					type: 'fullName',
					fullName: [{ type: 'directoryName', derHex: crlCaDnHex }],
				},
				indirectCrl: true,
			},
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: crlCa.certificate.pem,
				crl: indirectCrl.pem,
			}),
		).toMatchObject({ ok: true, value: { status: 'good' } });

		const mismatchedCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Indirect CRL Issuer' },
			signerPrivateKey: crlCa.keyPair.privateKey,
			issuerPublicKey: crlCa.keyPair.publicKey,
			issuingDistributionPoint: {
				distributionPoint: {
					type: 'fullName',
					fullName: [{ type: 'uri', value: 'http://example.test/other.crl' }],
				},
				indirectCrl: true,
			},
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: crlCa.certificate.pem,
				crl: mismatchedCrl.pem,
			}),
		).toMatchObject({
			ok: false,
			code: 'non_applicable',
			details: { reason: 'distribution_point_mismatch' },
		});
	});

	it('limits coveredReasons to the matched distribution point reasons (RFC 5280 §6.3.3 (d))', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Reason Mask CA' },
			extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Reason Mask CA' },
			subject: { commonName: 'reason-mask.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				crlDistributionPoints: [
					{
						distributionPoint: {
							type: 'fullName',
							fullName: [{ type: 'uri', value: 'http://example.test/partial.crl' }],
						},
						reasons: ['keyCompromise', 'cACompromise'],
					},
				],
			},
		});
		const fullScopeCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Reason Mask CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: fullScopeCrl.pem,
			}),
		).toMatchObject({
			ok: true,
			value: { status: 'good', coveredReasons: ['keyCompromise', 'cACompromise'] },
		});

		const scopedCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Reason Mask CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			issuingDistributionPoint: {
				distributionPoint: {
					type: 'fullName',
					fullName: [{ type: 'uri', value: 'http://example.test/partial.crl' }],
				},
				onlySomeReasons: ['cACompromise', 'superseded'],
			},
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: scopedCrl.pem,
			}),
		).toMatchObject({
			ok: true,
			value: { status: 'good', coveredReasons: ['cACompromise'] },
		});
	});

	it('unions coveredReasons across every matching distribution point (RFC 5280 §6.3.3)', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Multi DP CA' },
			extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Multi DP CA' },
			subject: { commonName: 'multi-dp.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				crlDistributionPoints: [
					{
						distributionPoint: {
							type: 'fullName',
							fullName: [{ type: 'uri', value: 'http://example.test/a.crl' }],
						},
						reasons: ['keyCompromise'],
					},
					{
						distributionPoint: {
							type: 'fullName',
							fullName: [{ type: 'uri', value: 'http://example.test/a.crl' }],
						},
						reasons: ['cACompromise'],
					},
				],
			},
		});
		const fullScopeCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Multi DP CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const result = await checkCertificateRevocationAgainstCrl({
			certificate: leaf.pem,
			issuerCertificate: ca.certificate.pem,
			crl: fullScopeCrl.pem,
		});
		expect(result.ok).toBe(true);
		if (!result.ok || result.value.status !== 'good') throw new Error('expected good');
		expect([...result.value.coveredReasons].sort()).toEqual(['cACompromise', 'keyCompromise']);
	});

	it('matches no-CRLDP issuerAltName names case-insensitively (RFC 5280 §7.2)', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'IAN Case CA' },
			extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'IAN Case CA' },
			subject: { commonName: 'ian-case.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				customExtensions: [
					{
						oid: OIDS.issuerAltName,
						value: sequence([encodeSubjectAltName({ type: 'dns', value: 'CRL.EXAMPLE' })]),
					},
				],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'IAN Case CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			issuingDistributionPoint: {
				distributionPoint: { type: 'fullName', fullName: [{ type: 'dns', value: 'crl.example' }] },
			},
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: crl.pem,
			}),
		).toMatchObject({ ok: true, value: { status: 'good' } });
	});

	it('matches SRV-ID distribution point names case-insensitively (RFC 4985 §2)', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'SRV DP CA' },
			extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'SRV DP CA' },
			subject: { commonName: 'srv-dp.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				crlDistributionPoints: [
					{
						distributionPoint: {
							type: 'fullName',
							fullName: [{ type: 'srv', value: '_ldap.crl.example' }],
						},
					},
				],
			},
		});
		for (const idpName of ['_ldap.crl.example', '_LDAP.CRL.EXAMPLE']) {
			const crl = await createCertificateRevocationList({
				issuer: { commonName: 'SRV DP CA' },
				signerPrivateKey: ca.keyPair.privateKey,
				issuerPublicKey: ca.keyPair.publicKey,
				issuingDistributionPoint: {
					distributionPoint: { type: 'fullName', fullName: [{ type: 'srv', value: idpName }] },
				},
			});
			expect(
				await checkCertificateRevocationAgainstCrl({
					certificate: leaf.pem,
					issuerCertificate: ca.certificate.pem,
					crl: crl.pem,
				}),
			).toMatchObject({ ok: true, value: { status: 'good' } });
		}

		const otherCrl = await createCertificateRevocationList({
			issuer: { commonName: 'SRV DP CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			issuingDistributionPoint: {
				distributionPoint: {
					type: 'fullName',
					fullName: [{ type: 'srv', value: '_imaps.crl.example' }],
				},
			},
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: otherCrl.pem,
			}),
		).toMatchObject({
			ok: false,
			code: 'non_applicable',
			details: { reason: 'distribution_point_mismatch' },
		});
	});

	// RFC 5280 §7.4 step 3 decodes unreserved octets, uppercases the remaining
	// triplets, and covers the whole unreserved set; steps 2 and 5 lowercase the
	// host and drop the default port even for a scheme the URL parser treats as
	// opaque; step 1 reduces an IDN host carried as percent-encoded UTF-8 to ACE.
	it.each([
		['http://crl.example/%7Ecerts/a.crl', 'http://crl.example/~certs/a.crl'],
		['http://crl.example/a%2fb.crl', 'http://crl.example/a%2Fb.crl'],
		['http://crl.example/%41%39%2D%2E%5F%7E.crl', 'http://crl.example/A9-._~.crl'],
		['ldap://CRL.EXAMPLE:389/cn=crl', 'ldap://crl.example/cn=crl'],
		['ldap://xn--bcher-kva.example/cn=crl', 'ldap://b%C3%BCcher.example/cn=crl'],
	])('treats %s and %s as the same distribution point', async (certificateUri, crlUri) => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'URI Norm CA' },
			extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'URI Norm CA' },
			subject: { commonName: 'uri-norm.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				crlDistributionPoints: [
					{
						distributionPoint: {
							type: 'fullName',
							fullName: [{ type: 'uri', value: certificateUri }],
						},
					},
				],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'URI Norm CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			issuingDistributionPoint: {
				distributionPoint: { type: 'fullName', fullName: [{ type: 'uri', value: crlUri }] },
			},
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: crl.pem,
			}),
		).toMatchObject({ ok: true, value: { status: 'good' } });
	});

	// `%2F` is reserved, so decoding it would collapse two different paths. The
	// remaining cases cover a non-conformant relative reference, a host whose
	// percent-decoding would change the authority, a host that decodes to an
	// unparseable authority, and a host carrying invalid UTF-8.
	it.each([
		['http://crl.example/a%2Fb.crl', 'http://crl.example/a/b.crl'],
		['http://crl.example/a.crl', 'http://crl.example/b.crl'],
		['ldap://crl.example:390/cn=crl', 'ldap://crl.example/cn=crl'],
		['crl.example/a.crl', 'crl.example/b.crl'],
		['ldap://a%2Fb.example/cn=crl', 'ldap://a%2Fc.example/cn=crl'],
		['ldap://%5B%5D/cn=crl', 'ldap://crl.example/cn=crl'],
		['ldap://a%FF.example/cn=crl', 'ldap://crl.example/cn=crl'],
	])('keeps %s and %s distinct under normalization', async (certificateUri, crlUri) => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'URI Distinct CA' },
			extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'URI Distinct CA' },
			subject: { commonName: 'uri-distinct.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				crlDistributionPoints: [
					{
						distributionPoint: {
							type: 'fullName',
							fullName: [{ type: 'uri', value: certificateUri }],
						},
					},
				],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'URI Distinct CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			issuingDistributionPoint: {
				distributionPoint: { type: 'fullName', fullName: [{ type: 'uri', value: crlUri }] },
			},
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: crl.pem,
			}),
		).toMatchObject({
			ok: false,
			code: 'non_applicable',
			details: { reason: 'distribution_point_mismatch' },
		});
	});

	it('freezes the canonical reason list so results cannot corrupt it', () => {
		expect(Object.isFrozen(ALL_DISTRIBUTION_POINT_REASONS)).toBe(true);
	});

	it('checks CRLs without certificate distribution points and signer permissions', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Full Scope CRL CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Full Scope CRL CA' },
			subject: { commonName: 'full-scope.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const fullScopeCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Full Scope CRL CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: fullScopeCrl.pem,
			}),
		).toMatchObject({
			ok: true,
			value: { status: 'good', coveredReasons: ALL_DISTRIBUTION_POINT_REASONS },
		});

		const reasonScopedCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Full Scope CRL CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			issuingDistributionPoint: {
				onlySomeReasons: ['keyCompromise'],
			},
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: reasonScopedCrl.pem,
			}),
		).toMatchObject({
			ok: true,
			value: { status: 'good', coveredReasons: ['keyCompromise'] },
		});

		const scopedCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Full Scope CRL CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			issuingDistributionPoint: {
				distributionPoint: {
					type: 'fullName',
					fullName: [{ type: 'uri', value: 'http://example.test/scoped.crl' }],
				},
			},
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: scopedCrl.pem,
			}),
		).toMatchObject({
			ok: false,
			code: 'non_applicable',
			details: { reason: 'distribution_point_mismatch' },
		});

		const signerWithoutCrlSign = await createSelfSignedCertificate({
			subject: { commonName: 'No CRL Sign CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign'],
			},
		});
		const noCrlSign = await createCertificateRevocationList({
			issuer: { commonName: 'No CRL Sign CA' },
			signerPrivateKey: signerWithoutCrlSign.keyPair.privateKey,
			issuerPublicKey: signerWithoutCrlSign.keyPair.publicKey,
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: signerWithoutCrlSign.certificate.pem,
				crl: noCrlSign.pem,
			}),
		).toMatchObject({
			ok: false,
			code: 'crl_sign_not_permitted',
			message: 'issuer certificate key usage does not permit CRL signing',
		});

		expect(
			await validateCertificateRevocationList({
				crl: noCrlSign.pem,
				issuerCertificate: signerWithoutCrlSign.certificate.pem,
			}),
		).toMatchObject({
			ok: false,
			code: 'crl_sign_not_permitted',
			message: 'issuer certificate key usage does not permit CRL signing',
		});
	});

	it('reports unsupported indirect and primary delta CRLs as non-applicable', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Unsupported CRL CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Unsupported CRL CA' },
			subject: { commonName: 'unsupported.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				crlDistributionPoints: [
					{
						distributionPoint: {
							type: 'fullName',
							fullName: [{ type: 'uri', value: 'http://example.test/unsupported.crl' }],
						},
					},
				],
			},
		});
		const indirectCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Unsupported CRL CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			issuingDistributionPoint: {
				distributionPoint: {
					type: 'fullName',
					fullName: [{ type: 'uri', value: 'http://example.test/unsupported.crl' }],
				},
				indirectCrl: true,
			},
			revokedCertificates: [
				{ serialNumber: hexToBytes(unwrap(parseCertificatePem(leaf.pem)).serialNumberHex) },
			],
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: indirectCrl.pem,
			}),
		).toMatchObject({
			ok: true,
			value: { status: 'revoked' },
		});

		const unsupportedNamedIssuerCrl = await addRevokedEntryCertificateIssuers(
			indirectCrl.der,
			ca.keyPair.privateKey,
			[
				{
					entryIndex: 0,
					names: [{ type: 'dns', value: 'unsupported.example.test' }],
				},
			],
		);
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: unsupportedNamedIssuerCrl,
			}),
		).toMatchObject({
			ok: false,
			code: 'non_applicable',
			message: 'indirect CRL entry certificateIssuer must include a directoryName',
			details: { reason: 'unsupported_indirect_crl' },
		});

		const deltaCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Unsupported CRL CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			baseCrlNumber: 1,
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: deltaCrl.pem,
			}),
		).toMatchObject({
			ok: false,
			code: 'non_applicable',
			message: 'a delta CRL cannot be used as the primary complete CRL input',
			details: { reason: 'unsupported_delta_crl' },
		});
	});

	it('merges delta CRL revocation entries over the complete CRL view', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Delta Merge CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Delta Merge CA' },
			subject: { commonName: 'delta-merge.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const parsedLeaf = unwrap(parseCertificatePem(leaf.pem));
		const completeCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Delta Merge CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 5,
		});
		const deltaCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Delta Merge CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 6,
			baseCrlNumber: 5,
			revokedCertificates: [
				{
					serialNumber: hexToBytes(parsedLeaf.serialNumberHex),
					reasonCode: 'keyCompromise',
				},
			],
		});

		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: completeCrl.pem,
				deltaCrl: deltaCrl.pem,
			}),
		).toMatchObject({
			ok: true,
			value: { status: 'revoked', reasonCode: 'keyCompromise', crl: { crlNumber: 5 } },
		});
	});

	it('uses removeFromCRL only to clear certificateHold entries from the complete CRL', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Delta Remove CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const heldLeafKeys = await generateKeyPair();
		const heldLeaf = await createCertificate({
			issuer: { commonName: 'Delta Remove CA' },
			subject: { commonName: 'delta-held.example' },
			publicKey: heldLeafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const compromisedLeafKeys = await generateKeyPair();
		const compromisedLeaf = await createCertificate({
			issuer: { commonName: 'Delta Remove CA' },
			subject: { commonName: 'delta-compromised.example' },
			publicKey: compromisedLeafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const expiredLeafKeys = await generateKeyPair();
		const expiredLeaf = await createCertificate({
			issuer: { commonName: 'Delta Remove CA' },
			subject: { commonName: 'delta-expired.example' },
			publicKey: expiredLeafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			validity: {
				notBefore: new Date('2025-01-01T00:00:00Z'),
				notAfter: new Date('2025-01-02T00:00:00Z'),
			},
		});
		const parsedHeldLeaf = unwrap(parseCertificatePem(heldLeaf.pem));
		const parsedCompromisedLeaf = unwrap(parseCertificatePem(compromisedLeaf.pem));
		const parsedExpiredLeaf = unwrap(parseCertificatePem(expiredLeaf.pem));
		const completeCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Delta Remove CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 10,
			thisUpdate: new Date('2025-01-01T00:00:00Z'),
			nextUpdate: new Date('2025-01-10T00:00:00Z'),
			revokedCertificates: [
				{
					serialNumber: hexToBytes(parsedHeldLeaf.serialNumberHex),
					reasonCode: 'certificateHold',
				},
				{
					serialNumber: hexToBytes(parsedCompromisedLeaf.serialNumberHex),
					reasonCode: 'keyCompromise',
				},
				{
					serialNumber: hexToBytes(parsedExpiredLeaf.serialNumberHex),
					reasonCode: 'keyCompromise',
				},
			],
		});
		const deltaCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Delta Remove CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 11,
			baseCrlNumber: 10,
			thisUpdate: new Date('2025-01-02T12:00:00Z'),
			nextUpdate: new Date('2025-01-10T00:00:00Z'),
			revokedCertificates: [
				{
					serialNumber: hexToBytes(parsedHeldLeaf.serialNumberHex),
					reasonCode: 'removeFromCRL',
				},
				{
					serialNumber: hexToBytes(parsedCompromisedLeaf.serialNumberHex),
					reasonCode: 'removeFromCRL',
				},
				{
					serialNumber: hexToBytes(parsedExpiredLeaf.serialNumberHex),
					reasonCode: 'removeFromCRL',
				},
			],
		});

		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: heldLeaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: completeCrl.pem,
				deltaCrl: deltaCrl.pem,
				at: new Date('2025-01-03T00:00:00Z'),
			}),
		).toMatchObject({
			ok: true,
			value: { status: 'good', crl: { crlNumber: 10 } },
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: compromisedLeaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: completeCrl.pem,
				deltaCrl: deltaCrl.pem,
				at: new Date('2025-01-03T00:00:00Z'),
			}),
		).toMatchObject({
			ok: true,
			value: {
				status: 'revoked',
				reasonCode: 'keyCompromise',
				crl: { crlNumber: 10 },
			},
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: expiredLeaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: completeCrl.pem,
				deltaCrl: deltaCrl.pem,
				at: new Date('2025-01-03T00:00:00Z'),
			}),
		).toMatchObject({
			ok: true,
			value: { status: 'good', crl: { crlNumber: 10 } },
		});
	});

	it('rejects stale delta CRLs during merge processing', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Delta Freshness CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Delta Freshness CA' },
			subject: { commonName: 'delta-freshness.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const now = new Date('2026-03-12T12:00:00Z');
		const completeCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Delta Freshness CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 2,
			thisUpdate: new Date('2026-03-12T10:00:00Z'),
			nextUpdate: new Date('2026-03-12T14:00:00Z'),
		});
		const deltaCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Delta Freshness CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 3,
			baseCrlNumber: 2,
			thisUpdate: new Date('2026-03-12T08:00:00Z'),
			nextUpdate: new Date('2026-03-12T09:00:00Z'),
		});

		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: completeCrl.pem,
				deltaCrl: deltaCrl.pem,
				at: now,
			}),
		).toMatchObject({
			ok: false,
			code: 'stale_crl',
			message: 'CRL is not valid at requested time',
		});
	});

	it('rejects delta CRLs whose scope drifts from the complete CRL', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Delta Scope CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Delta Scope CA' },
			subject: { commonName: 'delta-scope.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				crlDistributionPoints: [
					{
						distributionPoint: {
							type: 'fullName',
							fullName: [{ type: 'uri', value: 'http://example.test/delta-scope-a.crl' }],
						},
					},
				],
			},
		});
		const completeCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Delta Scope CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 7,
			issuingDistributionPoint: {
				distributionPoint: {
					type: 'fullName',
					fullName: [{ type: 'uri', value: 'http://example.test/delta-scope-a.crl' }],
				},
			},
		});
		const deltaCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Delta Scope CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 8,
			baseCrlNumber: 7,
			issuingDistributionPoint: {
				distributionPoint: {
					type: 'fullName',
					fullName: [{ type: 'uri', value: 'http://example.test/delta-scope-b.crl' }],
				},
			},
		});

		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: completeCrl.pem,
				deltaCrl: deltaCrl.pem,
			}),
		).toMatchObject({
			ok: false,
			code: 'non_applicable',
			message: 'complete and delta CRLs must share the same issuing distribution point scope',
			details: { reason: 'delta_crl_incompatible' },
		});
	});

	it('rejects incompatible delta CRL number combinations', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Delta Compatibility CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Delta Compatibility CA' },
			subject: { commonName: 'delta-compat.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});

		const completeDelta = await createCertificateRevocationList({
			issuer: { commonName: 'Delta Compatibility CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 8,
			baseCrlNumber: 7,
		});
		const normalDelta = await createCertificateRevocationList({
			issuer: { commonName: 'Delta Compatibility CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 9,
			baseCrlNumber: 8,
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: completeDelta.pem,
				deltaCrl: normalDelta.pem,
			}),
		).toMatchObject({
			ok: false,
			code: 'non_applicable',
			message: 'complete CRL input must not itself be a delta CRL',
			details: { reason: 'delta_crl_incompatible' },
		});

		const complete = await createCertificateRevocationList({
			issuer: { commonName: 'Delta Compatibility CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 8,
		});
		const missingIndicatorDelta = await createCertificateRevocationList({
			issuer: { commonName: 'Delta Compatibility CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 9,
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: complete.pem,
				deltaCrl: missingIndicatorDelta.pem,
			}),
		).toMatchObject({
			ok: false,
			code: 'non_applicable',
			message: 'delta CRL input must include a delta CRL indicator',
			details: { reason: 'delta_crl_incompatible' },
		});

		const tooNewBaseDelta = await createCertificateRevocationList({
			issuer: { commonName: 'Delta Compatibility CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 10,
			baseCrlNumber: 9,
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: complete.pem,
				deltaCrl: tooNewBaseDelta.pem,
			}),
		).toMatchObject({
			ok: false,
			code: 'non_applicable',
			message: 'delta CRL base number must not exceed the complete CRL number',
			details: { reason: 'delta_crl_incompatible' },
		});

		const notNewerDelta = await createCertificateRevocationList({
			issuer: { commonName: 'Delta Compatibility CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 8,
			baseCrlNumber: 8,
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: complete.pem,
				deltaCrl: notNewerDelta.pem,
			}),
		).toMatchObject({
			ok: false,
			code: 'non_applicable',
			message: 'delta CRL number must be newer than the complete CRL number',
			details: { reason: 'delta_crl_incompatible' },
		});
	});

	it('parses revoked entry certificateIssuer extensions', async () => {
		const crlIssuer = await createSelfSignedCertificate({
			subject: { commonName: 'Revoked Entry Parser CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const certificateIssuer = await createSelfSignedCertificate({
			subject: { commonName: 'Revoked Entry Leaf CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const parsedCertificateIssuer = unwrap(parseCertificatePem(certificateIssuer.certificate.pem));
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Revoked Entry Parser CA' },
			signerPrivateKey: crlIssuer.keyPair.privateKey,
			issuerPublicKey: crlIssuer.keyPair.publicKey,
			revokedCertificates: [{ serialNumber: Uint8Array.of(0x01) }],
		});
		const modifiedDer = await addRevokedEntryCertificateIssuers(
			crl.der,
			crlIssuer.keyPair.privateKey,
			[
				{
					entryIndex: 0,
					names: [{ type: 'directoryName', derHex: parsedCertificateIssuer.subject.derHex }],
				},
			],
		);
		expect(
			parseCertificateRevocationListDerOrThrow(modifiedDer).revokedCertificates[0]
				?.certificateIssuer,
		).toEqual([{ type: 'directoryName', derHex: parsedCertificateIssuer.subject.derHex }]);
	});

	it('checks indirect CRL issuer selection and carried certificateIssuer entries', async () => {
		const crlIssuer = await createSelfSignedCertificate({
			subject: { commonName: 'Indirect CRL Issuer' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const firstIssuer = await createSelfSignedCertificate({
			subject: { commonName: 'Indirect Leaf Issuer A' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const secondIssuer = await createSelfSignedCertificate({
			subject: { commonName: 'Indirect Leaf Issuer B' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const parsedCrlIssuer = unwrap(parseCertificatePem(crlIssuer.certificate.pem));
		const parsedFirstIssuer = unwrap(parseCertificatePem(firstIssuer.certificate.pem));
		const sharedSerial = Uint8Array.of(0x44);
		const firstLeafKeys = await generateKeyPair();
		const secondLeafKeys = await generateKeyPair();
		const distributionPoints = [
			{
				distributionPoint: {
					type: 'fullName',
					fullName: [{ type: 'uri', value: 'http://example.test/indirect.crl' }],
				},
				crlIssuer: [{ type: 'directoryName', derHex: parsedCrlIssuer.subject.derHex }],
			},
		] as const;
		const firstLeaf = await createCertificate({
			issuer: { commonName: 'Indirect Leaf Issuer A' },
			subject: { commonName: 'indirect-a.example' },
			publicKey: firstLeafKeys.publicKey,
			signerPrivateKey: firstIssuer.keyPair.privateKey,
			issuerPublicKey: firstIssuer.keyPair.publicKey,
			serialNumber: sharedSerial,
			extensions: { crlDistributionPoints: distributionPoints },
		});
		const secondLeaf = await createCertificate({
			issuer: { commonName: 'Indirect Leaf Issuer B' },
			subject: { commonName: 'indirect-b.example' },
			publicKey: secondLeafKeys.publicKey,
			signerPrivateKey: secondIssuer.keyPair.privateKey,
			issuerPublicKey: secondIssuer.keyPair.publicKey,
			serialNumber: sharedSerial,
			extensions: { crlDistributionPoints: distributionPoints },
		});
		const baseCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Indirect CRL Issuer' },
			signerPrivateKey: crlIssuer.keyPair.privateKey,
			issuerPublicKey: crlIssuer.keyPair.publicKey,
			issuingDistributionPoint: {
				distributionPoint: {
					type: 'fullName',
					fullName: [{ type: 'uri', value: 'http://example.test/indirect.crl' }],
				},
				indirectCrl: true,
			},
			revokedCertificates: [
				{ serialNumber: Uint8Array.of(0x01) },
				{ serialNumber: sharedSerial, reasonCode: 'keyCompromise' },
			],
		});
		const indirectCrlDer = await addRevokedEntryCertificateIssuers(
			baseCrl.der,
			crlIssuer.keyPair.privateKey,
			[
				{
					entryIndex: 0,
					names: [{ type: 'directoryName', derHex: parsedFirstIssuer.subject.derHex }],
				},
			],
		);
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: firstLeaf.pem,
				issuerCertificate: crlIssuer.certificate.pem,
				crl: indirectCrlDer,
			}),
		).toMatchObject({ ok: true, value: { status: 'revoked', reasonCode: 'keyCompromise' } });
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: secondLeaf.pem,
				issuerCertificate: crlIssuer.certificate.pem,
				crl: indirectCrlDer,
			}),
		).toMatchObject({ ok: true, value: { status: 'good' } });
	});

	it('rejects indirect CRLs without matching cRLIssuer distribution points', async () => {
		const crlIssuer = await createSelfSignedCertificate({
			subject: { commonName: 'Indirect Applicability CRL Issuer' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const certificateIssuer = await createSelfSignedCertificate({
			subject: { commonName: 'Indirect Applicability Leaf Issuer' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Indirect Applicability Leaf Issuer' },
			subject: { commonName: 'indirect-applicability.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: certificateIssuer.keyPair.privateKey,
			issuerPublicKey: certificateIssuer.keyPair.publicKey,
			extensions: {
				crlDistributionPoints: [
					{
						distributionPoint: {
							type: 'fullName',
							fullName: [{ type: 'uri', value: 'http://example.test/indirect-applicability.crl' }],
						},
					},
				],
			},
		});
		const indirectCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Indirect Applicability CRL Issuer' },
			signerPrivateKey: crlIssuer.keyPair.privateKey,
			issuerPublicKey: crlIssuer.keyPair.publicKey,
			issuingDistributionPoint: {
				distributionPoint: {
					type: 'fullName',
					fullName: [{ type: 'uri', value: 'http://example.test/indirect-applicability.crl' }],
				},
				indirectCrl: true,
			},
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: crlIssuer.certificate.pem,
				crl: indirectCrl.pem,
			}),
		).toMatchObject({
			ok: false,
			code: 'non_applicable',
			message: 'certificate distribution points do not authorize this indirect CRL issuer',
			details: { reason: 'issuer_mismatch' },
		});
	});

	it('rejects indirect CRLs for alternate issuers when certificate lacks distribution points', async () => {
		const crlIssuer = await createSelfSignedCertificate({
			subject: { commonName: 'Indirect No-DP CRL Issuer' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const certificateIssuer = await createSelfSignedCertificate({
			subject: { commonName: 'Indirect No-DP Certificate Issuer' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Indirect No-DP Certificate Issuer' },
			subject: { commonName: 'indirect-no-dp.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: certificateIssuer.keyPair.privateKey,
			issuerPublicKey: certificateIssuer.keyPair.publicKey,
		});
		const indirectCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Indirect No-DP CRL Issuer' },
			signerPrivateKey: crlIssuer.keyPair.privateKey,
			issuerPublicKey: crlIssuer.keyPair.publicKey,
			issuingDistributionPoint: {
				indirectCrl: true,
			},
		});

		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: crlIssuer.certificate.pem,
				crl: indirectCrl.pem,
			}),
		).toMatchObject({
			ok: false,
			code: 'non_applicable',
			details: { reason: 'issuer_mismatch' },
		});
	});

	it('rejects indirect CRLs when cRLIssuer uses unsupported GeneralName types', async () => {
		const crlIssuer = await createSelfSignedCertificate({
			subject: { commonName: 'Unsupported cRLIssuer CRL Issuer' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const certificateIssuer = await createSelfSignedCertificate({
			subject: { commonName: 'Unsupported cRLIssuer Leaf Issuer' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificateWithRawExtensions({
			issuer: { commonName: 'Unsupported cRLIssuer Leaf Issuer' },
			subject: { commonName: 'unsupported-crl-issuer-name.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: certificateIssuer.keyPair.privateKey,
			issuerPublicKey: certificateIssuer.keyPair.publicKey,
			extensions: {
				customExtensions: [
					{
						oid: OIDS.cRLDistributionPoints,
						value: encodeUncheckedCrlDistributionPoints([
							{
								fullNameUri: 'http://example.test/unsupported-crl-issuer.crl',
								crlIssuer: [{ type: 'dns', value: 'unsupported.example.test' }],
							},
						]),
					},
				],
			},
		});
		const indirectCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Unsupported cRLIssuer CRL Issuer' },
			signerPrivateKey: crlIssuer.keyPair.privateKey,
			issuerPublicKey: crlIssuer.keyPair.publicKey,
			issuingDistributionPoint: {
				distributionPoint: {
					type: 'fullName',
					fullName: [{ type: 'uri', value: 'http://example.test/unsupported-crl-issuer.crl' }],
				},
				indirectCrl: true,
			},
		});

		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: crlIssuer.certificate.pem,
				crl: indirectCrl.pem,
			}),
		).toMatchObject({
			ok: false,
			code: 'non_applicable',
			message: 'indirect CRL distribution points must identify the CRL issuer with directoryName',
			details: { reason: 'unsupported_indirect_crl' },
		});
	});

	it('rejects delta CRL entries with unsupported certificateIssuer names', async () => {
		const crlIssuer = await createSelfSignedCertificate({
			subject: { commonName: 'Delta Unsupported Entry CRL Issuer' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const certificateIssuer = await createSelfSignedCertificate({
			subject: { commonName: 'Delta Unsupported Entry Leaf Issuer' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const parsedCrlIssuer = unwrap(parseCertificatePem(crlIssuer.certificate.pem));
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Delta Unsupported Entry Leaf Issuer' },
			subject: { commonName: 'delta-unsupported-entry.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: certificateIssuer.keyPair.privateKey,
			issuerPublicKey: certificateIssuer.keyPair.publicKey,
			serialNumber: Uint8Array.of(0x55),
			extensions: {
				crlDistributionPoints: [
					{
						distributionPoint: {
							type: 'fullName',
							fullName: [{ type: 'uri', value: 'http://example.test/delta-unsupported-entry.crl' }],
						},
						crlIssuer: [{ type: 'directoryName', derHex: parsedCrlIssuer.subject.derHex }],
					},
				],
			},
		});
		const completeCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Delta Unsupported Entry CRL Issuer' },
			signerPrivateKey: crlIssuer.keyPair.privateKey,
			issuerPublicKey: crlIssuer.keyPair.publicKey,
			crlNumber: 10,
			issuingDistributionPoint: {
				distributionPoint: {
					type: 'fullName',
					fullName: [{ type: 'uri', value: 'http://example.test/delta-unsupported-entry.crl' }],
				},
				indirectCrl: true,
			},
		});
		const deltaBase = await createCertificateRevocationList({
			issuer: { commonName: 'Delta Unsupported Entry CRL Issuer' },
			signerPrivateKey: crlIssuer.keyPair.privateKey,
			issuerPublicKey: crlIssuer.keyPair.publicKey,
			crlNumber: 11,
			baseCrlNumber: 10,
			issuingDistributionPoint: {
				distributionPoint: {
					type: 'fullName',
					fullName: [{ type: 'uri', value: 'http://example.test/delta-unsupported-entry.crl' }],
				},
				indirectCrl: true,
			},
			revokedCertificates: [{ serialNumber: Uint8Array.of(0x55), reasonCode: 'keyCompromise' }],
		});
		const deltaCrl = await addRevokedEntryCertificateIssuers(
			deltaBase.der,
			crlIssuer.keyPair.privateKey,
			[
				{
					entryIndex: 0,
					names: [{ type: 'email', value: 'unsupported@example.test' }],
				},
			],
		);

		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: crlIssuer.certificate.pem,
				crl: completeCrl.pem,
				deltaCrl,
			}),
		).toMatchObject({
			ok: false,
			code: 'non_applicable',
			message: 'indirect CRL entry certificateIssuer must include a directoryName',
			details: { reason: 'unsupported_indirect_crl' },
		});
	});

	it('rejects parsed delta CRLs missing CRL numbers or mismatched authority key identifiers', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Parsed Delta Compatibility CA' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const { subjectKeyIdentifier: _ignoredSubjectKeyIdentifier, ...parsedIssuer } = unwrap(
			parseCertificatePem(ca.certificate.pem),
		);
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Parsed Delta Compatibility CA' },
			subject: { commonName: 'parsed-delta-compat.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				crlDistributionPoints: [
					{
						distributionPoint: {
							type: 'fullName',
							fullName: [{ type: 'uri', value: 'http://example.test/parsed-delta-compat.crl' }],
						},
					},
				],
			},
		});
		const complete = parseCertificateRevocationListPemOrThrow(
			(
				await createCertificateRevocationList({
					issuer: { commonName: 'Parsed Delta Compatibility CA' },
					signerPrivateKey: ca.keyPair.privateKey,
					issuerPublicKey: ca.keyPair.publicKey,
					crlNumber: 4,
					issuingDistributionPoint: {
						distributionPoint: {
							type: 'fullName',
							fullName: [{ type: 'uri', value: 'http://example.test/parsed-delta-compat.crl' }],
						},
					},
				})
			).pem,
		);
		const delta = parseCertificateRevocationListPemOrThrow(
			(
				await createCertificateRevocationList({
					issuer: { commonName: 'Parsed Delta Compatibility CA' },
					signerPrivateKey: ca.keyPair.privateKey,
					issuerPublicKey: ca.keyPair.publicKey,
					crlNumber: 5,
					baseCrlNumber: 4,
					issuingDistributionPoint: {
						distributionPoint: {
							type: 'fullName',
							fullName: [{ type: 'uri', value: 'http://example.test/parsed-delta-compat.crl' }],
						},
					},
				})
			).pem,
		);

		const { crlNumber: _ignoredCompleteCrlNumber, ...completeWithoutCrlNumber } = complete;

		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: parsedIssuer,
				crl: completeWithoutCrlNumber,
				deltaCrl: delta,
			}),
		).toMatchObject({ ok: true, value: { status: 'good' } });

		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: parsedIssuer,
				crl: complete,
				deltaCrl: { ...delta, authorityKeyIdentifier: 'deadbeef' },
			}),
		).toMatchObject({ ok: true, value: { status: 'good' } });
	});

	it('matches complex fullName issuing distribution points across delta compatibility', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Complex IDP CA' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const parsedCa = unwrap(parseCertificatePem(ca.certificate.pem));
		const complexNames = [
			{ type: 'dns', value: 'crl.example.test' },
			{ type: 'email', value: 'pki@example.test' },
			{ type: 'ip', value: '2001:db8::7' },
			{ type: 'uri', value: 'http://example.test/complex-idp.crl' },
			{ type: 'directoryName', derHex: parsedCa.subject.derHex },
			{ type: 'unknown', tag: 0x88, value: Uint8Array.of(0xde, 0xad) },
		] as const;
		const shuffledNames = [
			complexNames[3],
			complexNames[1],
			complexNames[0],
			complexNames[5],
			complexNames[4],
			complexNames[2],
		].flatMap((value) => (value === undefined ? [] : [value]));
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Complex IDP CA' },
			subject: { commonName: 'complex-idp.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				crlDistributionPoints: [
					{
						distributionPoint: {
							type: 'fullName',
							fullName: [{ type: 'uri', value: 'http://example.test/complex-idp.crl' }],
						},
					},
				],
			},
		});
		const complete = parseCertificateRevocationListPemOrThrow(
			(
				await createCertificateRevocationList({
					issuer: { commonName: 'Complex IDP CA' },
					signerPrivateKey: ca.keyPair.privateKey,
					issuerPublicKey: ca.keyPair.publicKey,
					crlNumber: 12,
					issuingDistributionPoint: {
						distributionPoint: { type: 'fullName', fullName: complexNames },
					},
				})
			).pem,
		);
		const delta = parseCertificateRevocationListPemOrThrow(
			(
				await createCertificateRevocationList({
					issuer: { commonName: 'Complex IDP CA' },
					signerPrivateKey: ca.keyPair.privateKey,
					issuerPublicKey: ca.keyPair.publicKey,
					crlNumber: 13,
					baseCrlNumber: 12,
					issuingDistributionPoint: {
						distributionPoint: { type: 'fullName', fullName: shuffledNames },
					},
				})
			).pem,
		);

		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: complete,
				deltaCrl: delta,
			}),
		).toMatchObject({ ok: true, value: { status: 'good' } });
	});

	it('rejects delta CRLs when fullName unknown bytes or reason sets differ', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Complex IDP Mismatch CA' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const parsedCa = unwrap(parseCertificatePem(ca.certificate.pem));
		const names = [
			{ type: 'uri', value: 'http://example.test/complex-idp-mismatch.crl' },
			{ type: 'directoryName', derHex: parsedCa.subject.derHex },
			{ type: 'unknown', tag: 0x88, value: Uint8Array.of(0xde, 0xad) },
		] as const;
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Complex IDP Mismatch CA' },
			subject: { commonName: 'complex-idp-mismatch.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				crlDistributionPoints: [
					{
						distributionPoint: {
							type: 'fullName',
							fullName: [{ type: 'uri', value: 'http://example.test/complex-idp-mismatch.crl' }],
						},
					},
				],
			},
		});
		const complete = parseCertificateRevocationListPemOrThrow(
			(
				await createCertificateRevocationList({
					issuer: { commonName: 'Complex IDP Mismatch CA' },
					signerPrivateKey: ca.keyPair.privateKey,
					issuerPublicKey: ca.keyPair.publicKey,
					crlNumber: 20,
					issuingDistributionPoint: {
						distributionPoint: { type: 'fullName', fullName: names },
						onlySomeReasons: ['keyCompromise'],
					},
				})
			).pem,
		);
		const delta = parseCertificateRevocationListPemOrThrow(
			(
				await createCertificateRevocationList({
					issuer: { commonName: 'Complex IDP Mismatch CA' },
					signerPrivateKey: ca.keyPair.privateKey,
					issuerPublicKey: ca.keyPair.publicKey,
					crlNumber: 21,
					baseCrlNumber: 20,
					issuingDistributionPoint: {
						distributionPoint: {
							type: 'fullName',
							fullName: [
								{ type: 'uri', value: 'http://example.test/complex-idp-mismatch.crl' },
								{ type: 'directoryName', derHex: parsedCa.subject.derHex },
								{ type: 'unknown', tag: 0x88, value: Uint8Array.of(0xde, 0xae) },
							],
						},
						onlySomeReasons: ['keyCompromise', 'cessationOfOperation'],
					},
				})
			).pem,
		);

		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: complete,
				deltaCrl: delta,
			}),
		).toMatchObject({
			ok: false,
			code: 'non_applicable',
			message: 'complete and delta CRLs must share the same issuing distribution point scope',
			details: { reason: 'delta_crl_incompatible' },
		});
	});

	it('matches relativeName issuing distribution points with normalized DirectoryString values', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Relative Name Delta CA' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Relative Name Delta CA' },
			subject: { commonName: 'relative-name-delta.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				crlDistributionPoints: [
					{
						distributionPoint: {
							type: 'relativeName',
							relativeName: [{ type: 'commonName', value: 'team alpha' }],
						},
					},
				],
			},
		});
		const complete = parseCertificateRevocationListPemOrThrow(
			(
				await createCertificateRevocationList({
					issuer: { commonName: 'Relative Name Delta CA' },
					signerPrivateKey: ca.keyPair.privateKey,
					issuerPublicKey: ca.keyPair.publicKey,
					crlNumber: 30,
					issuingDistributionPoint: {
						distributionPoint: {
							type: 'relativeName',
							relativeName: [{ type: 'commonName', value: ' Team   Alpha ' }],
						},
					},
				})
			).pem,
		);
		const delta = parseCertificateRevocationListPemOrThrow(
			(
				await createCertificateRevocationList({
					issuer: { commonName: 'Relative Name Delta CA' },
					signerPrivateKey: ca.keyPair.privateKey,
					issuerPublicKey: ca.keyPair.publicKey,
					crlNumber: 31,
					baseCrlNumber: 30,
					issuingDistributionPoint: {
						distributionPoint: {
							type: 'relativeName',
							relativeName: [{ type: 'commonName', value: 'TEAM ALPHA' }],
						},
					},
				})
			).pem,
		);

		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: complete,
				deltaCrl: delta,
			}),
		).toMatchObject({ ok: true, value: { status: 'good' } });

		const issuingDistributionPoint = delta.issuingDistributionPoint;
		const distributionPoint = issuingDistributionPoint?.distributionPoint;
		if (issuingDistributionPoint === undefined || distributionPoint?.type !== 'relativeName') {
			throw new Error('Expected relativeName issuing distribution point');
		}
		const relativeName = distributionPoint.relativeName;
		const poisonedDelta: ParsedCertificateRevocationList = {
			...delta,
			issuingDistributionPoint: {
				...issuingDistributionPoint,
				distributionPoint: {
					...distributionPoint,
					relativeName: {
						...relativeName,
						attributes: relativeName.attributes.map((attribute, index) =>
							index === 0 ? { ...attribute, value: 'TEAM\u0001ALPHA' } : attribute,
						),
						values: { ...relativeName.values, commonName: 'TEAM\u0001ALPHA' },
					},
				},
			},
		};

		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: complete,
				deltaCrl: poisonedDelta,
			}),
		).toMatchObject({ ok: true, value: { status: 'good' } });
	});

	it('treats indirect CRL entries without certificateIssuer as issuer mismatches', async () => {
		const crlIssuer = await createSelfSignedCertificate({
			subject: { commonName: 'Entry Mismatch CRL Issuer' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const certificateIssuer = await createSelfSignedCertificate({
			subject: { commonName: 'Entry Mismatch Leaf Issuer' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const parsedCrlIssuer = unwrap(parseCertificatePem(crlIssuer.certificate.pem));
		const leafKeys = await generateKeyPair();
		const sharedSerial = Uint8Array.of(0x66);
		const leaf = await createCertificate({
			issuer: { commonName: 'Entry Mismatch Leaf Issuer' },
			subject: { commonName: 'entry-mismatch.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: certificateIssuer.keyPair.privateKey,
			issuerPublicKey: certificateIssuer.keyPair.publicKey,
			serialNumber: sharedSerial,
			extensions: {
				crlDistributionPoints: [
					{
						distributionPoint: {
							type: 'fullName',
							fullName: [{ type: 'uri', value: 'http://example.test/entry-mismatch.crl' }],
						},
						crlIssuer: [{ type: 'directoryName', derHex: parsedCrlIssuer.subject.derHex }],
					},
				],
			},
		});
		const indirectCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Entry Mismatch CRL Issuer' },
			signerPrivateKey: crlIssuer.keyPair.privateKey,
			issuerPublicKey: crlIssuer.keyPair.publicKey,
			issuingDistributionPoint: {
				distributionPoint: {
					type: 'fullName',
					fullName: [{ type: 'uri', value: 'http://example.test/entry-mismatch.crl' }],
				},
				indirectCrl: true,
			},
			revokedCertificates: [{ serialNumber: sharedSerial, reasonCode: 'keyCompromise' }],
		});

		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: crlIssuer.certificate.pem,
				crl: indirectCrl.pem,
			}),
		).toMatchObject({ ok: true, value: { status: 'good' } });
	});

	it('creates CRL with all revocation reason codes', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Reason CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const reasons = [
			'unspecified',
			'keyCompromise',
			'cACompromise',
			'affiliationChanged',
			'superseded',
			'cessationOfOperation',
			'certificateHold',
			'removeFromCRL',
			'privilegeWithdrawn',
			'aACompromise',
		] as const;
		const revokedCerts = reasons.map((reason, index) => ({
			serialNumber: Uint8Array.of(index + 1),
			reasonCode: reason,
		}));
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Reason CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			revokedCertificates: revokedCerts,
		});
		const parsed = parseCertificateRevocationListPemOrThrow(crl.pem);
		expect(parsed.revokedCertificates).toHaveLength(reasons.length);
		for (let i = 0; i < reasons.length; i++) {
			expect(parsed.revokedCertificates[i]?.reasonCode).toBe(reasons[i]);
		}
	});

	it('validates CRL with DER sources', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'DER CRL CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const now = new Date();
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'DER CRL CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			thisUpdate: now,
			nextUpdate: new Date(now.getTime() + 3_600_000),
		});
		const caDer = new Uint8Array(pemDecodeOrThrow('CERTIFICATE', ca.certificate.pem));
		// Use DER for both CRL and issuer
		const result = await validateCertificateRevocationList({
			crl: crl.der,
			issuerCertificate: caDer,
			at: now,
		});
		expect(result.ok).toBe(true);
	});

	it('validates CRL with pre-parsed sources', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Parsed CRL CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const now = new Date();
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Parsed CRL CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			thisUpdate: now,
			nextUpdate: new Date(now.getTime() + 3_600_000),
		});
		const parsedCrl = parseCertificateRevocationListPemOrThrow(crl.pem);
		const parsedCa = unwrap(parseCertificatePem(ca.certificate.pem));
		const result = await validateCertificateRevocationList({
			crl: parsedCrl,
			issuerCertificate: parsedCa,
			at: now,
		});
		expect(result.ok).toBe(true);
	});

	it('validateCertificateRevocationList ignores tampered signed content fields on pre-parsed CRL input', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Malformed Parsed CRL Validate CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Malformed Parsed CRL Validate CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const parsedCrl = parseCertificateRevocationListPemOrThrow(crl.pem);
		const parsedCa = unwrap(parseCertificatePem(ca.certificate.pem));
		const tamperedCrl = { ...parsedCrl, tbsCertListDer: Uint8Array.of(0x30, 0x80) };

		const result = await validateCertificateRevocationList({
			crl: tamperedCrl,
			issuerCertificate: parsedCa,
		});
		expect(result.ok).toBe(true);
	});

	it('validateCertificateRevocationList fails closed for pre-parsed CRL input without DER', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'DER-less Parsed CRL Validate CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'DER-less Parsed CRL Validate CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const parsedCrl = parseCertificateRevocationListPemOrThrow(crl.pem);
		const { der: _ignoredDer, ...parsedCrlWithoutDer } = parsedCrl;

		const result = await validateCertificateRevocationList({
			crl: parsedCrlWithoutDer,
			issuerCertificate: ca.certificate.pem,
		});
		expect(result).toMatchObject({ ok: false, code: 'signature_invalid' });
	});

	it('validateCertificateRevocationList fails closed for malformed issuer certificate input', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Malformed Validate Issuer CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Malformed Validate Issuer CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const result = await validateCertificateRevocationList({
			crl: crl.pem,
			issuerCertificate: Uint8Array.of(0xff, 0xff),
		});
		expect(result).toMatchObject({ ok: false, code: 'signature_invalid' });
	});

	it('validateCertificateRevocationList ignores tampered parsed issuer certificate fields', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Tampered Parsed Validate Issuer CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Tampered Parsed Validate Issuer CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const parsedCa = unwrap(parseCertificatePem(ca.certificate.pem));
		const tamperedCa = {
			...parsedCa,
			keyUsage: { flags: [], nonZeroPadding: false },
			subjectPublicKeyInfoDer: Uint8Array.of(0x30, 0x00),
		};

		const result = await validateCertificateRevocationList({
			crl: crl.pem,
			issuerCertificate: tamperedCa,
		});
		expect(result.ok).toBe(true);
	});

	it('checkCertificateRevocationAgainstCrl ignores tampered revoked entries on pre-parsed CRL input', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Tampered Parsed CRL CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Tampered Parsed CRL CA' },
			subject: { commonName: 'tampered-parsed-crl.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const parsedLeaf = unwrap(parseCertificatePem(leaf.pem));
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Tampered Parsed CRL CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const parsedCrl = parseCertificateRevocationListPemOrThrow(crl.pem);
		const future = new Date('2999-01-01T00:00:00Z');
		const tamperedCrl = {
			...parsedCrl,
			thisUpdate: future,
			revokedCertificates: [
				{
					serialNumberHex: parsedLeaf.serialNumberHex,
					revocationDate: future,
					reasonCode: 'keyCompromise' as const,
				},
			],
		};

		const result = await checkCertificateRevocationAgainstCrl({
			certificate: leaf.pem,
			issuerCertificate: ca.certificate.pem,
			crl: tamperedCrl,
		});
		expect(result).toMatchObject({ ok: true, value: { status: 'good' } });
	});

	it('checkCertificateRevocationAgainstCrl ignores tampered signed content fields on pre-parsed CRL input', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Malformed Parsed CRL Check CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Malformed Parsed CRL Check CA' },
			subject: { commonName: 'malformed-parsed-crl-check.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Malformed Parsed CRL Check CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const parsedCrl = parseCertificateRevocationListPemOrThrow(crl.pem);
		const tamperedCrl = { ...parsedCrl, tbsCertListDer: Uint8Array.of(0x30, 0x80) };

		const result = await checkCertificateRevocationAgainstCrl({
			certificate: leaf.pem,
			issuerCertificate: ca.certificate.pem,
			crl: tamperedCrl,
		});
		expect(result).toMatchObject({ ok: true, value: { status: 'good' } });
	});

	it('checkCertificateRevocationAgainstCrl fails closed for malformed certificate input', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Malformed Target Cert CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Malformed Target Cert CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const result = await checkCertificateRevocationAgainstCrl({
			certificate: Uint8Array.of(0xff, 0xff),
			issuerCertificate: ca.certificate.pem,
			crl: crl.pem,
		});
		expect(result).toMatchObject({ ok: false, code: 'non_applicable' });
	});

	it('checkCertificateRevocationAgainstCrl rejects duplicate revoked entries for the same certificate', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Duplicate Revoked Entry CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Duplicate Revoked Entry CA' },
			subject: { commonName: 'duplicate-revoked-entry-check.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const parsedLeaf = unwrap(parseCertificatePem(leaf.pem));
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Duplicate Revoked Entry CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			revokedCertificates: [
				{ serialNumber: hexToBytes(parsedLeaf.serialNumberHex) },
				{ serialNumber: hexToBytes(parsedLeaf.serialNumberHex) },
			],
		});
		const result = await checkCertificateRevocationAgainstCrl({
			certificate: leaf.pem,
			issuerCertificate: ca.certificate.pem,
			crl: crl.pem,
		});
		expect(result).toMatchObject({ ok: false, code: 'signature_invalid' });
	});

	it('verifyCertificateRevocationListSignature rejects CRL signed by wrong key', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'CRL CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const otherCa = await createSelfSignedCertificate({
			subject: { commonName: 'CRL CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		// Sign CRL with ca but verify with otherCa (same subject, different key)
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'CRL CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const result = await verifyCertificateRevocationListSignature(crl.pem, otherCa.certificate.pem);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('signature_invalid');
	});

	it('verifyCertificateRevocationListSignature fails closed for malformed issuer certificate input', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Malformed Verify Issuer CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Malformed Verify Issuer CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const result = await verifyCertificateRevocationListSignature(
			crl.pem,
			Uint8Array.of(0xff, 0xff),
		);
		expect(result).toMatchObject({ ok: false, code: 'signature_invalid' });
	});

	it('validateCertificateRevocationList rejects signature with wrong key', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'CRL Validate CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const otherCa = await createSelfSignedCertificate({
			subject: { commonName: 'CRL Validate CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		// Create CRL without AKI to bypass AKI check, signed by ca
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'CRL Validate CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			// omit issuerPublicKey → no AKI extension
		});
		const result = await validateCertificateRevocationList({
			crl: crl.pem,
			issuerCertificate: otherCa.certificate.pem,
		});
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('signature_invalid');
	});

	it('rejects empty issuing distribution point fullName values', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'Bad Scope CRL Issuer' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});

		await expectRejectedErrorCode(
			createCertificateRevocationList({
				issuer: { commonName: 'Bad Scope CRL Issuer' },
				signerPrivateKey: issuer.keyPair.privateKey,
				issuerPublicKey: issuer.keyPair.publicKey,
				issuingDistributionPoint: {
					distributionPoint: {
						type: 'fullName',
						fullName: [],
					},
				},
			}),
			'distribution_point_full_name_empty',
		);
	});

	it('rejects empty freshest CRL issuer lists', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'Bad Freshest CRL Issuer' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});

		await expectRejectedErrorCode(
			createCertificateRevocationList({
				issuer: { commonName: 'Bad Freshest CRL Issuer' },
				signerPrivateKey: issuer.keyPair.privateKey,
				issuerPublicKey: issuer.keyPair.publicKey,
				freshestCrlDistributionPoints: [{ crlIssuer: [] }],
			}),
			'distribution_point_crl_issuer_empty',
		);
	});

	it('verifies CRL with PEM string sources', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'PEM CRL CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'PEM CRL CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const result = await verifyCertificateRevocationListSignature(crl.pem, ca.certificate.pem);
		expect(result.ok).toBe(true);
	});

	it('parseCertificateRevocationListDerOrThrow rejects IDP with unsupported dist point name tags', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'IDP CRL CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		// Create CRL with IDP extension
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'IDP CRL CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			issuingDistributionPoint: {
				distributionPoint: {
					type: 'fullName',
					fullName: [{ type: 'uri', value: 'http://crl.example.com/crl.pem' }],
				},
			},
		});
		const derBytes = new Uint8Array(pemDecodeOrThrow('X509 CRL', crl.pem));
		// Find the IDP OID bytes (2.5.29.28 = 55 1D 1C) in the CRL DER
		const idpOidBytes = [0x55, 0x1d, 0x1c];
		let idpOffset = -1;
		for (let i = 0; i < derBytes.length - 3; i++) {
			if (
				derBytes[i] === idpOidBytes[0] &&
				derBytes[i + 1] === idpOidBytes[1] &&
				derBytes[i + 2] === idpOidBytes[2]
			) {
				idpOffset = i;
				break;
			}
		}
		expect(idpOffset).not.toBe(-1);
		// Inside the IDP SEQUENCE, the distributionPoint is tagged [0] (0xa0).
		// Find all 0xa0 bytes after the IDP OID. The inner one (inside OCTET STRING > SEQUENCE)
		// is the distributionPoint. Change it to 0x81 (onlyContainsUserCerts [1]).
		// Structure: OID, [BOOL critical], OCTET STRING { SEQUENCE { [0] distributionPoint { ... } } }
		// The first 0xa0 after OID is the outer extension wrapper — we need the one inside SEQUENCE.
		// Count 0xa0 occurrences after OID: skip the first one (or two) and modify the deepest.
		let count = 0;
		let targetOffset = -1;
		for (let i = idpOffset + 3; i < derBytes.length; i++) {
			if (derBytes[i] === 0xa0) {
				count++;
				targetOffset = i;
				// The IDP SEQUENCE contains [0] as distributionPoint — it's nested inside
				// outer wrappers. The deepest [0] within ~30 bytes is the one we want.
				if (count >= 2) break; // second 0xa0 after OID is the inner one
			}
		}
		if (targetOffset !== -1) {
			// Change [0] to [1] (onlyContainsUserCerts) — tag 0xa0 → 0x81
			derBytes[targetOffset] = 0x81;
			expect(() => parseCertificateRevocationListDerOrThrow(derBytes)).toThrow(
				'Unsupported distributionPointName tag',
			);
		}
	});

	it('parseCertificateRevocationListDerOrThrow rejects malformed AKI without keyIdentifier (lines 680-682)', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'AKI CRL CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'AKI CRL CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const derBytes = new Uint8Array(pemDecodeOrThrow('X509 CRL', crl.pem));
		// Find AKI OID bytes (2.5.29.35 = 55 1D 23)
		const akiOidBytes = [0x55, 0x1d, 0x23];
		let akiOffset = -1;
		for (let i = 0; i < derBytes.length - 3; i++) {
			if (
				derBytes[i] === akiOidBytes[0] &&
				derBytes[i + 1] === akiOidBytes[1] &&
				derBytes[i + 2] === akiOidBytes[2]
			) {
				akiOffset = i;
				break;
			}
		}
		expect(akiOffset).not.toBe(-1);
		// Find the 0x80 tag (keyIdentifier [0]) after AKI OID and change to 0x82
		// (authorityCertSerialNumber [2]) — which is not 0x80 or 0xa0
		let tagOffset = akiOffset + 3;
		while (tagOffset < derBytes.length && derBytes[tagOffset] !== 0x80) {
			tagOffset++;
		}
		if (tagOffset < derBytes.length) {
			derBytes[tagOffset] = 0x82; // Change keyIdentifier [0] to serialNumber [2]
		}
		expect(() => parseCertificateRevocationListDerOrThrow(derBytes)).toThrow(
			'authorityKeyIdentifier fields must preserve DER order',
		);
	});

	it('parseCertificateRevocationListDerOrThrow rejects malformed AKI ordering and shape', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Bad CRL AKI CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Bad CRL AKI CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		expect(() =>
			parseCertificateRevocationListDerOrThrow(
				rewriteCrlExtensionValuePayload(
					new Uint8Array(pemDecodeOrThrow('X509 CRL', crl.pem)),
					OIDS.authorityKeyIdentifier,
					sequence([tlv(0x82, Uint8Array.of(0x01)), explicitContext(1, sequence([]))]),
				),
			),
		).toThrow('authorityKeyIdentifier fields must preserve DER order');
	});

	it('parseCertificateRevocationListDerOrThrow rejects non-SEQUENCE AKI payloads', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Bad CRL AKI Wrapper CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Bad CRL AKI Wrapper CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		expect(() =>
			parseCertificateRevocationListDerOrThrow(
				rewriteCrlExtensionValuePayload(
					new Uint8Array(pemDecodeOrThrow('X509 CRL', crl.pem)),
					OIDS.authorityKeyIdentifier,
					setOf([tlv(0x80, Uint8Array.of(0x01))]),
				),
			),
		).toThrow('authorityKeyIdentifier must use SEQUENCE');
	});

	it('parseCertificateRevocationListDerOrThrow rejects duplicate CRL extension OIDs', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Duplicate CRL Extension CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Duplicate CRL Extension CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 7,
		});

		expect(() =>
			parseCertificateRevocationListDerOrThrow(
				duplicateCrlExtension(
					new Uint8Array(pemDecodeOrThrow('X509 CRL', crl.pem)),
					OIDS.cRLNumber,
				),
			),
		).toThrow('Duplicate CRL extension OID');
	});

	it('parseCertificateRevocationListDerOrThrow rejects unsupported critical CRL extensions', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Unknown Critical CRL Extension CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Unknown Critical CRL Extension CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 7,
		});

		expect(() =>
			parseCertificateRevocationListDerOrThrow(
				appendCriticalCrlExtension(
					new Uint8Array(pemDecodeOrThrow('X509 CRL', crl.pem)),
					'1.2.3.4.5.6',
					Uint8Array.of(0x05, 0x00),
				),
			),
		).toThrow('Unsupported critical CRL extension OID: 1.2.3.4.5.6');
	});

	it('parseCertificateRevocationListDerOrThrow rejects non-INTEGER version tags', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Bad CRL Version Tag CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Bad CRL Version Tag CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 1,
		});
		expect(() =>
			parseCertificateRevocationListDerOrThrow(
				rewriteCrlVersionTag(new Uint8Array(pemDecodeOrThrow('X509 CRL', crl.pem)), 0x01),
			),
		).toThrow('version must use INTEGER');
	});

	it('parseCertificateRevocationListDerOrThrow rejects unsupported explicit version values', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Bad CRL Version Value CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Bad CRL Version Value CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 1,
		});
		expect(() =>
			parseCertificateRevocationListDerOrThrow(
				rewriteCrlVersionValue(
					new Uint8Array(pemDecodeOrThrow('X509 CRL', crl.pem)),
					Uint8Array.of(0x00),
				),
			),
		).toThrow('Unsupported CRL version: 1');
	});

	it('parseCertificateRevocationListDerOrThrow rejects malformed top-level trailing fields', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Trailing CRL Field CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Trailing CRL Field CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		expect(() =>
			parseCertificateRevocationListDerOrThrow(
				rewriteCrlWithExtraTopLevelField(
					new Uint8Array(pemDecodeOrThrow('X509 CRL', crl.pem)),
					tlv(0x05, new Uint8Array()),
				),
			),
		).toThrow('Malformed CRL');
	});

	it('parseCertificateRevocationListDerOrThrow rejects v1 CRLs with CRL extensions', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'V1 CRL With Extensions CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'V1 CRL With Extensions CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 9,
		});
		expect(() =>
			parseCertificateRevocationListDerOrThrow(
				removeCrlVersion(new Uint8Array(pemDecodeOrThrow('X509 CRL', crl.pem))),
			),
		).toThrow('CRL extensions require version 2');
	});

	it('parseCertificateRevocationListDerOrThrow rejects v1 CRLs with revoked entry extensions', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'V1 CRL With Entry Extensions CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'V1 CRL With Entry Extensions CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			revokedCertificates: [
				{
					serialNumber: Uint8Array.of(0x01),
					reasonCode: 'keyCompromise',
				},
			],
		});
		expect(() =>
			parseCertificateRevocationListDerOrThrow(
				removeCrlVersion(new Uint8Array(pemDecodeOrThrow('X509 CRL', crl.pem))),
			),
		).toThrow('revoked certificate extensions require CRL version 2');
	});

	it('parseCertificateRevocationListDerOrThrow rejects repeated issuingDistributionPoint fields', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Repeated IDP Field CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Repeated IDP Field CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			issuingDistributionPoint: { indirectCrl: true },
		});
		expect(() =>
			parseCertificateRevocationListDerOrThrow(
				rewriteCrlExtensionValuePayload(
					new Uint8Array(pemDecodeOrThrow('X509 CRL', crl.pem)),
					OIDS.issuingDistributionPoint,
					sequence([tlv(0x84, Uint8Array.of(0xff)), tlv(0x84, Uint8Array.of(0x00))]),
				),
			),
		).toThrow('IssuingDistributionPoint indirectCrl must not repeat');
	});

	it('rejects a malformed directoryName in an issuingDistributionPoint', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Malformed DirectoryName IDP CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Malformed DirectoryName IDP CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			issuingDistributionPoint: { indirectCrl: true },
		});
		const malformed = rewriteCrlExtensionValuePayload(
			new Uint8Array(pemDecodeOrThrow('X509 CRL', crl.pem)),
			OIDS.issuingDistributionPoint,
			sequence([tlv(0xa0, tlv(0xa0, tlv(0xa4, nullValue())))]),
		);

		expect(() => parseCertificateRevocationListDerOrThrow(malformed)).toThrow(
			'directoryName must wrap a Name SEQUENCE',
		);
		const result = parseCertificateRevocationListDer(malformed);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('malformed');
	});

	it('parseCertificateRevocationListDerOrThrow rejects conflicting issuingDistributionPoint scope booleans', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Conflicting IDP Scope CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Conflicting IDP Scope CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			issuingDistributionPoint: { onlyContainsUserCerts: true },
		});
		expect(() =>
			parseCertificateRevocationListDerOrThrow(
				rewriteCrlExtensionValuePayload(
					new Uint8Array(pemDecodeOrThrow('X509 CRL', crl.pem)),
					OIDS.issuingDistributionPoint,
					sequence([tlv(0x81, Uint8Array.of(0xff)), tlv(0x82, Uint8Array.of(0xff))]),
				),
			),
		).toThrow('IssuingDistributionPoint scope booleans are mutually exclusive');
	});

	it('preserves explicitly encoded false issuingDistributionPoint scope booleans', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Explicit False IDP Scope CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Explicit False IDP Scope CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			issuingDistributionPoint: { onlyContainsUserCerts: true },
		});
		const crlDer = new Uint8Array(pemDecodeOrThrow('X509 CRL', crl.pem));
		const allFalse = rewriteCrlExtensionValuePayload(
			crlDer,
			OIDS.issuingDistributionPoint,
			sequence([
				tlv(0x81, Uint8Array.of(0x00)),
				tlv(0x82, Uint8Array.of(0x00)),
				tlv(0x85, Uint8Array.of(0x00)),
			]),
		);
		const userCertsOnly = rewriteCrlExtensionValuePayload(
			crlDer,
			OIDS.issuingDistributionPoint,
			sequence([
				tlv(0x81, Uint8Array.of(0xff)),
				tlv(0x82, Uint8Array.of(0x00)),
				tlv(0x85, Uint8Array.of(0x00)),
			]),
		);

		expect(parseCertificateRevocationListDerOrThrow(allFalse).issuingDistributionPoint).toEqual({
			onlyContainsUserCerts: false,
			onlyContainsCACerts: false,
			onlyContainsAttributeCerts: false,
		});
		expect(
			parseCertificateRevocationListDerOrThrow(userCertsOnly).issuingDistributionPoint,
		).toEqual({
			onlyContainsUserCerts: true,
			onlyContainsCACerts: false,
			onlyContainsAttributeCerts: false,
		});
	});

	it('parseCertificateRevocationListDerOrThrow rejects unsupported issuingDistributionPoint distributionPointName tags', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Bad IDP Name Tag CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Bad IDP Name Tag CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			issuingDistributionPoint: { indirectCrl: true },
		});
		expect(() =>
			parseCertificateRevocationListDerOrThrow(
				rewriteCrlExtensionValuePayload(
					new Uint8Array(pemDecodeOrThrow('X509 CRL', crl.pem)),
					OIDS.issuingDistributionPoint,
					sequence([explicitContext(0, tlv(0x82, new TextEncoder().encode('bad.example')))]),
				),
			),
		).toThrow('Unsupported distributionPointName tag');
	});

	it('parseCertificateRevocationListDerOrThrow rejects freshestCRL distribution points with only reasons', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Bad Freshest CRL DP CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Bad Freshest CRL DP CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			freshestCrlDistributionPoints: [
				{
					distributionPoint: {
						type: 'fullName',
						fullName: [{ type: 'uri', value: 'http://example.test/ok.crl' }],
					},
				},
			],
		});
		expect(() =>
			parseCertificateRevocationListDerOrThrow(
				rewriteCrlExtensionValuePayload(
					new Uint8Array(pemDecodeOrThrow('X509 CRL', crl.pem)),
					OIDS.freshestCRL,
					sequence([sequence([tlv(0x81, Uint8Array.of(0x00))])]),
				),
			),
		).toThrow('DistributionPoint must include distributionPoint or crlIssuer');
	});

	it('parseCertificateRevocationListDerOrThrow rejects empty freshestCRL distribution point sequences', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Bad Empty Freshest CRL CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Bad Empty Freshest CRL CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			freshestCrlDistributionPoints: [
				{
					distributionPoint: {
						type: 'fullName',
						fullName: [{ type: 'uri', value: 'http://example.test/ok.crl' }],
					},
				},
			],
		});
		expect(() =>
			parseCertificateRevocationListDerOrThrow(
				rewriteCrlExtensionValuePayload(
					new Uint8Array(pemDecodeOrThrow('X509 CRL', crl.pem)),
					OIDS.freshestCRL,
					sequence([]),
				),
			),
		).toThrow('DistributionPoints must not be empty');
	});

	it('parseCertificateRevocationListDerOrThrow rejects non-OCTET CRL extension values', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Bad CRL Extension Value CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Bad CRL Extension Value CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 7,
		});

		expect(() =>
			parseCertificateRevocationListDerOrThrow(
				rewriteCrlExtensionValueTag(
					new Uint8Array(pemDecodeOrThrow('X509 CRL', crl.pem)),
					OIDS.cRLNumber,
					0x02,
				),
			),
		).toThrow('CRL extension value must use OCTET STRING');
	});

	it('parseCertificateRevocationListDerOrThrow rejects malformed CRL extension middle fields', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Bad CRL Extension Middle Field CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Bad CRL Extension Middle Field CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 7,
		});

		expect(() =>
			parseCertificateRevocationListDerOrThrow(
				rewriteCrlExtensionMiddleFieldTag(
					new Uint8Array(pemDecodeOrThrow('X509 CRL', crl.pem)),
					OIDS.cRLNumber,
					0x02,
				),
			),
		).toThrow('Malformed CRL extension');
	});

	it('parseCertificateRevocationListDerOrThrow rejects duplicate revoked entry extension OIDs', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Duplicate Revoked Entry Extension CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Duplicate Revoked Entry Extension CA' },
			subject: { commonName: 'duplicate-revoked-entry.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const parsedLeaf = unwrap(parseCertificatePem(leaf.pem));
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Duplicate Revoked Entry Extension CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			revokedCertificates: [
				{
					serialNumber: hexToBytes(parsedLeaf.serialNumberHex),
					revocationDate: new Date('2024-01-01T00:00:00Z'),
					reasonCode: 'keyCompromise',
				},
			],
		});

		expect(() =>
			parseCertificateRevocationListDerOrThrow(
				duplicateFirstRevokedEntryExtension(
					new Uint8Array(pemDecodeOrThrow('X509 CRL', crl.pem)),
					OIDS.cRLReason,
				),
			),
		).toThrow('Duplicate revoked certificate extension OID');
	});

	it('parseCertificateRevocationListDerOrThrow rejects non-OCTET revoked entry extension values', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Bad Revoked Entry Extension Value CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Bad Revoked Entry Extension Value CA' },
			subject: { commonName: 'bad-revoked-entry-value.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const parsedLeaf = unwrap(parseCertificatePem(leaf.pem));
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Bad Revoked Entry Extension Value CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			revokedCertificates: [
				{
					serialNumber: hexToBytes(parsedLeaf.serialNumberHex),
					revocationDate: new Date('2024-01-01T00:00:00Z'),
					reasonCode: 'keyCompromise',
				},
			],
		});

		expect(() =>
			parseCertificateRevocationListDerOrThrow(
				rewriteFirstRevokedEntryExtensionValueTag(
					new Uint8Array(pemDecodeOrThrow('X509 CRL', crl.pem)),
					OIDS.cRLReason,
					0x02,
				),
			),
		).toThrow('Revoked certificate extension value must use OCTET STRING');
	});

	it('parseCertificateRevocationListDerOrThrow rejects empty certificateIssuer GeneralNames', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Bad CertIssuer Names CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Bad CertIssuer Names CA' },
			subject: { commonName: 'bad-cert-issuer-names.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const parsedLeaf = unwrap(parseCertificatePem(leaf.pem));
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Bad CertIssuer Names CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			revokedCertificates: [{ serialNumber: hexToBytes(parsedLeaf.serialNumberHex) }],
		});
		const withCertificateIssuer = await addRevokedEntryCertificateIssuers(
			crl.der,
			ca.keyPair.privateKey,
			[{ entryIndex: 0, names: [{ type: 'dns', value: 'issuer.example.test' }] }],
		);
		expect(() =>
			parseCertificateRevocationListDerOrThrow(
				rewriteFirstRevokedEntryExtensionValuePayload(
					withCertificateIssuer,
					OIDS.certificateIssuer,
					sequence([]),
				),
			),
		).toThrow('GeneralNames must not be empty');
	});

	it('parseCertificateRevocationListDerOrThrow rejects non-SEQUENCE certificateIssuer wrappers', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Bad CertIssuer Wrapper CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Bad CertIssuer Wrapper CA' },
			subject: { commonName: 'bad-cert-issuer-wrapper.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const parsedLeaf = unwrap(parseCertificatePem(leaf.pem));
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Bad CertIssuer Wrapper CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			revokedCertificates: [{ serialNumber: hexToBytes(parsedLeaf.serialNumberHex) }],
		});
		const withCertificateIssuer = await addRevokedEntryCertificateIssuers(
			crl.der,
			ca.keyPair.privateKey,
			[{ entryIndex: 0, names: [{ type: 'dns', value: 'issuer.example.test' }] }],
		);
		expect(() =>
			parseCertificateRevocationListDerOrThrow(
				rewriteFirstRevokedEntryExtensionValuePayload(
					withCertificateIssuer,
					OIDS.certificateIssuer,
					setOf([tlv(0x82, new TextEncoder().encode('issuer.example.test'))]),
				),
			),
		).toThrow('certificateIssuer must use SEQUENCE');
	});

	it('parseCertificateRevocationListDerOrThrow rejects non-INTEGER revoked serialNumber tags', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Bad Revoked Serial Tag CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Bad Revoked Serial Tag CA' },
			subject: { commonName: 'bad-revoked-serial.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const parsedLeaf = unwrap(parseCertificatePem(leaf.pem));
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Bad Revoked Serial Tag CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			revokedCertificates: [
				{
					serialNumber: hexToBytes(parsedLeaf.serialNumberHex),
					revocationDate: new Date('2024-01-01T00:00:00Z'),
					reasonCode: 'keyCompromise',
				},
			],
		});

		expect(() =>
			parseCertificateRevocationListDerOrThrow(
				rewriteFirstRevokedEntrySerialTag(
					new Uint8Array(pemDecodeOrThrow('X509 CRL', crl.pem)),
					0x04,
				),
			),
		).toThrow('revoked serialNumber must use INTEGER');
	});

	it('parseCertificateRevocationListDerOrThrow rejects malformed revoked entry extension middle fields', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Bad Revoked Entry Extension Middle Field CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Bad Revoked Entry Extension Middle Field CA' },
			subject: { commonName: 'bad-revoked-entry-middle.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const parsedLeaf = unwrap(parseCertificatePem(leaf.pem));
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Bad Revoked Entry Extension Middle Field CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			revokedCertificates: [
				{
					serialNumber: hexToBytes(parsedLeaf.serialNumberHex),
					revocationDate: new Date('2024-01-01T00:00:00Z'),
					reasonCode: 'keyCompromise',
				},
			],
		});

		expect(() =>
			parseCertificateRevocationListDerOrThrow(
				rewriteFirstRevokedEntryExtensionMiddleFieldTag(
					new Uint8Array(pemDecodeOrThrow('X509 CRL', crl.pem)),
					OIDS.cRLReason,
					0x02,
				),
			),
		).toThrow('Malformed revoked certificate extension');
	});
});

function duplicateCrlExtension(crlDer: Uint8Array, oid: string): Uint8Array {
	const topLevel = readSequenceChildren(crlDer);
	const tbsCertList = topLevel[0];
	const signatureAlgorithm = topLevel[1];
	const signatureValue = topLevel[2];
	if (
		tbsCertList === undefined ||
		signatureAlgorithm === undefined ||
		signatureValue === undefined
	) {
		throw new Error('Malformed CRL');
	}
	const tbsDer = sliceElement(crlDer, tbsCertList);
	const tbsChildren = readSequenceChildren(tbsDer);
	const extensionIndex = tbsChildren.findIndex((child) => child.tag === 0xa0);
	if (extensionIndex === -1) {
		throw new Error('CRL missing extensions');
	}
	const extensionWrapper = tbsChildren[extensionIndex];
	if (extensionWrapper === undefined) {
		throw new Error('CRL missing extensions');
	}
	const extensionSequence = childrenOf(tbsDer, extensionWrapper)[0];
	if (extensionSequence === undefined) {
		throw new Error('CRL missing extension sequence');
	}
	const rebuiltWrapper = explicitContext(
		0,
		duplicateSequenceEntryByOid(tbsDer, extensionSequence, oid),
	);
	const rebuiltTbs = sequence(
		tbsChildren.map((child, index) =>
			index === extensionIndex ? rebuiltWrapper : sliceElement(tbsDer, child),
		),
	);
	return sequence([
		rebuiltTbs,
		sliceElement(crlDer, signatureAlgorithm),
		sliceElement(crlDer, signatureValue),
	]);
}

function appendCriticalCrlExtension(
	crlDer: Uint8Array,
	oid: string,
	valueDer: Uint8Array,
): Uint8Array {
	const topLevel = readSequenceChildren(crlDer);
	const tbsCertList = topLevel[0];
	const signatureAlgorithm = topLevel[1];
	const signatureValue = topLevel[2];
	if (
		tbsCertList === undefined ||
		signatureAlgorithm === undefined ||
		signatureValue === undefined
	) {
		throw new Error('Malformed CRL');
	}
	const tbsDer = sliceElement(crlDer, tbsCertList);
	const tbsChildren = readSequenceChildren(tbsDer);
	const extensionIndex = tbsChildren.findIndex((child) => child.tag === 0xa0);
	if (extensionIndex === -1) {
		throw new Error('CRL missing extensions');
	}
	const extensionWrapper = tbsChildren[extensionIndex];
	if (extensionWrapper === undefined) {
		throw new Error('CRL missing extensions');
	}
	const extensionSequence = childrenOf(tbsDer, extensionWrapper)[0];
	if (extensionSequence === undefined) {
		throw new Error('CRL missing extension sequence');
	}
	const extensionEntries = childrenOf(tbsDer, extensionSequence).map((entry) =>
		sliceElement(tbsDer, entry),
	);
	const rebuiltWrapper = explicitContext(
		0,
		sequence([
			...extensionEntries,
			sequence([objectIdentifier(oid), bool(true), octetString(valueDer)]),
		]),
	);
	const rebuiltTbs = sequence(
		tbsChildren.map((child, index) =>
			index === extensionIndex ? rebuiltWrapper : sliceElement(tbsDer, child),
		),
	);
	return sequence([
		rebuiltTbs,
		sliceElement(crlDer, signatureAlgorithm),
		sliceElement(crlDer, signatureValue),
	]);
}

function rewriteCrlExtensionValueTag(crlDer: Uint8Array, oid: string, tag: number): Uint8Array {
	const topLevel = readSequenceChildren(crlDer);
	const tbsCertList = topLevel[0];
	const signatureAlgorithm = topLevel[1];
	const signatureValue = topLevel[2];
	if (
		tbsCertList === undefined ||
		signatureAlgorithm === undefined ||
		signatureValue === undefined
	) {
		throw new Error('Malformed CRL');
	}
	const tbsDer = sliceElement(crlDer, tbsCertList);
	const tbsChildren = readSequenceChildren(tbsDer);
	const extensionIndex = tbsChildren.findIndex((child) => child.tag === 0xa0);
	if (extensionIndex === -1) {
		throw new Error('CRL missing extensions');
	}
	const extensionWrapper = tbsChildren[extensionIndex];
	if (extensionWrapper === undefined) {
		throw new Error('CRL missing extensions');
	}
	const extensionSequence = childrenOf(tbsDer, extensionWrapper)[0];
	if (extensionSequence === undefined) {
		throw new Error('CRL missing extension sequence');
	}
	const rebuiltWrapper = explicitContext(
		0,
		rewriteSequenceEntryValueTag(tbsDer, extensionSequence, oid, tag),
	);
	const rebuiltTbs = sequence(
		tbsChildren.map((child, index) =>
			index === extensionIndex ? rebuiltWrapper : sliceElement(tbsDer, child),
		),
	);
	return sequence([
		rebuiltTbs,
		sliceElement(crlDer, signatureAlgorithm),
		sliceElement(crlDer, signatureValue),
	]);
}

function rewriteCrlExtensionValuePayload(
	crlDer: Uint8Array,
	oid: string,
	extensionValueDer: Uint8Array,
): Uint8Array {
	const topLevel = readSequenceChildren(crlDer);
	const tbsCertList = topLevel[0];
	const signatureAlgorithm = topLevel[1];
	const signatureValue = topLevel[2];
	if (
		tbsCertList === undefined ||
		signatureAlgorithm === undefined ||
		signatureValue === undefined
	) {
		throw new Error('Malformed CRL');
	}
	const tbsDer = sliceElement(crlDer, tbsCertList);
	const tbsChildren = readSequenceChildren(tbsDer);
	const extensionIndex = tbsChildren.findIndex((child) => child.tag === 0xa0);
	if (extensionIndex === -1) {
		throw new Error('CRL missing extensions');
	}
	const extensionWrapper = tbsChildren[extensionIndex];
	if (extensionWrapper === undefined) {
		throw new Error('CRL missing extensions');
	}
	const extensionSequence = childrenOf(tbsDer, extensionWrapper)[0];
	if (extensionSequence === undefined) {
		throw new Error('CRL missing extension sequence');
	}
	const rebuiltWrapper = explicitContext(
		0,
		rewriteSequenceEntryValuePayload(tbsDer, extensionSequence, oid, extensionValueDer),
	);
	const rebuiltTbs = sequence(
		tbsChildren.map((child, index) =>
			index === extensionIndex ? rebuiltWrapper : sliceElement(tbsDer, child),
		),
	);
	return sequence([
		rebuiltTbs,
		sliceElement(crlDer, signatureAlgorithm),
		sliceElement(crlDer, signatureValue),
	]);
}

function rewriteCrlExtensionMiddleFieldTag(
	crlDer: Uint8Array,
	oid: string,
	tag: number,
): Uint8Array {
	return rewriteCrlExtensionEntry(crlDer, (tbsDer, extensionSequence) =>
		rewriteSequenceEntryMiddleFieldTag(tbsDer, extensionSequence, oid, tag),
	);
}

function rewriteCrlVersionTag(crlDer: Uint8Array, tag: number): Uint8Array {
	const topLevel = readSequenceChildren(crlDer);
	const tbsCertList = topLevel[0];
	const signatureAlgorithm = topLevel[1];
	const signatureValue = topLevel[2];
	if (
		tbsCertList === undefined ||
		signatureAlgorithm === undefined ||
		signatureValue === undefined
	) {
		throw new Error('Malformed CRL');
	}
	const tbsDer = sliceElement(crlDer, tbsCertList);
	const tbsChildren = readSequenceChildren(tbsDer);
	const versionElement = tbsChildren[0];
	if (versionElement?.tag !== 0x02) {
		throw new Error('CRL missing version INTEGER');
	}
	const rebuiltTbs = sequence(
		tbsChildren.map((child, index) =>
			index === 0 ? tlv(tag, child.value) : sliceElement(tbsDer, child),
		),
	);
	return sequence([
		rebuiltTbs,
		sliceElement(crlDer, signatureAlgorithm),
		sliceElement(crlDer, signatureValue),
	]);
}

function rewriteCrlVersionValue(crlDer: Uint8Array, versionValue: Uint8Array): Uint8Array {
	const topLevel = readSequenceChildren(crlDer);
	const tbsCertList = topLevel[0];
	const signatureAlgorithm = topLevel[1];
	const signatureValue = topLevel[2];
	if (
		tbsCertList === undefined ||
		signatureAlgorithm === undefined ||
		signatureValue === undefined
	) {
		throw new Error('Malformed CRL');
	}
	const tbsDer = sliceElement(crlDer, tbsCertList);
	const tbsChildren = readSequenceChildren(tbsDer);
	const versionElement = tbsChildren[0];
	if (versionElement?.tag !== 0x02) {
		throw new Error('CRL missing version INTEGER');
	}
	const rebuiltTbs = sequence(
		tbsChildren.map((child, index) =>
			index === 0 ? tlv(0x02, versionValue) : sliceElement(tbsDer, child),
		),
	);
	return sequence([
		rebuiltTbs,
		sliceElement(crlDer, signatureAlgorithm),
		sliceElement(crlDer, signatureValue),
	]);
}

function rewriteCrlWithExtraTopLevelField(
	crlDer: Uint8Array,
	extraFieldDer: Uint8Array,
): Uint8Array {
	const topLevel = readSequenceChildren(crlDer);
	return sequence([...topLevel.map((child) => sliceElement(crlDer, child)), extraFieldDer]);
}

function removeCrlVersion(crlDer: Uint8Array): Uint8Array {
	const topLevel = readSequenceChildren(crlDer);
	const tbsCertList = topLevel[0];
	const signatureAlgorithm = topLevel[1];
	const signatureValue = topLevel[2];
	if (
		tbsCertList === undefined ||
		signatureAlgorithm === undefined ||
		signatureValue === undefined
	) {
		throw new Error('Malformed CRL');
	}
	const tbsDer = sliceElement(crlDer, tbsCertList);
	const tbsChildren = readSequenceChildren(tbsDer);
	const rebuiltTbs = sequence(
		tbsChildren
			.filter((child, index) => !(index === 0 && child.tag === 0x02))
			.map((child) => sliceElement(tbsDer, child)),
	);
	return sequence([
		rebuiltTbs,
		sliceElement(crlDer, signatureAlgorithm),
		sliceElement(crlDer, signatureValue),
	]);
}

function duplicateFirstRevokedEntryExtension(crlDer: Uint8Array, oid: string): Uint8Array {
	const topLevel = readSequenceChildren(crlDer);
	const tbsCertList = topLevel[0];
	const signatureAlgorithm = topLevel[1];
	const signatureValue = topLevel[2];
	if (
		tbsCertList === undefined ||
		signatureAlgorithm === undefined ||
		signatureValue === undefined
	) {
		throw new Error('Malformed CRL');
	}
	const tbsDer = sliceElement(crlDer, tbsCertList);
	const tbsChildren = readSequenceChildren(tbsDer);
	const revokedEntriesIndex = findRevokedEntriesIndex(tbsChildren);
	const revokedEntries = tbsChildren[revokedEntriesIndex];
	if (revokedEntries === undefined) {
		throw new Error('CRL missing revokedCertificates');
	}
	const revokedEntryElements = childrenOf(tbsDer, revokedEntries);
	const firstEntry = revokedEntryElements[0];
	if (firstEntry === undefined) {
		throw new Error('CRL missing revoked entry');
	}
	const firstEntryDer = sliceElement(tbsDer, firstEntry);
	const firstEntryParts = readSequenceChildren(firstEntryDer);
	const entryExtensions = firstEntryParts[2];
	if (entryExtensions === undefined) {
		throw new Error('Revoked entry missing extensions');
	}
	const rebuiltFirstEntry = sequence([
		sliceElement(firstEntryDer, firstEntryParts[0] ?? fail('revoked serialNumber missing')),
		sliceElement(firstEntryDer, firstEntryParts[1] ?? fail('revocationDate missing')),
		duplicateSequenceEntryByOid(firstEntryDer, entryExtensions, oid),
	]);
	const rebuiltRevokedEntries = sequence([
		rebuiltFirstEntry,
		...revokedEntryElements.slice(1).map((entry) => sliceElement(tbsDer, entry)),
	]);
	const rebuiltTbs = sequence(
		tbsChildren.map((child, index) =>
			index === revokedEntriesIndex ? rebuiltRevokedEntries : sliceElement(tbsDer, child),
		),
	);
	return sequence([
		rebuiltTbs,
		sliceElement(crlDer, signatureAlgorithm),
		sliceElement(crlDer, signatureValue),
	]);
}

function rewriteFirstRevokedEntryExtensionValueTag(
	crlDer: Uint8Array,
	oid: string,
	tag: number,
): Uint8Array {
	const topLevel = readSequenceChildren(crlDer);
	const tbsCertList = topLevel[0];
	const signatureAlgorithm = topLevel[1];
	const signatureValue = topLevel[2];
	if (
		tbsCertList === undefined ||
		signatureAlgorithm === undefined ||
		signatureValue === undefined
	) {
		throw new Error('Malformed CRL');
	}
	const tbsDer = sliceElement(crlDer, tbsCertList);
	const tbsChildren = readSequenceChildren(tbsDer);
	const revokedEntriesIndex = findRevokedEntriesIndex(tbsChildren);
	const revokedEntries = tbsChildren[revokedEntriesIndex];
	if (revokedEntries === undefined) {
		throw new Error('CRL missing revokedCertificates');
	}
	const revokedEntryElements = childrenOf(tbsDer, revokedEntries);
	const firstEntry = revokedEntryElements[0];
	if (firstEntry === undefined) {
		throw new Error('CRL missing revoked entry');
	}
	const firstEntryDer = sliceElement(tbsDer, firstEntry);
	const firstEntryParts = readSequenceChildren(firstEntryDer);
	const entryExtensions = firstEntryParts[2];
	if (entryExtensions === undefined) {
		throw new Error('Revoked entry missing extensions');
	}
	const rebuiltFirstEntry = sequence([
		sliceElement(firstEntryDer, firstEntryParts[0] ?? fail('revoked serialNumber missing')),
		sliceElement(firstEntryDer, firstEntryParts[1] ?? fail('revocationDate missing')),
		rewriteSequenceEntryValueTag(firstEntryDer, entryExtensions, oid, tag),
	]);
	const rebuiltRevokedEntries = sequence([
		rebuiltFirstEntry,
		...revokedEntryElements.slice(1).map((entry) => sliceElement(tbsDer, entry)),
	]);
	const rebuiltTbs = sequence(
		tbsChildren.map((child, index) =>
			index === revokedEntriesIndex ? rebuiltRevokedEntries : sliceElement(tbsDer, child),
		),
	);
	return sequence([
		rebuiltTbs,
		sliceElement(crlDer, signatureAlgorithm),
		sliceElement(crlDer, signatureValue),
	]);
}

function rewriteFirstRevokedEntryExtensionValuePayload(
	crlDer: Uint8Array,
	oid: string,
	extensionValueDer: Uint8Array,
): Uint8Array {
	return rewriteFirstRevokedEntryExtension(crlDer, (firstEntryDer, entryExtensions) =>
		rewriteSequenceEntryValuePayload(firstEntryDer, entryExtensions, oid, extensionValueDer),
	);
}

function rewriteFirstRevokedEntryExtensionMiddleFieldTag(
	crlDer: Uint8Array,
	oid: string,
	tag: number,
): Uint8Array {
	return rewriteFirstRevokedEntryExtension(crlDer, (firstEntryDer, entryExtensions) =>
		rewriteSequenceEntryMiddleFieldTag(firstEntryDer, entryExtensions, oid, tag),
	);
}

function rewriteFirstRevokedEntrySerialTag(crlDer: Uint8Array, tag: number): Uint8Array {
	const topLevel = readSequenceChildren(crlDer);
	const tbsCertList = topLevel[0];
	const signatureAlgorithm = topLevel[1];
	const signatureValue = topLevel[2];
	if (
		tbsCertList === undefined ||
		signatureAlgorithm === undefined ||
		signatureValue === undefined
	) {
		throw new Error('Malformed CRL');
	}
	const tbsDer = sliceElement(crlDer, tbsCertList);
	const tbsChildren = readSequenceChildren(tbsDer);
	const revokedEntriesIndex = findRevokedEntriesIndex(tbsChildren);
	const revokedEntries = tbsChildren[revokedEntriesIndex];
	if (revokedEntries === undefined) {
		throw new Error('CRL missing revokedCertificates');
	}
	const revokedEntryElements = childrenOf(tbsDer, revokedEntries);
	const firstEntry = revokedEntryElements[0];
	if (firstEntry === undefined) {
		throw new Error('CRL missing revoked entry');
	}
	const firstEntryDer = sliceElement(tbsDer, firstEntry);
	const firstEntryParts = readSequenceChildren(firstEntryDer);
	const serialNumber = firstEntryParts[0];
	if (serialNumber === undefined) {
		throw new Error('revoked serialNumber missing');
	}
	const rebuiltFirstEntry = sequence([
		tlv(tag, serialNumber.value),
		...firstEntryParts.slice(1).map((part) => sliceElement(firstEntryDer, part)),
	]);
	const rebuiltRevokedEntries = sequence([
		rebuiltFirstEntry,
		...revokedEntryElements.slice(1).map((entry) => sliceElement(tbsDer, entry)),
	]);
	const rebuiltTbs = sequence(
		tbsChildren.map((child, index) =>
			index === revokedEntriesIndex ? rebuiltRevokedEntries : sliceElement(tbsDer, child),
		),
	);
	return sequence([
		rebuiltTbs,
		sliceElement(crlDer, signatureAlgorithm),
		sliceElement(crlDer, signatureValue),
	]);
}

function rewriteCrlExtensionEntry(
	crlDer: Uint8Array,
	rewrite: (
		tbsDer: Uint8Array,
		extensionSequence: ReturnType<typeof readSequenceChildren>[number],
	) => Uint8Array,
): Uint8Array {
	const topLevel = readSequenceChildren(crlDer);
	const tbsCertList = topLevel[0];
	const signatureAlgorithm = topLevel[1];
	const signatureValue = topLevel[2];
	if (
		tbsCertList === undefined ||
		signatureAlgorithm === undefined ||
		signatureValue === undefined
	) {
		throw new Error('Malformed CRL');
	}
	const tbsDer = sliceElement(crlDer, tbsCertList);
	const tbsChildren = readSequenceChildren(tbsDer);
	const extensionIndex = tbsChildren.findIndex((child) => child.tag === 0xa0);
	if (extensionIndex === -1) {
		throw new Error('CRL missing extensions');
	}
	const extensionWrapper = tbsChildren[extensionIndex];
	if (extensionWrapper === undefined) {
		throw new Error('CRL missing extensions');
	}
	const extensionSequence = childrenOf(tbsDer, extensionWrapper)[0];
	if (extensionSequence === undefined) {
		throw new Error('CRL missing extension sequence');
	}
	const rebuiltWrapper = explicitContext(0, rewrite(tbsDer, extensionSequence));
	const rebuiltTbs = sequence(
		tbsChildren.map((child, index) =>
			index === extensionIndex ? rebuiltWrapper : sliceElement(tbsDer, child),
		),
	);
	return sequence([
		rebuiltTbs,
		sliceElement(crlDer, signatureAlgorithm),
		sliceElement(crlDer, signatureValue),
	]);
}

function rewriteFirstRevokedEntryExtension(
	crlDer: Uint8Array,
	rewrite: (
		firstEntryDer: Uint8Array,
		entryExtensions: ReturnType<typeof readSequenceChildren>[number],
	) => Uint8Array,
): Uint8Array {
	const topLevel = readSequenceChildren(crlDer);
	const tbsCertList = topLevel[0];
	const signatureAlgorithm = topLevel[1];
	const signatureValue = topLevel[2];
	if (
		tbsCertList === undefined ||
		signatureAlgorithm === undefined ||
		signatureValue === undefined
	) {
		throw new Error('Malformed CRL');
	}
	const tbsDer = sliceElement(crlDer, tbsCertList);
	const tbsChildren = readSequenceChildren(tbsDer);
	const revokedEntriesIndex = findRevokedEntriesIndex(tbsChildren);
	const revokedEntries = tbsChildren[revokedEntriesIndex];
	if (revokedEntries === undefined) {
		throw new Error('CRL missing revokedCertificates');
	}
	const revokedEntryElements = childrenOf(tbsDer, revokedEntries);
	const firstEntry = revokedEntryElements[0];
	if (firstEntry === undefined) {
		throw new Error('CRL missing revoked entry');
	}
	const firstEntryDer = sliceElement(tbsDer, firstEntry);
	const firstEntryParts = readSequenceChildren(firstEntryDer);
	const entryExtensions = firstEntryParts[2];
	if (entryExtensions === undefined) {
		throw new Error('Revoked entry missing extensions');
	}
	const rebuiltFirstEntry = sequence([
		sliceElement(firstEntryDer, firstEntryParts[0] ?? fail('revoked serialNumber missing')),
		sliceElement(firstEntryDer, firstEntryParts[1] ?? fail('revocationDate missing')),
		rewrite(firstEntryDer, entryExtensions),
	]);
	const rebuiltRevokedEntries = sequence([
		rebuiltFirstEntry,
		...revokedEntryElements.slice(1).map((entry) => sliceElement(tbsDer, entry)),
	]);
	const rebuiltTbs = sequence(
		tbsChildren.map((child, index) =>
			index === revokedEntriesIndex ? rebuiltRevokedEntries : sliceElement(tbsDer, child),
		),
	);
	return sequence([
		rebuiltTbs,
		sliceElement(crlDer, signatureAlgorithm),
		sliceElement(crlDer, signatureValue),
	]);
}

function duplicateSequenceEntryByOid(
	source: Uint8Array,
	sequenceElement: ReturnType<typeof readSequenceChildren>[number],
	oid: string,
): Uint8Array {
	const entries = childrenOf(source, sequenceElement).map((entry) => sliceElement(source, entry));
	const duplicate = entries.find((entryDer) => {
		const oidElement = readSequenceChildren(entryDer)[0];
		return oidElement !== undefined && decodeObjectIdentifier(oidElement.value) === oid;
	});
	if (duplicate === undefined) {
		throw new Error(`Missing extension OID: ${oid}`);
	}
	return sequence([...entries, duplicate]);
}

function rewriteSequenceEntryValueTag(
	source: Uint8Array,
	sequenceElement: ReturnType<typeof readSequenceChildren>[number],
	oid: string,
	tag: number,
): Uint8Array {
	const entries = childrenOf(source, sequenceElement).map((entry) => {
		const entryDer = sliceElement(source, entry);
		const parts = readSequenceChildren(entryDer);
		const oidElement = parts[0];
		const valueElement = parts[parts.length - 1];
		if (
			oidElement === undefined ||
			valueElement === undefined ||
			decodeObjectIdentifier(oidElement.value) !== oid
		) {
			return entryDer;
		}
		const middle = parts.slice(1, parts.length - 1).map((part) => sliceElement(entryDer, part));
		return sequence([sliceElement(entryDer, oidElement), ...middle, tlv(tag, valueElement.value)]);
	});
	return sequence(entries);
}

function rewriteSequenceEntryValuePayload(
	source: Uint8Array,
	sequenceElement: ReturnType<typeof readSequenceChildren>[number],
	oid: string,
	extensionValueDer: Uint8Array,
): Uint8Array {
	const entries = childrenOf(source, sequenceElement).map((entry) => {
		const entryDer = sliceElement(source, entry);
		const parts = readSequenceChildren(entryDer);
		const oidElement = parts[0];
		if (oidElement === undefined || decodeObjectIdentifier(oidElement.value) !== oid) {
			return entryDer;
		}
		const criticalElement = parts.length === 3 ? parts[1] : undefined;
		return sequence([
			sliceElement(entryDer, oidElement),
			...(criticalElement === undefined ? [] : [sliceElement(entryDer, criticalElement)]),
			octetString(extensionValueDer),
		]);
	});
	return sequence(entries);
}

function rewriteSequenceEntryMiddleFieldTag(
	source: Uint8Array,
	sequenceElement: ReturnType<typeof readSequenceChildren>[number],
	oid: string,
	tag: number,
): Uint8Array {
	const entries = childrenOf(source, sequenceElement).map((entry) => {
		const entryDer = sliceElement(source, entry);
		const parts = readSequenceChildren(entryDer);
		const oidElement = parts[0];
		const valueElement = parts[parts.length - 1];
		if (
			oidElement === undefined ||
			valueElement === undefined ||
			decodeObjectIdentifier(oidElement.value) !== oid
		) {
			return entryDer;
		}
		if (parts.length === 2) {
			return sequence([
				sliceElement(entryDer, oidElement),
				tlv(tag, Uint8Array.of(0x00)),
				sliceElement(entryDer, valueElement),
			]);
		}
		const middle = parts[1];
		if (middle === undefined) {
			throw new Error('Malformed extension entry');
		}
		return sequence([
			sliceElement(entryDer, oidElement),
			tlv(tag, middle.value),
			sliceElement(entryDer, valueElement),
		]);
	});
	return sequence(entries);
}

function findRevokedEntriesIndex(children: ReturnType<typeof readSequenceChildren>): number {
	let index = children[0]?.tag === 0x02 ? 3 : 2;
	const maybeNextUpdate = children[index + 1];
	if (
		maybeNextUpdate !== undefined &&
		(maybeNextUpdate.tag === 0x17 || maybeNextUpdate.tag === 0x18)
	) {
		index += 1;
	}
	return index + 1;
}

function fail(message: string): never {
	throw new Error(message);
}

describe('crl Result forms', () => {
	it('parseCertificateRevocationListDer/Pem return ok for valid CRLs and malformed otherwise', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Result Form CA' },
			extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Result Form CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			revokedCertificates: [],
		});
		const der = parseCertificateRevocationListDer(crl.der);
		expect(der.ok).toBe(true);
		if (der.ok) {
			expect(der.value.issuer.values.commonName).toBe('Result Form CA');
		}
		const pem = parseCertificateRevocationListPem(crl.pem);
		expect(pem.ok).toBe(true);

		const badDer = parseCertificateRevocationListDer(Uint8Array.of(0x30, 0x00));
		expect(badDer.ok).toBe(false);
		if (!badDer.ok) {
			expect(badDer.code).toBe('malformed');
		}
		const badPem = parseCertificateRevocationListPem('not pem');
		expect(badPem.ok).toBe(false);
	});
});

describe('CRL maximum age', () => {
	async function issueOpenEndedCrl() {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Max Age CRL CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Max Age CRL CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			thisUpdate: new Date('2020-01-01T00:00:00Z'),
		});
		return { ca, crl };
	}

	it('rejects a CRL older than maxAgeMs even when nextUpdate is absent', async () => {
		const { ca, crl } = await issueOpenEndedCrl();
		const at = new Date('2100-01-01T00:00:00Z');

		const unbounded = await validateCertificateRevocationList({
			crl: crl.pem,
			issuerCertificate: ca.certificate.pem,
			at,
		});
		expect(unbounded.ok).toBe(true);

		const bounded = await validateCertificateRevocationList({
			crl: crl.pem,
			issuerCertificate: ca.certificate.pem,
			at,
			maxAgeMs: 365 * 24 * 60 * 60 * 1000,
		});
		expect(bounded.ok).toBe(false);
		if (!bounded.ok) {
			expect(bounded.code).toBe('stale_crl');
		}

		const withinAge = await validateCertificateRevocationList({
			crl: crl.pem,
			issuerCertificate: ca.certificate.pem,
			at: new Date('2020-06-01T00:00:00Z'),
			maxAgeMs: 365 * 24 * 60 * 60 * 1000,
		});
		expect(withinAge.ok).toBe(true);
	});

	it('rejects a negative maxAgeMs', async () => {
		const { ca, crl } = await issueOpenEndedCrl();

		expect(
			validateCertificateRevocationList({
				crl: crl.pem,
				issuerCertificate: ca.certificate.pem,
				at: new Date('2020-06-01T00:00:00Z'),
				maxAgeMs: -1,
			}),
		).rejects.toThrow(RangeError);
	});

	it('reports an invalid crlMaxAgeMs as an invariant, not indeterminate evidence', async () => {
		const { ca, crl } = await issueOpenEndedCrl();
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Max Age CRL CA' },
			subject: { commonName: 'invariant-leaf.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});

		expect(
			checkCertificateRevocation({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				evidence: [{ kind: 'crl', crl: crl.pem }],
				crlMaxAgeMs: -1,
			}),
		).rejects.toThrow(RangeError);
	});

	it('applies maxAgeMs through checkCertificateRevocationAgainstCrl', async () => {
		const { ca, crl } = await issueOpenEndedCrl();
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Max Age CRL CA' },
			subject: { commonName: 'max-age-leaf.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});

		const result = await checkCertificateRevocationAgainstCrl({
			certificate: leaf.pem,
			issuerCertificate: ca.certificate.pem,
			crl: crl.pem,
			at: new Date('2100-01-01T00:00:00Z'),
			maxAgeMs: 365 * 24 * 60 * 60 * 1000,
		});
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.code).toBe('stale_crl');
		}
	});
});
