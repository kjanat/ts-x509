import { describe, expect, it } from 'bun:test';
import type { CreatePfxInput } from '#micro509';
import {
	createCertificate,
	createPfx,
	createSelfSignedCertificate,
	exportPkcs8Der,
	generateKeyPair,
	parsePfxDer,
	parsePfxPem,
	unwrap,
} from '#micro509';
import {
	explicitContext,
	integerFromNumber,
	nullValue,
	objectIdentifier,
	octetString,
	readSequenceChildren,
	sequence,
	setOf,
	tlv,
} from '#micro509/internal/asn1/der';
import { OIDS } from '#micro509/internal/asn1/oids';
import { parsePkcs12MacData } from '#micro509/pkcs';
import { childrenOf } from '#test/helpers';

/** Success-path helper: builds a PFX and unwraps the typed result. */
async function buildPfx(input: CreatePfxInput) {
	return unwrap(await createPfx(input));
}

describe('pfx', () => {
	it('creates and parses passwordless PFX bundles', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'PFX Root' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'PFX Root' },
			subject: { commonName: 'pfx-leaf.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const pfx = await buildPfx({
			certificates: [
				{
					certificate: leaf.pem,
					attributes: {
						friendlyName: 'leaf',
						localKeyId: Uint8Array.of(1, 2, 3),
					},
				},
				{
					certificate: ca.certificate.pem,
					attributes: { friendlyName: 'root' },
				},
			],
			privateKeys: [
				{
					privateKey: leafKeys.privateKey,
					attributes: {
						friendlyName: 'leaf',
						localKeyId: Uint8Array.of(1, 2, 3),
					},
				},
			],
		});
		const parsed = await parsePfxPem(pfx.pem);
		expect(parsed.ok).toBe(true);
		if (!parsed.ok) throw new Error('unreachable');
		expect(
			parsed.value.certificates.map((certificate) => certificate.subject.values.commonName),
		).toEqual(['pfx-leaf.example', 'PFX Root']);
		expect(parsed.value.privateKeys).toHaveLength(1);
		expect(parsed.value.bags[0]).toMatchObject({
			kind: 'certificate',
			attributes: { friendlyName: 'leaf', localKeyId: '010203' },
		});
	});

	it('creates and parses encrypted PFX bundles', async () => {
		const keyPair = await generateKeyPair();
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: 'encrypted-pfx.example' },
			keyPair,
		});
		const pfx = await buildPfx({
			certificates: [
				{
					certificate: certificate.certificate.pem,
					attributes: { friendlyName: 'leaf' },
				},
			],
			privateKeys: [
				{
					privateKey: keyPair.privateKey,
					attributes: { friendlyName: 'leaf-key' },
				},
			],
			encryption: { password: 'secret123' },
		});
		const parsed = await parsePfxPem(pfx.pem, { password: 'secret123' });
		expect(parsed.ok).toBe(true);
		if (!parsed.ok) throw new Error('unreachable');
		expect(parsed.value.certificates.map((entry) => entry.subject.values.commonName)).toEqual([
			'encrypted-pfx.example',
		]);
		expect(parsed.value.privateKeys).toHaveLength(1);
		const wrongPassword = await parsePfxPem(pfx.pem, { password: 'wrong' });
		expect(wrongPassword).toMatchObject({
			ok: false,
			code: 'invalid_password',
		});
		if (!wrongPassword.ok) {
			expect(wrongPassword.error.code).toBe('invalid_password');
		}
	});

	it('verifies PFX MAC integrity', async () => {
		const keyPair = await generateKeyPair();
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: 'mac-pfx.example' },
			keyPair,
		});
		const pfx = await buildPfx({
			certificates: [{ certificate: certificate.certificate.pem }],
			privateKeys: [{ privateKey: keyPair.privateKey }],
			mac: { password: 'integrity123' },
		});
		const parsed = await parsePfxPem(pfx.pem, { macPassword: 'integrity123' });
		expect(parsed.ok).toBe(true);
		if (!parsed.ok) throw new Error('unreachable');
		expect(parsed.value.macData?.verification).toBe('valid');
		const wrongMac = await parsePfxPem(pfx.pem, { macPassword: 'wrong' });
		expect(wrongMac).toMatchObject({
			ok: false,
			code: 'invalid_password',
		});
		if (!wrongMac.ok) {
			expect(wrongMac.error.code).toBe('invalid_password');
		}
	});

	it('parsePfxDer rejects truncated DER', async () => {
		const result = await parsePfxDer(Uint8Array.of(0x30, 0x03, 0x02, 0x01, 0x03));
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('malformed');
	});

	it('parsePfxDer rejects completely garbage input', async () => {
		const result = await parsePfxDer(Uint8Array.of(0xff, 0xff));
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('malformed');
	});

	it('parsePfxDer rejects unsupported PFX versions and top-level trailing fields', async () => {
		const authenticatedSafe = sequence([]);
		const authSafe = sequence([
			objectIdentifier(OIDS.pkcs7Data),
			explicitContext(0, octetString(authenticatedSafe)),
		]);
		const unsupportedVersion = await parsePfxDer(sequence([integerFromNumber(2), authSafe]));
		expect(unsupportedVersion).toMatchObject({ ok: false, code: 'malformed' });
		const trailingField = await parsePfxDer(
			sequence([integerFromNumber(3), authSafe, sequence([]), tlv(0x05, new Uint8Array())]),
		);
		expect(trailingField).toMatchObject({ ok: false, code: 'malformed' });
	});

	it('parsePfxPem rejects empty PEM', async () => {
		const result = await parsePfxPem('not a PEM');
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('malformed');
	});

	it('parsePfxPem returns malformed for invalid PEM body text', async () => {
		const result = await parsePfxPem('-----BEGIN PKCS12-----\n%%%\n-----END PKCS12-----');
		expect(result).toMatchObject({ ok: false, code: 'malformed' });
		if (!result.ok) {
			expect(result.error.code).toBe('malformed');
		}
	});

	it('parsePfxPem rejects multiple PFX blocks', async () => {
		const keyPair = await generateKeyPair();
		const cert = await createSelfSignedCertificate({
			subject: { commonName: 'multi-pfx' },
			keyPair,
		});
		const pfx = await buildPfx({
			certificates: [{ certificate: cert.certificate.pem }],
			privateKeys: [{ privateKey: keyPair.privateKey }],
		});
		const doublePem = `${pfx.pem}\n${pfx.pem}`;
		const result = await parsePfxPem(doublePem);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('malformed');
	});

	it('creates and parses PFX with encrypted content and wrong password', async () => {
		const keyPair = await generateKeyPair();
		const cert = await createSelfSignedCertificate({
			subject: { commonName: 'enc-pfx-wrong' },
			keyPair,
		});
		const pfx = await buildPfx({
			certificates: [{ certificate: cert.certificate.pem }],
			privateKeys: [{ privateKey: keyPair.privateKey }],
			encryption: { password: 'correct' },
		});
		// No password provided for encrypted PFX
		const result = await parsePfxDer(pfx.der);
		expect(result.ok).toBe(false);
	});

	// -----------------------------------------------------------------------
	// createPfx input variants
	// -----------------------------------------------------------------------

	it('creates PFX with CryptoKey private key source', async () => {
		const keyPair = await generateKeyPair();
		const cert = await createSelfSignedCertificate({
			subject: { commonName: 'cryptokey-pfx' },
			keyPair,
		});
		// Pass CryptoKey directly (covers normalizePrivateKey CryptoKey path)
		const pfx = await buildPfx({
			certificates: [{ certificate: cert.certificate.pem }],
			privateKeys: [{ privateKey: keyPair.privateKey }],
		});
		const parsed = await parsePfxDer(pfx.der);
		expect(parsed.ok).toBe(true);
		if (!parsed.ok) throw new Error('unreachable');
		expect(parsed.value.privateKeys).toHaveLength(1);
	});

	it('creates PFX with Uint8Array private key source', async () => {
		const keyPair = await generateKeyPair();
		const cert = await createSelfSignedCertificate({
			subject: { commonName: 'uint8-key-pfx' },
			keyPair,
		});
		// Pass Uint8Array PKCS#8 DER (covers normalizePrivateKey Uint8Array path)
		const pkcs8 = await exportPkcs8Der(keyPair.privateKey);
		const pfx = await buildPfx({
			certificates: [{ certificate: cert.certificate.pem }],
			privateKeys: [{ privateKey: pkcs8 }],
		});
		const parsed = await parsePfxDer(pfx.der);
		expect(parsed.ok).toBe(true);
		if (!parsed.ok) throw new Error('unreachable');
		expect(parsed.value.privateKeys).toHaveLength(1);
	});

	it('creates PFX with DER certificate source', async () => {
		const keyPair = await generateKeyPair();
		const cert = await createSelfSignedCertificate({
			subject: { commonName: 'der-cert-pfx' },
			keyPair,
		});
		// Pass Uint8Array certificate DER (covers normalizeCertificate Uint8Array path)
		const pfx = await buildPfx({
			certificates: [{ certificate: cert.certificate.der }],
			privateKeys: [{ privateKey: keyPair.privateKey }],
		});
		const parsed = await parsePfxDer(pfx.der);
		expect(parsed.ok).toBe(true);
		if (!parsed.ok) throw new Error('unreachable');
		expect(parsed.value.certificates).toHaveLength(1);
		expect(parsed.value.certificates[0]?.subject.values.commonName).toBe('der-cert-pfx');
	});

	it('creates PFX with no attributes on bags', async () => {
		const keyPair = await generateKeyPair();
		const cert = await createSelfSignedCertificate({
			subject: { commonName: 'no-attr-pfx' },
			keyPair,
		});
		// No attributes — covers encodeBagAttributes returning []
		const pfx = await buildPfx({
			certificates: [{ certificate: cert.certificate.pem }],
			privateKeys: [{ privateKey: keyPair.privateKey }],
		});
		const parsed = await parsePfxDer(pfx.der);
		expect(parsed.ok).toBe(true);
		if (!parsed.ok) throw new Error('unreachable');
		expect(parsed.value.bags[0]?.attributes.entries).toHaveLength(0);
	});

	// -----------------------------------------------------------------------
	// parsePfx error paths with crafted DER
	// -----------------------------------------------------------------------

	it('parsePfxDer returns password_required for encrypted content without password', async () => {
		const keyPair = await generateKeyPair();
		const cert = await createSelfSignedCertificate({
			subject: { commonName: 'pw-required' },
			keyPair,
		});
		const pfx = await buildPfx({
			certificates: [{ certificate: cert.certificate.pem }],
			privateKeys: [{ privateKey: keyPair.privateKey }],
			encryption: { password: 'secret' },
		});
		// Parse without password — should get password_required
		const result = await parsePfxDer(pfx.der);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.code).toBe('password_required');
		}
	});

	it('parsePfxDer handles PFX with MAC and no macPassword (skips verification)', async () => {
		const keyPair = await generateKeyPair();
		const cert = await createSelfSignedCertificate({
			subject: { commonName: 'mac-no-pw' },
			keyPair,
		});
		const pfx = await buildPfx({
			certificates: [{ certificate: cert.certificate.pem }],
			privateKeys: [{ privateKey: keyPair.privateKey }],
			mac: { password: 'macpw' },
		});
		// Parse without providing macPassword — MAC is parsed but not verified
		const result = await parsePfxDer(pfx.der);
		expect(result.ok).toBe(true);
		if (!result.ok) throw new Error('unreachable');
		// macData should be present but no 'valid' field (password was not provided)
		expect(result.value.macData).toBeDefined();
		expect(result.value.macData?.digestAlgorithmOid).toBeDefined();
		expect(result.value.macData?.digestAlgorithmName).toBe('SHA-256');
	});

	it('parsePfxDer returns invalid_password when MAC verification fails', async () => {
		const keyPair = await generateKeyPair();
		const cert = await createSelfSignedCertificate({
			subject: { commonName: 'mac-bad-pw' },
			keyPair,
		});
		const pfx = await buildPfx({
			certificates: [{ certificate: cert.certificate.pem }],
			privateKeys: [{ privateKey: keyPair.privateKey }],
			mac: { password: 'correct' },
		});
		// Wrong macPassword — MAC is invalid
		const result = await parsePfxDer(pfx.der, { macPassword: 'wrong' });
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('invalid_password');
	});

	it('parsePfxDer handles PFX with both MAC and encryption', async () => {
		const keyPair = await generateKeyPair();
		const cert = await createSelfSignedCertificate({
			subject: { commonName: 'mac-enc-pfx' },
			keyPair,
		});
		const pfx = await buildPfx({
			certificates: [{ certificate: cert.certificate.pem }],
			privateKeys: [{ privateKey: keyPair.privateKey }],
			encryption: { password: 'content-pw' },
			mac: { password: 'mac-pw' },
		});
		// Correct passwords
		const result = await parsePfxDer(pfx.der, { password: 'content-pw', macPassword: 'mac-pw' });
		expect(result.ok).toBe(true);
		if (!result.ok) throw new Error('unreachable');
		expect(result.value.macData?.verification).toBe('valid');
		expect(result.value.certificates).toHaveLength(1);
		expect(result.value.privateKeys).toHaveLength(1);
	});

	it('creates PFX with certificates only (no private keys)', async () => {
		const cert = await createSelfSignedCertificate({
			subject: { commonName: 'certs-only' },
		});
		const pfx = await buildPfx({
			certificates: [{ certificate: cert.certificate.pem }],
		});
		const parsed = await parsePfxDer(pfx.der);
		expect(parsed.ok).toBe(true);
		if (!parsed.ok) throw new Error('unreachable');
		expect(parsed.value.certificates).toHaveLength(1);
		expect(parsed.value.privateKeys).toHaveLength(0);
	});

	it('creates PFX with private keys only (no certificates)', async () => {
		const keyPair = await generateKeyPair();
		const pfx = await buildPfx({
			privateKeys: [{ privateKey: keyPair.privateKey }],
		});
		const parsed = await parsePfxDer(pfx.der);
		expect(parsed.ok).toBe(true);
		if (!parsed.ok) throw new Error('unreachable');
		expect(parsed.value.certificates).toHaveLength(0);
		expect(parsed.value.privateKeys).toHaveLength(1);
	});

	it('createPfx returns invalid_certificate for PEM without CERTIFICATE block', async () => {
		const result = await createPfx({
			certificates: [
				{ certificate: '-----BEGIN PRIVATE KEY-----\nMQ==\n-----END PRIVATE KEY-----' },
			],
		});
		expect(result).toMatchObject({ ok: false, code: 'invalid_certificate' });
		if (!result.ok) {
			expect(result.error.code).toBe('invalid_certificate');
		}
	});

	it('parses PFX with unknown bag type', async () => {
		// Build PFX with a SafeBag using an unknown OID → kind: "unknown"
		const unknownBagOid = '1.2.3.4.5.6.7';
		const unknownValue = octetString(Uint8Array.of(0xde, 0xad));
		const safeBag = sequence([objectIdentifier(unknownBagOid), explicitContext(0, unknownValue)]);
		const safeContents = sequence([safeBag]);
		// Wrap in plaintext ContentInfo
		const contentInfo = sequence([
			objectIdentifier(OIDS.pkcs7Data),
			explicitContext(0, octetString(safeContents)),
		]);
		const authenticatedSafe = sequence([contentInfo]);
		const pfxDer = sequence([
			integerFromNumber(3),
			sequence([
				objectIdentifier(OIDS.pkcs7Data),
				explicitContext(0, octetString(authenticatedSafe)),
			]),
		]);
		const result = await parsePfxDer(pfxDer);
		expect(result.ok).toBe(true);
		if (!result.ok) throw new Error('unreachable');
		expect(result.value.bags).toHaveLength(1);
		expect(result.value.bags[0]?.kind).toBe('unknown');
	});

	it('parses PFX with key bag (PKCS#8 private key)', async () => {
		const keyPair = await generateKeyPair();
		const pkcs8 = await exportPkcs8Der(keyPair.privateKey);
		// Build PFX with a pkcs12KeyBag SafeBag → kind: "privateKey"
		const safeBag = sequence([objectIdentifier(OIDS.pkcs12KeyBag), explicitContext(0, pkcs8)]);
		const safeContents = sequence([safeBag]);
		const contentInfo = sequence([
			objectIdentifier(OIDS.pkcs7Data),
			explicitContext(0, octetString(safeContents)),
		]);
		const authenticatedSafe = sequence([contentInfo]);
		const pfxDer = sequence([
			integerFromNumber(3),
			sequence([
				objectIdentifier(OIDS.pkcs7Data),
				explicitContext(0, octetString(authenticatedSafe)),
			]),
		]);
		const result = await parsePfxDer(pfxDer);
		expect(result.ok).toBe(true);
		if (!result.ok) throw new Error('unreachable');
		expect(result.value.bags).toHaveLength(1);
		expect(result.value.bags[0]?.kind).toBe('privateKey');
		expect(result.value.privateKeys).toHaveLength(1);
	});

	it('parsePfxDer rejects PFX with unsupported ContentInfo type', async () => {
		// Build PFX whose authenticatedSafe contains a ContentInfo with an unsupported OID
		const badContentInfo = sequence([
			objectIdentifier('1.2.3.4.5'), // not pkcs7Data or pkcs7EncryptedData
			explicitContext(0, octetString(Uint8Array.of(0x01))),
		]);
		const authenticatedSafe = sequence([badContentInfo]);
		const pfxDer = sequence([
			integerFromNumber(3),
			sequence([
				objectIdentifier(OIDS.pkcs7Data),
				explicitContext(0, octetString(authenticatedSafe)),
			]),
		]);
		const result = await parsePfxDer(pfxDer);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('malformed');
	});

	it('parsePfxDer returns malformed for ContentInfo with missing content', async () => {
		// ContentInfo with only OID, no content
		const badContentInfo = sequence([objectIdentifier(OIDS.pkcs7Data)]);
		const authenticatedSafe = sequence([badContentInfo]);
		const pfxDer = sequence([
			integerFromNumber(3),
			sequence([
				objectIdentifier(OIDS.pkcs7Data),
				explicitContext(0, octetString(authenticatedSafe)),
			]),
		]);
		const result = await parsePfxDer(pfxDer);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('malformed');
	});

	it('parsePfxDer returns malformed for SafeBag with missing bagValue', async () => {
		// SafeBag with only bagId, no bagValue
		const badSafeBag = sequence([objectIdentifier(OIDS.pkcs12CertBag)]);
		const safeContents = sequence([badSafeBag]);
		const contentInfo = sequence([
			objectIdentifier(OIDS.pkcs7Data),
			explicitContext(0, octetString(safeContents)),
		]);
		const authenticatedSafe = sequence([contentInfo]);
		const pfxDer = sequence([
			integerFromNumber(3),
			sequence([
				objectIdentifier(OIDS.pkcs7Data),
				explicitContext(0, octetString(authenticatedSafe)),
			]),
		]);
		const result = await parsePfxDer(pfxDer);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('malformed');
	});

	it('parsePfxDer returns malformed for certBag with missing cert value', async () => {
		// certBag with only certType OID, no cert value
		const certBag = sequence([objectIdentifier(OIDS.x509CertificateBagType)]);
		const safeBag = sequence([objectIdentifier(OIDS.pkcs12CertBag), explicitContext(0, certBag)]);
		const safeContents = sequence([safeBag]);
		const contentInfo = sequence([
			objectIdentifier(OIDS.pkcs7Data),
			explicitContext(0, octetString(safeContents)),
		]);
		const authenticatedSafe = sequence([contentInfo]);
		const pfxDer = sequence([
			integerFromNumber(3),
			sequence([
				objectIdentifier(OIDS.pkcs7Data),
				explicitContext(0, octetString(authenticatedSafe)),
			]),
		]);
		const result = await parsePfxDer(pfxDer);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('malformed');
	});

	it('parsePfxDer rejects certBag entries with non-x509 certType OIDs', async () => {
		const cert = await createSelfSignedCertificate({
			subject: { commonName: 'wrong-cert-type-pfx' },
		});
		const certBag = sequence([
			objectIdentifier('1.2.3.4.5'),
			explicitContext(0, octetString(cert.certificate.der)),
		]);
		const safeBag = sequence([objectIdentifier(OIDS.pkcs12CertBag), explicitContext(0, certBag)]);
		const pfxDer = wrapSafeBags([safeBag]);

		const result = await parsePfxDer(pfxDer);
		expect(result).toMatchObject({ ok: false, code: 'malformed' });
	});

	it('parsePfxDer returns malformed when extractContextChild gets non-context tag', async () => {
		// Put a SEQUENCE where context-specific [0] is expected for bag value
		// This tests extractContextChild's (element.tag & 0xe0) !== 0xa0 check
		const safeBag = sequence([
			objectIdentifier(OIDS.pkcs12CertBag),
			// Use SEQUENCE (0x30) instead of [0] EXPLICIT context
			sequence([octetString(Uint8Array.of(0x01))]),
		]);
		const safeContents = sequence([safeBag]);
		const contentInfo = sequence([
			objectIdentifier(OIDS.pkcs7Data),
			explicitContext(0, octetString(safeContents)),
		]);
		const authenticatedSafe = sequence([contentInfo]);
		const pfxDer = sequence([
			integerFromNumber(3),
			sequence([
				objectIdentifier(OIDS.pkcs7Data),
				explicitContext(0, octetString(authenticatedSafe)),
			]),
		]);
		const result = await parsePfxDer(pfxDer);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('malformed');
	});

	it('parsePfxDer returns malformed for bag attribute with missing values', async () => {
		// SafeBag with attribute SET containing an attribute with only OID, no value SET
		const attrWithOnlyOid = sequence([objectIdentifier('1.2.3.4')]);
		const safeBag = sequence([
			objectIdentifier('1.2.3.4.5.6'),
			explicitContext(0, octetString(Uint8Array.of(0x01))),
			setOf([attrWithOnlyOid]),
		]);
		const safeContents = sequence([safeBag]);
		const contentInfo = sequence([
			objectIdentifier(OIDS.pkcs7Data),
			explicitContext(0, octetString(safeContents)),
		]);
		const authenticatedSafe = sequence([contentInfo]);
		const pfxDer = sequence([
			integerFromNumber(3),
			sequence([
				objectIdentifier(OIDS.pkcs7Data),
				explicitContext(0, octetString(authenticatedSafe)),
			]),
		]);
		const result = await parsePfxDer(pfxDer);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('malformed');
	});

	it('parsePfxDer rejects repeated friendlyName attributes', async () => {
		const safeBag = sequence([
			objectIdentifier('1.2.3.4.5.6'),
			explicitContext(0, octetString(Uint8Array.of(0x01))),
			setOf([
				sequence([objectIdentifier(OIDS.friendlyName), setOf([bmpString('first')])]),
				sequence([objectIdentifier(OIDS.friendlyName), setOf([bmpString('second')])]),
			]),
		]);
		const result = await parsePfxDer(wrapSafeBags([safeBag]));
		expect(result).toMatchObject({ ok: false, code: 'malformed' });
	});

	it('parsePfxDer rejects empty known shorthand attribute value sets', async () => {
		const safeBag = sequence([
			objectIdentifier('1.2.3.4.5.6'),
			explicitContext(0, octetString(Uint8Array.of(0x01))),
			setOf([sequence([objectIdentifier(OIDS.friendlyName), setOf([])])]),
		]);
		const result = await parsePfxDer(wrapSafeBags([safeBag]));
		expect(result).toMatchObject({ ok: false, code: 'malformed' });
	});

	it('parsePfxDer rejects malformed known shorthand attribute containers', async () => {
		const safeBag = sequence([
			objectIdentifier('1.2.3.4.5.6'),
			explicitContext(0, octetString(Uint8Array.of(0x01))),
			setOf([
				sequence([objectIdentifier(OIDS.friendlyName), sequence([bmpString('wrong-container')])]),
			]),
		]);
		const result = await parsePfxDer(wrapSafeBags([safeBag]));
		expect(result).toMatchObject({ ok: false, code: 'malformed' });
	});

	it('parsePfxDer rejects friendlyName values with wrong string tag', async () => {
		const safeBag = sequence([
			objectIdentifier('1.2.3.4.5.6'),
			explicitContext(0, octetString(Uint8Array.of(0x01))),
			setOf([sequence([objectIdentifier(OIDS.friendlyName), setOf([integerFromNumber(7)])])]),
		]);
		const result = await parsePfxDer(wrapSafeBags([safeBag]));
		expect(result).toMatchObject({ ok: false, code: 'malformed' });
	});

	it('parsePfxDer rejects malformed localKeyId attribute values', async () => {
		const safeBag = sequence([
			objectIdentifier('1.2.3.4.5.6'),
			explicitContext(0, octetString(Uint8Array.of(0x01))),
			setOf([
				sequence([
					objectIdentifier(OIDS.localKeyId),
					setOf([integerFromNumber(1), octetString(Uint8Array.of(0x02))]),
				]),
			]),
		]);
		const result = await parsePfxDer(wrapSafeBags([safeBag]));
		expect(result).toMatchObject({ ok: false, code: 'malformed' });
	});

	it('parsePfxDer rejects single localKeyId values with wrong tag', async () => {
		const safeBag = sequence([
			objectIdentifier('1.2.3.4.5.6'),
			explicitContext(0, octetString(Uint8Array.of(0x01))),
			setOf([sequence([objectIdentifier(OIDS.localKeyId), setOf([integerFromNumber(1)])])]),
		]);
		const result = await parsePfxDer(wrapSafeBags([safeBag]));
		expect(result).toMatchObject({ ok: false, code: 'malformed' });
	});

	it('parses PFX with bag attribute having empty value set', async () => {
		// SafeBag with attribute that has a values SET but no values inside
		// This covers the firstValue === undefined continue path
		const attrWithEmptyValues = sequence([
			objectIdentifier('1.2.3.4'),
			setOf([]), // empty values SET
		]);
		const unknownBag = sequence([
			objectIdentifier('1.2.3.4.5.6'),
			explicitContext(0, octetString(Uint8Array.of(0x01))),
			setOf([attrWithEmptyValues]),
		]);
		const safeContents = sequence([unknownBag]);
		const contentInfo = sequence([
			objectIdentifier(OIDS.pkcs7Data),
			explicitContext(0, octetString(safeContents)),
		]);
		const authenticatedSafe = sequence([contentInfo]);
		const pfxDer = sequence([
			integerFromNumber(3),
			sequence([
				objectIdentifier(OIDS.pkcs7Data),
				explicitContext(0, octetString(authenticatedSafe)),
			]),
		]);
		const result = await parsePfxDer(pfxDer);
		expect(result.ok).toBe(true);
		if (!result.ok) throw new Error('unreachable');
		expect(result.value.bags[0]?.attributes.entries).toHaveLength(1);
		expect(result.value.bags[0]?.attributes.friendlyName).toBeUndefined();
	});

	it('parsePfxDer returns malformed for encrypted data with bad encrypted content', async () => {
		// Build encrypted ContentInfo with malformed EncryptedData — decryptEncryptedData
		// throws which gets caught and surfaced as invalid_password
		const encryptedData = sequence([integerFromNumber(0)]);
		const encryptedContentInfo = sequence([
			objectIdentifier(OIDS.pkcs7EncryptedData),
			explicitContext(0, encryptedData),
		]);
		const authenticatedSafe = sequence([encryptedContentInfo]);
		const pfxDer = sequence([
			integerFromNumber(3),
			sequence([
				objectIdentifier(OIDS.pkcs7Data),
				explicitContext(0, octetString(authenticatedSafe)),
			]),
		]);
		const result = await parsePfxDer(pfxDer, { password: 'test' });
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('malformed');
	});

	it('parsePfxDer returns malformed when MAC data parsing throws (lines 198-201)', async () => {
		// Build PFX with a MAC section that has totally invalid structure,
		// causing parsePkcs12MacData to throw
		const authenticatedSafe = sequence([]); // empty safe contents
		const contentInfo = sequence([
			objectIdentifier(OIDS.pkcs7Data),
			explicitContext(0, octetString(authenticatedSafe)),
		]);
		// MAC section: use a completely malformed SEQUENCE (not valid MacData)
		const malformedMac = sequence([integerFromNumber(999)]);
		const pfxDer = sequence([integerFromNumber(3), contentInfo, malformedMac]);
		const result = await parsePfxDer(pfxDer, { password: 'test' });
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('malformed');
	});

	it('extractContentInfoData throws on malformed outer ContentInfo (line 281)', async () => {
		// Build PFX where the OUTER AuthSafe ContentInfo has only one child (missing content)
		const malformedAuthSafe = sequence([objectIdentifier(OIDS.pkcs7Data)]);
		// No explicitContext(0, ...) → missing second child in outer ContentInfo
		const pfxDer = sequence([integerFromNumber(3), malformedAuthSafe]);
		const result = await parsePfxDer(pfxDer);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('malformed');
	});

	it('parsePfxDer rejects ContentInfo wrappers with trailing fields or multi-value contexts', async () => {
		const malformedAuthSafe = sequence([
			objectIdentifier(OIDS.pkcs7Data),
			explicitContext(0, octetString(sequence([]))),
			tlv(0x05, new Uint8Array()),
		]);
		const outerResult = await parsePfxDer(sequence([integerFromNumber(3), malformedAuthSafe]));
		expect(outerResult).toMatchObject({ ok: false, code: 'malformed' });

		const multiValueContentInfo = sequence([
			objectIdentifier(OIDS.pkcs7Data),
			explicitContext(0, new Uint8Array([0x04, 0x00, 0x04, 0x00])),
		]);
		const innerResult = await parsePfxDer(
			sequence([
				integerFromNumber(3),
				sequence([
					objectIdentifier(OIDS.pkcs7Data),
					explicitContext(0, octetString(sequence([multiValueContentInfo]))),
				]),
			]),
		);
		expect(innerResult).toMatchObject({ ok: false, code: 'malformed' });
	});

	it('extractContentInfoData throws on non-pkcs7Data outer content type (line 284)', async () => {
		// Outer ContentInfo with wrong content type OID
		const wrongTypeAuthSafe = sequence([
			objectIdentifier('1.2.840.113549.1.7.3'), // envelopedData, not pkcs7Data
			explicitContext(0, octetString(new Uint8Array([0x30, 0x00]))),
		]);
		const pfxDer = sequence([integerFromNumber(3), wrongTypeAuthSafe]);
		const result = await parsePfxDer(pfxDer);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('malformed');
	});

	it('decryptEncryptedData returns malformed on malformed EncryptedContentInfo (lines 560, 563)', async () => {
		// Build encrypted ContentInfo where EncryptedData has EncryptedContentInfo
		// with only one child (contentType OID, missing algorithm and encrypted content)
		const encryptedContentInfo = sequence([
			objectIdentifier(OIDS.pkcs7Data), // contentType
			// Missing algorithmIdentifier and encryptedContent
		]);
		const encryptedData = sequence([
			integerFromNumber(0), // version
			encryptedContentInfo,
		]);
		const encContentInfo = sequence([
			objectIdentifier(OIDS.pkcs7EncryptedData),
			explicitContext(0, encryptedData),
		]);
		const authenticatedSafe = sequence([encContentInfo]);
		const pfxDer = sequence([
			integerFromNumber(3),
			sequence([
				objectIdentifier(OIDS.pkcs7Data),
				explicitContext(0, octetString(authenticatedSafe)),
			]),
		]);
		const result = await parsePfxDer(pfxDer, { password: 'test' });
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('malformed');
	});

	it('decryptEncryptedData returns malformed on wrong encrypted content tag (line 563)', async () => {
		// EncryptedContentInfo with algorithm and content, but content tag is not 0x80
		const encryptedContentInfo = sequence([
			objectIdentifier(OIDS.pkcs7Data), // contentType
			sequence([objectIdentifier('1.2.840.113549.1.5.13')]), // algorithm
			octetString(new Uint8Array([0x01, 0x02])), // OCTET STRING (tag 0x04) instead of [0] (tag 0x80)
		]);
		const encryptedData = sequence([
			integerFromNumber(0), // version
			encryptedContentInfo,
		]);
		const encContentInfo = sequence([
			objectIdentifier(OIDS.pkcs7EncryptedData),
			explicitContext(0, encryptedData),
		]);
		const authenticatedSafe = sequence([encContentInfo]);
		const pfxDer = sequence([
			integerFromNumber(3),
			sequence([
				objectIdentifier(OIDS.pkcs7Data),
				explicitContext(0, octetString(authenticatedSafe)),
			]),
		]);
		const result = await parsePfxDer(pfxDer, { password: 'test' });
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('malformed');
	});

	it('parsePfxDer rejects EncryptedData trailing fields and odd-length friendlyName BMPString values', async () => {
		const encryptedContentInfo = sequence([
			objectIdentifier(OIDS.pkcs7Data),
			sequence([objectIdentifier(OIDS.pbes2), sequence([])]),
			tlv(0x80, Uint8Array.of(0x01, 0x02)),
		]);
		const encryptedData = sequence([integerFromNumber(0), encryptedContentInfo, setOf([])]);
		const encryptedResult = await parsePfxDer(
			sequence([
				integerFromNumber(3),
				sequence([
					objectIdentifier(OIDS.pkcs7Data),
					explicitContext(
						0,
						octetString(
							sequence([
								sequence([
									objectIdentifier(OIDS.pkcs7EncryptedData),
									explicitContext(0, encryptedData),
								]),
							]),
						),
					),
				]),
			]),
			{ password: 'test' },
		);
		expect(encryptedResult).toMatchObject({ ok: false, code: 'malformed' });

		const oddFriendlyName = await parsePfxDer(
			wrapSafeBags([
				sequence([
					objectIdentifier('1.2.3.4.5.6'),
					explicitContext(0, octetString(Uint8Array.of(0x01))),
					setOf([
						sequence([
							objectIdentifier(OIDS.friendlyName),
							setOf([Uint8Array.of(0x1e, 0x01, 0x00)]),
						]),
					]),
				]),
			]),
		);
		expect(oddFriendlyName).toMatchObject({ ok: false, code: 'malformed' });
	});

	it('parsePfxDer returns malformed for invalid PBES2 parameters', async () => {
		const encryptedContentInfo = sequence([
			objectIdentifier(OIDS.pkcs7Data),
			sequence([
				objectIdentifier(OIDS.pbes2),
				sequence([
					sequence([
						objectIdentifier(OIDS.pbkdf2),
						sequence([octetString(Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8)), integerFromNumber(0)]),
					]),
					sequence([objectIdentifier(OIDS.aes256Cbc), octetString(new Uint8Array(16))]),
				]),
			]),
			tlv(0x80, Uint8Array.of(0x01, 0x02)),
		]);
		const encryptedData = sequence([integerFromNumber(0), encryptedContentInfo]);
		const contentInfo = sequence([
			objectIdentifier(OIDS.pkcs7EncryptedData),
			explicitContext(0, encryptedData),
		]);
		const authenticatedSafe = sequence([contentInfo]);
		const pfxDer = sequence([
			integerFromNumber(3),
			sequence([
				objectIdentifier(OIDS.pkcs7Data),
				explicitContext(0, octetString(authenticatedSafe)),
			]),
		]);
		const result = await parsePfxDer(pfxDer, { password: 'test' });
		expect(result).toMatchObject({ ok: false, code: 'malformed' });
	});

	it('extractContextOctetString throws when context child is not OCTET STRING (line 581)', async () => {
		// ContentInfo with pkcs7Data type but context value containing INTEGER instead of OCTET STRING
		const badContextContentInfo = sequence([
			objectIdentifier(OIDS.pkcs7Data),
			explicitContext(0, integerFromNumber(42)), // INTEGER, not OCTET STRING
		]);
		const authenticatedSafe = sequence([badContextContentInfo]);
		const pfxDer = sequence([
			integerFromNumber(3),
			sequence([
				objectIdentifier(OIDS.pkcs7Data),
				explicitContext(0, octetString(authenticatedSafe)),
			]),
		]);
		const result = await parsePfxDer(pfxDer);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('malformed');
	});
});

function wrapSafeBags(bags: readonly Uint8Array[]): Uint8Array {
	const safeContents = sequence(bags);
	const contentInfo = sequence([
		objectIdentifier(OIDS.pkcs7Data),
		explicitContext(0, octetString(safeContents)),
	]);
	const authenticatedSafe = sequence([contentInfo]);
	return sequence([
		integerFromNumber(3),
		sequence([
			objectIdentifier(OIDS.pkcs7Data),
			explicitContext(0, octetString(authenticatedSafe)),
		]),
	]);
}

function bmpString(value: string): Uint8Array {
	const bytes = new Uint8Array(value.length * 2);
	for (let index = 0; index < value.length; index += 1) {
		const codePoint = value.charCodeAt(index);
		bytes[index * 2] = codePoint >> 8;
		bytes[index * 2 + 1] = codePoint & 0xff;
	}
	return new Uint8Array([0x1e, bytes.length, ...bytes]);
}

describe('PFX KDF work-factor limit', () => {
	async function issuePfx(iterations: { readonly encryption: number; readonly mac: number }) {
		const keys = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
		return buildPfx({
			privateKeys: [{ privateKey: keys.privateKey }],
			encryption: { password: 'pw', iterations: iterations.encryption },
			mac: { password: 'pw', iterations: iterations.mac },
		});
	}

	it('rejects MacData iteration counts above maxKdfIterations', async () => {
		const pfx = await issuePfx({ encryption: 1024, mac: 4096 });
		const result = await parsePfxDer(pfx.der, { password: 'pw', maxKdfIterations: 2048 });
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.code).toBe('kdf_iterations_exceeded');
		}
	});

	it('rejects PBES2 iteration counts above maxKdfIterations', async () => {
		const pfx = await issuePfx({ encryption: 4096, mac: 1024 });
		const result = await parsePfxDer(pfx.der, { password: 'pw', maxKdfIterations: 2048 });
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.code).toBe('kdf_iterations_exceeded');
		}
		const accepted = await parsePfxDer(pfx.der, { password: 'pw', maxKdfIterations: 4096 });
		expect(accepted.ok).toBe(true);
	});

	it('caps PKCS#12 MAC iterations at 100,000 by default', async () => {
		// The PKCS#12 KDF runs one awaited digest per round from JS, so it costs
		// far more per iteration than native PBKDF2 and needs a lower ceiling.
		const macData = (iterations: number) =>
			sequence([
				sequence([
					sequence([objectIdentifier(OIDS.sha256), nullValue()]),
					octetString(new Uint8Array(32)),
				]),
				octetString(new Uint8Array(8)),
				integerFromNumber(iterations),
			]);

		const rejected = await parsePkcs12MacData(macData(100_001), new Uint8Array(4), 'pw');
		expect(rejected.ok).toBe(false);
		if (!rejected.ok) {
			expect(rejected.code).toBe('kdf_iterations_exceeded');
		}

		const accepted = await parsePkcs12MacData(macData(2_048), new Uint8Array(4), 'pw');
		expect(accepted.ok).toBe(true);
	});

	it('bounds KDF work across every encrypted entry, not per entry', async () => {
		const keys = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
		const base = await buildPfx({
			privateKeys: [{ privateKey: keys.privateKey }],
			encryption: { password: 'pw', iterations: 1_000 },
		});

		// createPfx emits one encrypted ContentInfo; repeat it so the file asks
		// for the same work many times over without any single count standing out.
		const top = readSequenceChildren(base.der);
		const authSafe = top[1];
		if (authSafe === undefined) throw new Error('missing AuthenticatedSafe');
		const authSafeDer = base.der.slice(authSafe.start - authSafe.headerLength, authSafe.end);
		const wrapper = readSequenceChildren(authSafeDer)[1];
		if (wrapper === undefined) throw new Error('missing content wrapper');
		const octets = childrenOf(authSafeDer, wrapper)[0];
		if (octets === undefined) throw new Error('missing content octets');
		const entries = readSequenceChildren(octets.value);
		const entry = entries[0];
		if (entry === undefined) throw new Error('missing encrypted entry');
		const entryDer = octets.value.slice(entry.start - entry.headerLength, entry.end);

		const repeats = 50;
		const inflated = sequence([
			integerFromNumber(3),
			sequence([
				objectIdentifier(OIDS.pkcs7Data),
				explicitContext(0, octetString(sequence(Array.from({ length: repeats }, () => entryDer)))),
			]),
		]);

		// Each entry asks for 1,000 rounds, well under the ceiling; together they
		// ask for 50,000.
		const result = await parsePfxDer(inflated, { password: 'pw', maxKdfIterations: 10_000 });
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.code).toBe('kdf_iterations_exceeded');
		}

		const withinBudget = await parsePfxDer(inflated, { password: 'pw', maxKdfIterations: 60_000 });
		expect(withinBudget.ok).toBe(true);
	});

	it('reports an invalid maxKdfIterations as an invariant, not malformed input', async () => {
		const pfx = await issuePfx({ encryption: 1024, mac: 1024 });

		expect(parsePfxDer(pfx.der, { password: 'pw', maxKdfIterations: 0 })).rejects.toThrow(
			RangeError,
		);
	});
});
