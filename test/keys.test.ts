import { describe, expect, it, test } from 'bun:test';
import { X509Certificate } from 'node:crypto';
import type { KeyPairMaterial } from '#micro509';
import {
	createCertificate,
	decryptRsaOaep,
	decryptRsaOaepOrThrow,
	derivePublicKey,
	encryptRsaOaep,
	encryptRsaOaepOrThrow,
	exportBinaryBase64,
	exportEncryptedPkcs1Pem,
	exportEncryptedPkcs8Der,
	exportEncryptedPkcs8Pem,
	exportEncryptedSec1Pem,
	exportPkcs1Der,
	exportPkcs1Pem,
	exportPkcs8Der,
	exportPkcs8Pem,
	exportPrivateJwk,
	exportPublicJwk,
	exportSec1Der,
	exportSec1Pem,
	exportSpkiDer,
	exportSpkiPem,
	generateKeyPair,
	importEncryptedPkcs1Pem,
	importEncryptedPkcs1PemOrThrow,
	importEncryptedPkcs8Der,
	importEncryptedPkcs8Pem,
	importEncryptedSec1Pem,
	importEncryptedSec1PemOrThrow,
	importPkcs1Der,
	importPkcs1Pem,
	importPkcs8Base64,
	importPkcs8Der,
	importPkcs8Pem,
	importPrivateJwk,
	importPrivateJwkOrThrow,
	importPublicJwk,
	importSec1Der,
	importSec1DerOrThrow,
	importSec1Pem,
	importSpkiBase64,
	importSpkiDer,
	importSpkiPem,
	inspectEncryptedPkcs8Der,
	pemEncode,
	unwrap,
} from '#micro509';
import { toArrayBuffer, toHex } from '#micro509/internal/asn1/asn1';
import { concatBytes, integerFromNumber, octetString, sequence } from '#micro509/internal/asn1/der';
import { md5 } from '#micro509/internal/crypto/hash';
import { encodePbes2AlgorithmIdentifier } from '#micro509/internal/crypto/pbes2';
import { base64Encode } from '#micro509/internal/shared/base64';
import { hexToBytes } from '#test/helpers';

/** Minimal shape every `import*` Result satisfies, success or failure. */
type FailableImport =
	| { readonly ok: true; readonly value: CryptoKey }
	| { readonly ok: false; readonly error: { readonly code: string; readonly message: string } };

/** Assert an import Result failed with the given code and, optionally, a message substring. */
async function expectImportFailure(
	pending: Promise<FailableImport>,
	code: string,
	messagePart?: string,
): Promise<void> {
	const result = await pending;
	expect(result.ok).toBe(false);
	if (result.ok) {
		return;
	}
	expect(result.error.code).toBe(code);
	if (messagePart !== undefined) expect(result.error.message).toContain(messagePart);
}

/** Assert a throwing-variant promise rejected with a message containing `messagePart`. */
async function expectRejection(pending: Promise<unknown>, messagePart: string): Promise<void> {
	try {
		await pending;
	} catch (error) {
		expect(error instanceof Error ? error.message : String(error)).toContain(messagePart);
		return;
	}
	throw new Error(`expected a rejection containing '${messagePart}', but it resolved`);
}

/**
 * Header lines RFC 822 §3.2 excludes from `field-name`: empty, embedded SPACE,
 * an embedded CTL, and non-ASCII.
 */
const MALFORMED_PEM_HEADER_NAMES = [
	':junk',
	'Bad Name:thing',
	'Bad\u0001Name:thing',
	'Ünicode:thing',
] as const;

/** Encrypt arbitrary DER as a traditional RSA PEM fixture for structural-error tests. */
async function encryptTraditionalRsaFixture(der: Uint8Array, password: string): Promise<string> {
	const iv = Uint8Array.from({ length: 16 }, (_, index) => index);
	const passwordBytes = new TextEncoder().encode(password);
	const keyBytes = new Uint8Array(32);
	let previous = new Uint8Array();
	let offset = 0;
	while (offset < keyBytes.length) {
		previous = md5(concatBytes([previous, passwordBytes, iv.slice(0, 8)]));
		const length = Math.min(previous.length, keyBytes.length - offset);
		keyBytes.set(previous.slice(0, length), offset);
		offset += length;
	}
	const key = await crypto.subtle.importKey(
		'raw',
		toArrayBuffer(keyBytes),
		{ name: 'AES-CBC', length: 256 },
		false,
		['encrypt'],
	);
	const encrypted = new Uint8Array(
		await crypto.subtle.encrypt(
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
		'-----BEGIN RSA PRIVATE KEY-----',
		'Proc-Type: 4,ENCRYPTED',
		`DEK-Info: AES-256-CBC,${toHex(iv).toUpperCase()}`,
		'',
		body,
		'-----END RSA PRIVATE KEY-----',
	].join('\n');
}

describe('keys', () => {
	it('roundtrips RSA PKCS#1 and EC SEC1 private keys', async () => {
		const rsa = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const pkcs1Pem = await exportPkcs1Pem(rsa.privateKey);
		const pkcs1Der = await exportPkcs1Der(rsa.privateKey);
		const rsaFromPem = unwrap(await importPkcs1Pem(pkcs1Pem, { kind: 'rsa' }));
		const rsaFromDer = unwrap(await importPkcs1Der(pkcs1Der, { kind: 'rsa' }));
		expect(await exportPkcs8Der(rsaFromPem)).toEqual(await exportPkcs8Der(rsa.privateKey));
		expect(await exportPkcs8Der(rsaFromDer)).toEqual(await exportPkcs8Der(rsa.privateKey));

		const ec = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
		const sec1Pem = await exportSec1Pem(ec.privateKey);
		const sec1Der = await exportSec1Der(ec.privateKey);
		const ecFromPem = unwrap(
			await importSec1Pem(sec1Pem, {
				kind: 'ecdsa',
				curve: 'P-256',
			}),
		);
		const ecFromDer = unwrap(
			await importSec1Der(sec1Der, {
				kind: 'ecdsa',
				curve: 'P-256',
			}),
		);
		expect(await exportPkcs8Der(ecFromPem)).toEqual(await exportPkcs8Der(ec.privateKey));
		expect(await exportPkcs8Der(ecFromDer)).toEqual(await exportPkcs8Der(ec.privateKey));
	});

	it('roundtrips encrypted PKCS#8 helpers', async () => {
		const keyPair = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const cases = [
			{ cipher: 'AES-128-CBC', prf: 'HMAC-SHA-1' },
			{ cipher: 'AES-128-CBC', prf: 'HMAC-SHA-256' },
			{ cipher: 'AES-192-CBC', prf: 'HMAC-SHA-1' },
			{ cipher: 'AES-192-CBC', prf: 'HMAC-SHA-256' },
			{ cipher: 'AES-256-CBC', prf: 'HMAC-SHA-1' },
			{ cipher: 'AES-256-CBC', prf: 'HMAC-SHA-256' },
		] as const;
		for (const testCase of cases) {
			const pem = await exportEncryptedPkcs8Pem(keyPair.privateKey, {
				password: 'secret123',
				...testCase,
			});
			const der = await exportEncryptedPkcs8Der(keyPair.privateKey, {
				password: 'secret123',
				...testCase,
			});
			const importedPem = unwrap(
				await importEncryptedPkcs8Pem(pem, 'secret123', {
					kind: 'rsa',
				}),
			);
			const importedDer = unwrap(
				await importEncryptedPkcs8Der(der, 'secret123', {
					kind: 'rsa',
				}),
			);
			expect(await exportPkcs8Der(importedPem)).toEqual(await exportPkcs8Der(keyPair.privateKey));
			expect(await exportPkcs8Der(importedDer)).toEqual(await exportPkcs8Der(keyPair.privateKey));
		}

		const pem = await exportEncryptedPkcs8Pem(keyPair.privateKey, {
			password: 'secret123',
		});
		await expectImportFailure(
			importEncryptedPkcs8Pem(pem, 'wrong', { kind: 'rsa' }),
			'invalid_password',
			'Invalid password or encrypted content',
		);
	});

	it('inspectEncryptedPkcs8Der reads PBES2 parameters without the password', async () => {
		const keyPair = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
		const der = await exportEncryptedPkcs8Der(keyPair.privateKey, {
			password: 'secret123',
			iterations: 2_048,
			cipher: 'AES-128-CBC',
			prf: 'HMAC-SHA-1',
		});
		const parameters = inspectEncryptedPkcs8Der(der);

		expect(parameters.iterations).toBe(2_048);
		expect(parameters.cipher).toBe('AES-128-CBC');
		expect(parameters.prf).toBe('HMAC-SHA-1');
		expect(parameters.salt.length).toBeGreaterThanOrEqual(8);
		expect(parameters.iv).toHaveLength(16);
		expect(() => inspectEncryptedPkcs8Der(Uint8Array.of(0x30, 0x00))).toThrow(
			'Malformed EncryptedPrivateKeyInfo',
		);
	});

	it('returns invalid_password when decrypting PKCS#8 DER with the wrong password', async () => {
		const keyPair = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
		const der = await exportEncryptedPkcs8Der(keyPair.privateKey, { password: 'right' });
		const result = await importEncryptedPkcs8Der(der, 'wrong', {
			kind: 'ecdsa',
			curve: 'P-256',
		});
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.code).toBe('invalid_password');
		}
	});

	it('reports corrupted traditional PEM ciphertext as invalid_password', async () => {
		// Altering the first ciphertext block garbles the first two plaintext
		// blocks and leaves the trailing PKCS#7 padding intact, so AES-CBC
		// decryption succeeds and only the key structure reveals the damage.
		const corruptFirstCipherBlock = (pem: string): string => {
			const lines = pem.split('\n');
			const bodyIndex = lines.indexOf('') + 1;
			const line = lines[bodyIndex];
			if (line === undefined || line.length === 0) {
				throw new Error('encrypted PEM has no body');
			}
			lines[bodyIndex] = `${line[0] === 'A' ? 'B' : 'A'}${line.slice(1)}`;
			return lines.join('\n');
		};

		const rsa = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const rsaPem = await exportEncryptedPkcs1Pem(rsa.privateKey, { password: 'secret123' });
		await expectImportFailure(
			importEncryptedPkcs1Pem(corruptFirstCipherBlock(rsaPem), 'secret123', { kind: 'rsa' }),
			'invalid_password',
			'Invalid password or encrypted PEM content',
		);

		const ec = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
		const ecPem = await exportEncryptedSec1Pem(ec.privateKey, { password: 'secret123' });
		await expectImportFailure(
			importEncryptedSec1Pem(corruptFirstCipherBlock(ecPem), 'secret123', {
				kind: 'ecdsa',
				curve: 'P-256',
			}),
			'invalid_password',
			'Invalid password or encrypted PEM content',
		);

		// Relabelling decrypts cleanly and yields an ECPrivateKey where an
		// RSAPrivateKey belongs, so only the structure check rejects it.
		await expectImportFailure(
			importEncryptedPkcs1Pem(ecPem.replaceAll('EC PRIVATE KEY', 'RSA PRIVATE KEY'), 'secret123', {
				kind: 'rsa',
			}),
			'invalid_password',
			'Invalid password or encrypted PEM content',
		);
	});

	it('reports malformed PKCS#1 multiprime structures as invalid_password', async () => {
		const password = 'secret123';
		const rsaFields = Array.from({ length: 8 }, (_, index) => integerFromNumber(index + 2));
		const otherPrimeInfo = sequence([
			integerFromNumber(11),
			integerFromNumber(13),
			integerFromNumber(17),
		]);
		const malformed = [
			sequence([integerFromNumber(0), ...rsaFields, sequence([otherPrimeInfo])]),
			sequence([integerFromNumber(1), ...rsaFields]),
			sequence([integerFromNumber(1), ...rsaFields, integerFromNumber(19)]),
			sequence([integerFromNumber(1), ...rsaFields, sequence([])]),
			sequence([
				integerFromNumber(1),
				...rsaFields,
				sequence([sequence([integerFromNumber(11), integerFromNumber(13)])]),
			]),
		];
		for (const der of malformed) {
			await expectImportFailure(
				importEncryptedPkcs1Pem(await encryptTraditionalRsaFixture(der, password), password, {
					kind: 'rsa',
				}),
				'invalid_password',
				'Invalid password or encrypted PEM content',
			);
		}
	});

	it('roundtrips encrypted traditional RSA and EC PEM helpers', async () => {
		const rsa = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const encryptedRsaPem = await exportEncryptedPkcs1Pem(rsa.privateKey, {
			password: 'secret123',
		});
		const importedRsa = unwrap(
			await importEncryptedPkcs1Pem(encryptedRsaPem, 'secret123', {
				kind: 'rsa',
			}),
		);
		expect(await exportPkcs8Der(importedRsa)).toEqual(await exportPkcs8Der(rsa.privateKey));
		const importedCrOnlyRsa = unwrap(
			await importEncryptedPkcs1Pem(encryptedRsaPem.replace(/\n/g, '\r'), 'secret123', {
				kind: 'rsa',
			}),
		);
		expect(await exportPkcs8Der(importedCrOnlyRsa)).toEqual(await exportPkcs8Der(rsa.privateKey));
		// OpenSSL-style encapsulated headers permit no space after the colon.
		const noSpaceHeaderPem = encryptedRsaPem
			.replace('Proc-Type: ', 'Proc-Type:')
			.replace('DEK-Info: ', 'DEK-Info:');
		const importedNoSpaceRsa = unwrap(
			await importEncryptedPkcs1Pem(noSpaceHeaderPem, 'secret123', { kind: 'rsa' }),
		);
		expect(await exportPkcs8Der(importedNoSpaceRsa)).toEqual(await exportPkcs8Der(rsa.privateKey));
		for (const badName of MALFORMED_PEM_HEADER_NAMES) {
			const badHeaderPem = encryptedRsaPem.replace('Proc-Type: ', `${badName}\nProc-Type: `);
			await expectImportFailure(
				importEncryptedPkcs1Pem(badHeaderPem, 'secret123', { kind: 'rsa' }),
				'malformed',
			);
			await expectRejection(
				importEncryptedPkcs1PemOrThrow(badHeaderPem, 'secret123', { kind: 'rsa' }),
				'Invalid PEM header name',
			);
		}
		await expectImportFailure(
			importEncryptedPkcs1Pem(encryptedRsaPem, 'wrong', { kind: 'rsa' }),
			'invalid_password',
			'Invalid password or encrypted PEM content',
		);

		const ec = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
		const encryptedEcPem = await exportEncryptedSec1Pem(ec.privateKey, {
			password: 'secret123',
		});
		const importedEc = unwrap(
			await importEncryptedSec1Pem(encryptedEcPem, 'secret123', {
				kind: 'ecdsa',
				curve: 'P-256',
			}),
		);
		expect(await exportPkcs8Der(importedEc)).toEqual(await exportPkcs8Der(ec.privateKey));
		for (const badName of MALFORMED_PEM_HEADER_NAMES) {
			const badHeaderPem = encryptedEcPem.replace('Proc-Type: ', `${badName}\nProc-Type: `);
			await expectImportFailure(
				importEncryptedSec1Pem(badHeaderPem, 'secret123', { kind: 'ecdsa', curve: 'P-256' }),
				'malformed',
			);
			await expectRejection(
				importEncryptedSec1PemOrThrow(badHeaderPem, 'secret123', {
					kind: 'ecdsa',
					curve: 'P-256',
				}),
				'Invalid PEM header name',
			);
		}
	});

	// Header grammar is shared by the PKCS#1 and SEC1 paths through
	// decryptTraditionalPem, so these cover it on the cheaper EC keygen.
	async function encryptedEcPemFixture(): Promise<{
		readonly pem: string;
		readonly pkcs8: Uint8Array;
	}> {
		const ec = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
		return {
			pem: await exportEncryptedSec1Pem(ec.privateKey, { password: 'secret123' }),
			pkcs8: await exportPkcs8Der(ec.privateKey),
		};
	}

	const ecImportOptions = { kind: 'ecdsa', curve: 'P-256' } as const;

	it('unfolds RFC 1421 4.6 encapsulated headers folded per RFC 822 3.1.1', async () => {
		const { pem, pkcs8 } = await encryptedEcPemFixture();
		const folded = [
			pem.replace('Proc-Type: 4,ENCRYPTED', 'Proc-Type: 4,\n ENCRYPTED'),
			pem.replace(/DEK-Info: ([^,]+),/, 'DEK-Info: $1,\n           '),
			// RFC 1421 Figure 3 folds a field whose first line carries no body.
			pem.replace('Proc-Type: 4,ENCRYPTED', 'Proc-Type:\n\t4,ENCRYPTED'),
		];
		for (const foldedPem of folded) {
			const imported = unwrap(
				await importEncryptedSec1Pem(foldedPem, 'secret123', ecImportOptions),
			);
			expect(await exportPkcs8Der(imported)).toEqual(pkcs8);
		}
	});

	it.each(['\u000b', '\u00a0', '\u3000'])(
		'rejects %j in a consumed header field, which RFC 822 3.3 excludes from LWSP-char',
		async (nonLwsp) => {
			const { pem } = await encryptedEcPemFixture();
			for (const candidate of [
				pem.replace('4,ENCRYPTED', `4,${nonLwsp}ENCRYPTED`),
				pem.replace('Proc-Type: ', `Proc-Type:${nonLwsp}`),
			]) {
				await expectImportFailure(
					importEncryptedSec1Pem(candidate, 'secret123', ecImportOptions),
					'malformed',
				);
				await expectRejection(
					importEncryptedSec1PemOrThrow(candidate, 'secret123', ecImportOptions),
					'Traditional PEM encryption headers missing',
				);
			}
			const dekInfoPem = pem.replace(/,(?=[0-9A-F]{32})/, `,${nonLwsp}`);
			await expectImportFailure(
				importEncryptedSec1Pem(dekInfoPem, 'secret123', ecImportOptions),
				'malformed',
			);
			await expectRejection(
				importEncryptedSec1PemOrThrow(dekInfoPem, 'secret123', ecImportOptions),
				'Traditional PEM encryption requires a 16-byte IV',
			);
		},
	);

	it('roundtrips keys through PEM, base64, and JWK imports', async () => {
		const original = await generateKeyPair({
			kind: 'rsa',
			modulusLength: 2048,
		});
		const importedPublic = unwrap(
			await importSpkiPem(await original.exportSpkiPem(), {
				kind: 'rsa',
			}),
		);
		const importedPrivate = unwrap(
			await importPkcs8Pem(await original.exportPkcs8Pem(), { kind: 'rsa' }),
		);
		const base64Public = unwrap(
			await importSpkiBase64(await exportBinaryBase64(original.publicKey), {
				kind: 'rsa',
			}),
		);
		const base64Private = unwrap(
			await importPkcs8Base64(await exportBinaryBase64(original.privateKey), {
				kind: 'rsa',
			}),
		);
		const jwkPublic = unwrap(
			await importPublicJwk(await original.exportPublicJwk(), {
				kind: 'rsa',
			}),
		);
		const jwkPrivate = unwrap(
			await importPrivateJwk(await original.exportPrivateJwk(), { kind: 'rsa' }),
		);

		const certificate = await createCertificate({
			issuer: { commonName: 'imported-ca' },
			subject: { commonName: 'imported-leaf' },
			publicKey: importedPublic,
			signerPrivateKey: importedPrivate,
			issuerPublicKey: importedPublic,
		});
		const certificateFromBase64 = await createCertificate({
			issuer: { commonName: 'imported-ca-2' },
			subject: { commonName: 'imported-leaf-2' },
			publicKey: base64Public,
			signerPrivateKey: base64Private,
			issuerPublicKey: base64Public,
		});
		const certificateFromJwk = await createCertificate({
			issuer: { commonName: 'imported-ca-3' },
			subject: { commonName: 'imported-leaf-3' },
			publicKey: jwkPublic,
			signerPrivateKey: jwkPrivate,
			issuerPublicKey: jwkPublic,
		});

		expect(new X509Certificate(certificate.pem).subject).toContain('CN=imported-leaf');
		expect(new X509Certificate(certificateFromBase64.pem).subject).toContain('CN=imported-leaf-2');
		expect(new X509Certificate(certificateFromJwk.pem).subject).toContain('CN=imported-leaf-3');
		expect(await exportSpkiDer(importedPublic)).toEqual(await original.exportSpkiDer());
		expect(await exportPkcs8Der(importedPrivate)).toEqual(await original.exportPkcs8Der());
		expect(await exportSpkiDer(base64Public)).toEqual(await original.exportSpkiDer());
		expect(await exportPkcs8Der(base64Private)).toEqual(await original.exportPkcs8Der());
		expect(await exportSpkiDer(jwkPublic)).toEqual(await original.exportSpkiDer());
		expect(await exportPkcs8Der(jwkPrivate)).toEqual(await original.exportPkcs8Der());
	});

	it('importPublicJwk rejects private-key material and algorithm mismatches', async () => {
		const rsa = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const publicJwk = await exportPublicJwk(rsa.publicKey);
		const privateJwk = await exportPrivateJwk(rsa.privateKey);
		await expectImportFailure(
			importPublicJwk(privateJwk, { kind: 'rsa' }),
			'malformed',
			'Public JWK must not contain private key material',
		);
		await expectImportFailure(
			importPublicJwk(publicJwk, { kind: 'ecdsa', curve: 'P-256' }),
			'malformed',
			'Public JWK algorithm does not match requested import algorithm',
		);
	});

	it('importPrivateJwk rejects public-only JWKs and algorithm mismatches', async () => {
		const rsa = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const rsaPublicJwk = await exportPublicJwk(rsa.publicKey);
		const rsaPrivateJwk = await exportPrivateJwk(rsa.privateKey);
		const ec = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
		const ecPrivateJwk = await exportPrivateJwk(ec.privateKey);
		await expectImportFailure(
			importPrivateJwk(rsaPublicJwk, { kind: 'rsa' }),
			'malformed',
			'Private JWK must contain private key material',
		);
		await expectImportFailure(
			importPrivateJwk(ecPrivateJwk, { kind: 'ecdsa', curve: 'P-384' }),
			'malformed',
			'Private JWK algorithm does not match requested import algorithm',
		);
		await expectImportFailure(
			importPrivateJwk(rsaPrivateJwk, { kind: 'ecdsa', curve: 'P-256' }),
			'malformed',
			'Private JWK algorithm does not match requested import algorithm',
		);
		expect(importPrivateJwkOrThrow(rsaPublicJwk, { kind: 'rsa' })).rejects.toThrow(
			'Private JWK must contain private key material',
		);
		expect(
			importPrivateJwkOrThrow(ecPrivateJwk, { kind: 'ecdsa', curve: 'P-384' }),
		).rejects.toThrow('Private JWK algorithm does not match requested import algorithm');
	});

	it('roundtrips EC and Ed25519 private keys through JWK', async () => {
		const ec = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
		const ecFromJwk = unwrap(
			await importPrivateJwk(await ec.exportPrivateJwk(), { kind: 'ecdsa', curve: 'P-256' }),
		);
		expect(await exportPkcs8Der(ecFromJwk)).toEqual(await ec.exportPkcs8Der());

		const ed = await generateKeyPair({ kind: 'ed25519' });
		const edFromJwk = unwrap(
			await importPrivateJwk(await ed.exportPrivateJwk(), { kind: 'ed25519' }),
		);
		expect(await exportPkcs8Der(edFromJwk)).toEqual(await ed.exportPkcs8Der());
	});

	it('imports and exports keys via ecdsa and ed25519', async () => {
		const ecP384 = await generateKeyPair({
			kind: 'ecdsa',
			curve: 'P-384',
		});
		const ecPub = unwrap(
			await importSpkiBase64(await exportBinaryBase64(ecP384.publicKey), {
				kind: 'ecdsa',
				curve: 'P-384',
			}),
		);
		const ecPriv = unwrap(
			await importPkcs8Base64(await exportBinaryBase64(ecP384.privateKey), {
				kind: 'ecdsa',
				curve: 'P-384',
			}),
		);
		expect(await exportSpkiDer(ecPub)).toEqual(await ecP384.exportSpkiDer());
		expect(await exportPkcs8Der(ecPriv)).toEqual(await ecP384.exportPkcs8Der());

		const ed = await generateKeyPair({ kind: 'ed25519' });
		const edPub = unwrap(
			await importSpkiPem(await ed.exportSpkiPem(), {
				kind: 'ed25519',
			}),
		);
		const edPriv = unwrap(
			await importPkcs8Pem(await ed.exportPkcs8Pem(), {
				kind: 'ed25519',
			}),
		);
		expect(await exportSpkiDer(edPub)).toEqual(await ed.exportSpkiDer());
		expect(await exportPkcs8Der(edPriv)).toEqual(await ed.exportPkcs8Der());
	});

	it('derivePublicKey reconstructs the SPKI from an imported private key', async () => {
		const cases = [
			{ kind: 'rsa', modulusLength: 2048 } as const,
			{ kind: 'ecdsa', curve: 'P-256' } as const,
			{ kind: 'ecdsa', curve: 'P-521' } as const,
			{ kind: 'ed25519' } as const,
		];
		for (const algorithm of cases) {
			const original = await generateKeyPair(algorithm);
			// Round-trip through PKCS#8 so we start from a bare sign-only private key.
			const importAlgorithm =
				algorithm.kind === 'ecdsa'
					? { kind: 'ecdsa' as const, curve: algorithm.curve }
					: algorithm.kind === 'rsa'
						? { kind: 'rsa' as const }
						: { kind: 'ed25519' as const };
			const privateKey = unwrap(
				await importPkcs8Pem(await original.exportPkcs8Pem(), importAlgorithm),
			);
			expect(privateKey.type).toBe('private');

			const publicKey = await derivePublicKey(privateKey);
			expect(publicKey.type).toBe('public');
			expect(publicKey.usages).toEqual(['verify']);
			expect(publicKey.algorithm.name).toBe(original.publicKey.algorithm.name);
			expect(await exportSpkiDer(publicKey)).toEqual(await original.exportSpkiDer());
		}
	});

	it('derivePublicKey rejects public and non-extractable keys', async () => {
		const ec = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
		expect(derivePublicKey(ec.publicKey)).rejects.toThrow(
			'derivePublicKey requires a private CryptoKey',
		);

		const nonExtractable = await crypto.subtle.generateKey(
			{ name: 'ECDSA', namedCurve: 'P-256' },
			false,
			['sign', 'verify'],
		);
		if (!('privateKey' in nonExtractable)) {
			throw new Error('expected an asymmetric key pair');
		}
		expect(derivePublicKey(nonExtractable.privateKey)).rejects.toThrow(
			'Cannot derive public key from a non-extractable private key',
		);
	});

	it('accepts RSA-PSS and ECDSA P-521 key inputs', async () => {
		const rsaPss = await generateKeyPair({
			kind: 'rsa',
			scheme: 'pss',
			hash: 'SHA-256',
		});
		expect(rsaPss.privateKey.algorithm.name).toBe('RSA-PSS');

		const rsaPssPublic = unwrap(
			await importSpkiPem(await rsaPss.exportSpkiPem(), {
				kind: 'rsa',
				scheme: 'pss',
				hash: 'SHA-256',
			}),
		);
		expect(rsaPssPublic.algorithm.name).toBe('RSA-PSS');

		const ecP521 = await generateKeyPair({
			kind: 'ecdsa',
			curve: 'P-521',
		});
		const ecP521Public = unwrap(
			await importSpkiBase64(await exportBinaryBase64(ecP521.publicKey), {
				kind: 'ecdsa',
				curve: 'P-521',
			}),
		);
		const ecP521Private = unwrap(
			await importPkcs8Base64(await exportBinaryBase64(ecP521.privateKey), {
				kind: 'ecdsa',
				curve: 'P-521',
			}),
		);
		expect(await exportSpkiDer(ecP521Public)).toEqual(await ecP521.exportSpkiDer());
		expect(await exportPkcs8Der(ecP521Private)).toEqual(await ecP521.exportPkcs8Der());
	});

	it('exports keys with standalone PEM and JWK helpers', async () => {
		const keyPair = await generateKeyPair({ kind: 'ed25519' });
		expect(await exportSpkiPem(keyPair.publicKey)).toContain('BEGIN PUBLIC KEY');
		expect(await exportPkcs8Pem(keyPair.privateKey)).toContain('BEGIN PRIVATE KEY');
		expect(await exportPublicJwk(keyPair.publicKey)).toHaveProperty('kty');
		expect(await exportPrivateJwk(keyPair.privateKey)).toHaveProperty('kty');
	});

	it('exportPkcs1Der throws for non-RSA key', async () => {
		const ecKeys = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
		expect(exportPkcs1Der(ecKeys.privateKey)).rejects.toThrow(
			'PKCS#1 export requires an RSA private key',
		);
	});

	it('exportSec1Der throws for non-EC key', async () => {
		const rsaKeys = await generateKeyPair({
			kind: 'rsa',
			modulusLength: 2048,
		});
		expect(exportSec1Der(rsaKeys.privateKey)).rejects.toThrow(
			'SEC1 export requires an EC private key',
		);
	});

	it('round-trips RSA SHA-512 keys through PKCS#1', async () => {
		const keys = await generateKeyPair({
			kind: 'rsa',
			modulusLength: 2048,
			hash: 'SHA-512',
		});
		const pkcs1Der = await exportPkcs1Der(keys.privateKey);
		expect(pkcs1Der.length).toBeGreaterThan(100);
		const pkcs1Pem = await exportPkcs1Pem(keys.privateKey);
		expect(pkcs1Pem).toContain('BEGIN RSA PRIVATE KEY');
		const reimported = unwrap(
			await importPkcs1Der(pkcs1Der, {
				kind: 'rsa',
				hash: 'SHA-512',
			}),
		);
		expect(reimported.type).toBe('private');
	});

	it('round-trips EC P-384 keys through SEC1', async () => {
		const keys = await generateKeyPair({
			kind: 'ecdsa',
			curve: 'P-384',
		});
		const sec1Der = await exportSec1Der(keys.privateKey);
		expect(sec1Der.length).toBeGreaterThan(40);
		const sec1Pem = await exportSec1Pem(keys.privateKey);
		expect(sec1Pem).toContain('BEGIN EC PRIVATE KEY');
		const reimported = unwrap(
			await importSec1Der(sec1Der, {
				kind: 'ecdsa',
				curve: 'P-384',
			}),
		);
		expect(reimported.type).toBe('private');
	});

	it('rejects a SEC1 ECPrivateKey whose version is not 1 (RFC 5915 §3)', async () => {
		const { sequence, integerFromNumber, octetString } = await import(
			'#micro509/internal/asn1/der'
		);
		const versionTwo = sequence([integerFromNumber(2), octetString(new Uint8Array(32))]);
		const result = await importSec1Der(versionTwo, { kind: 'ecdsa', curve: 'P-256' });
		expect(result.ok).toBe(false);
		if (result.ok) throw new Error('unreachable');
		expect(result.error.message).toContain('Malformed SEC 1');
	});

	it('round-trips EC P-521 keys through SEC1', async () => {
		const keys = await generateKeyPair({
			kind: 'ecdsa',
			curve: 'P-521',
		});
		const sec1Der = await exportSec1Der(keys.privateKey);
		expect(sec1Der.length).toBeGreaterThan(60);
		const sec1Pem = await exportSec1Pem(keys.privateKey);
		expect(sec1Pem).toContain('BEGIN EC PRIVATE KEY');
		const reimported = unwrap(
			await importSec1Pem(sec1Pem, {
				kind: 'ecdsa',
				curve: 'P-521',
			}),
		);
		expect(await exportPkcs8Der(reimported)).toEqual(await exportPkcs8Der(keys.privateKey));
	});

	it('round-trips encrypted PKCS#1 PEM for RSA keys', async () => {
		const keys = await generateKeyPair({
			kind: 'rsa',
			modulusLength: 2048,
		});
		for (const cipher of ['AES-128-CBC', 'AES-192-CBC', 'AES-256-CBC'] as const) {
			const encrypted = await exportEncryptedPkcs1Pem(keys.privateKey, {
				password: 'testpass',
				cipher,
			});
			expect(encrypted).toContain('Proc-Type: 4,ENCRYPTED');
			expect(encrypted).toContain(`DEK-Info: ${cipher}`);
			const reimported = unwrap(
				await importEncryptedPkcs1Pem(encrypted, 'testpass', {
					kind: 'rsa',
				}),
			);
			expect(reimported.type).toBe('private');
		}
	});

	it('round-trips encrypted SEC1 PEM for EC keys', async () => {
		const keys = await generateKeyPair({
			kind: 'ecdsa',
			curve: 'P-256',
		});
		for (const cipher of ['AES-128-CBC', 'AES-192-CBC', 'AES-256-CBC'] as const) {
			const encrypted = await exportEncryptedSec1Pem(keys.privateKey, {
				password: 'ecpass',
				cipher,
			});
			expect(encrypted).toContain('Proc-Type: 4,ENCRYPTED');
			expect(encrypted).toContain(`DEK-Info: ${cipher}`);
			const reimported = unwrap(
				await importEncryptedSec1Pem(encrypted, 'ecpass', {
					kind: 'ecdsa',
					curve: 'P-256',
				}),
			);
			expect(reimported.type).toBe('private');
		}
	});

	it('PKCS#8 base64 import works for Ed25519 keys', async () => {
		const keys = await generateKeyPair({ kind: 'ed25519' });
		const base64 = await exportBinaryBase64(keys.privateKey);
		const reimported = unwrap(await importPkcs8Base64(base64, { kind: 'ed25519' }));
		expect(reimported.type).toBe('private');
	});
});

/** Is a bun canary build */
const isCanary = (await Bun.$`${process.argv0} --revision`.text()).includes('canary');

describe('keys: coverage — malformed inputs', () => {
	it('importEncryptedPkcs8Der throws on malformed EncryptedPrivateKeyInfo (missing OCTET STRING)', async () => {
		// SEQUENCE with only one child (algorithmIdentifier) and no encryptedData
		const { sequence, objectIdentifier, nullValue } = await import('#micro509/internal/asn1/der');
		const malformed = sequence([
			sequence([objectIdentifier('1.2.840.113549.1.5.13'), nullValue()]),
		]);
		await expectImportFailure(
			importEncryptedPkcs8Der(malformed, 'pass', { kind: 'ecdsa', curve: 'P-256' }),
			'malformed',
			'Malformed EncryptedPrivateKeyInfo',
		);
	});

	it('importEncryptedPkcs8Der throws when second child is not OCTET STRING', async () => {
		const { sequence, objectIdentifier, nullValue, integerFromNumber } = await import(
			'#micro509/internal/asn1/der'
		);
		// second child is INTEGER (tag 0x02), not OCTET STRING (tag 0x04)
		const malformed = sequence([
			sequence([objectIdentifier('1.2.840.113549.1.5.13'), nullValue()]),
			integerFromNumber(42),
		]);
		await expectImportFailure(
			importEncryptedPkcs8Der(malformed, 'pass', { kind: 'ecdsa', curve: 'P-256' }),
			'malformed',
			'Malformed EncryptedPrivateKeyInfo',
		);
	});

	it('importEncryptedPkcs8Der throws when EncryptedPrivateKeyInfo has trailing children', async () => {
		const { sequence, objectIdentifier, nullValue, octetString, integerFromNumber } = await import(
			'#micro509/internal/asn1/der'
		);
		const malformed = sequence([
			sequence([objectIdentifier('1.2.840.113549.1.5.13'), nullValue()]),
			octetString(Uint8Array.of(0x01, 0x02)),
			integerFromNumber(7),
		]);
		await expectImportFailure(
			importEncryptedPkcs8Der(malformed, 'pass', { kind: 'ecdsa', curve: 'P-256' }),
			'malformed',
			'Malformed EncryptedPrivateKeyInfo',
		);
	});

	it('importSpkiBase64 throws on malformed SubjectPublicKeyInfo', async () => {
		await expectImportFailure(
			importSpkiBase64('MAI=', { kind: 'rsa' }),
			'malformed',
			'Malformed SubjectPublicKeyInfo',
		);
	});

	it('importSpkiBase64 throws on SubjectPublicKeyInfo with trailing fields', async () => {
		const { bitString, integerFromNumber, sequence, objectIdentifier } = await import(
			'#micro509/internal/asn1/der'
		);
		const malformed = sequence([
			sequence([objectIdentifier('1.2.840.113549.1.1.1')]),
			bitString(Uint8Array.of(0x00), 0),
			integerFromNumber(1),
		]);
		await expectImportFailure(
			importSpkiBase64(Buffer.from(malformed).toString('base64'), { kind: 'rsa' }),
			'malformed',
			'Malformed SubjectPublicKeyInfo',
		);
	});

	it('importSpkiBase64 throws on algorithm identifiers missing an OID', async () => {
		const { bitString, integerFromNumber, sequence } = await import('#micro509/internal/asn1/der');
		const malformed = sequence([
			sequence([integerFromNumber(1)]),
			bitString(Uint8Array.of(0x00), 0),
		]);
		await expectImportFailure(
			importSpkiBase64(Buffer.from(malformed).toString('base64'), { kind: 'rsa' }),
			'malformed',
			'Malformed SubjectPublicKeyInfo',
		);
	});

	it('importSpkiBase64 throws on invalid subjectPublicKey BIT STRING content', async () => {
		const { sequence, objectIdentifier } = await import('#micro509/internal/asn1/der');
		const malformed = sequence([
			sequence([objectIdentifier('1.2.840.113549.1.1.1')]),
			Uint8Array.of(0x03, 0x02, 0x01, 0x01),
		]);
		await expectImportFailure(
			importSpkiBase64(Buffer.from(malformed).toString('base64'), { kind: 'rsa' }),
			'malformed',
			'Malformed SubjectPublicKeyInfo',
		);
	});

	it('importSpkiBase64 rejects the respellings of one key', async () => {
		const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
		const keyPair = await generateKeyPair({ kind: 'ed25519' });
		const base64 = await exportBinaryBase64(keyPair.publicKey);
		expect(base64.endsWith('=')).toBe(true);
		const canonical = alphabet.indexOf(base64.slice(-2, -1));
		expect(canonical % 4).toBe(0);
		for (const offset of [1, 2, 3]) {
			await expectImportFailure(
				importSpkiBase64(`${base64.slice(0, -2)}${alphabet.charAt(canonical + offset)}=`, {
					kind: 'ed25519',
				}),
				'malformed',
				'Invalid base64 SubjectPublicKeyInfo',
			);
		}
		await expectImportFailure(
			importSpkiBase64(base64.slice(0, -1), { kind: 'ed25519' }),
			'malformed',
			'Invalid base64 SubjectPublicKeyInfo',
		);
		expect(unwrap(await importSpkiBase64(base64, { kind: 'ed25519' })).type).toBe('public');
	});

	it('importSpki base64 and PEM preserve algorithm mismatch errors', async () => {
		const rsa = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const base64 = await exportBinaryBase64(rsa.publicKey);
		const pem = await exportSpkiPem(rsa.publicKey);
		await expectImportFailure(
			importSpkiBase64(base64, { kind: 'ecdsa', curve: 'P-256' }),
			'malformed',
			'SubjectPublicKeyInfo algorithm does not match requested import algorithm',
		);
		await expectImportFailure(
			importSpkiPem(pem, { kind: 'ecdsa', curve: 'P-256' }),
			'malformed',
			'SubjectPublicKeyInfo algorithm does not match requested import algorithm',
		);
	});

	it('importPkcs8Base64 throws on malformed PKCS#8 private key', async () => {
		await expectImportFailure(
			importPkcs8Base64('MAI=', { kind: 'rsa' }),
			'malformed',
			'Malformed PKCS#8 private key',
		);
	});

	/** RFC 5958 §2 v2 `OneAsymmetricKey`: `attributes [0]` empty, `publicKey [1]` present. */
	const ONE_ASYMMETRIC_KEY_V2 =
		'3053020101300506032b657004220420' +
		'9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60' +
		'a000812100' +
		'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';

	test('imports RFC 5958 v2 OneAsymmetricKey with attributes and publicKey (oven-sh/bun#35432, oven-sh/bun#35433)', async () => {
		const key = unwrap(
			await importPkcs8Der(hexToBytes(ONE_ASYMMETRIC_KEY_V2), { kind: 'ed25519' }),
		);
		expect(key.type).toBe('private');
		expect(key.algorithm.name).toBe('Ed25519');
	});

	// The import above reduces a v2 key to its v1 fields before the platform call,
	// so it passes on every build and says nothing about the platform. This one
	// hands WebCrypto the v2 structure RFC 5958 §2 defines, which is what
	// oven-sh/bun#35432 rejects: it fails on a stock build and passes once the fix
	// in oven-sh/bun#35433 lands, which `bun run test:35433` exercises.
	test.failingIf(!isCanary)(
		'WebCrypto imports an RFC 5958 v2 OneAsymmetricKey (oven-sh/bun#35432)',
		async () => {
			const key = await crypto.subtle.importKey(
				'pkcs8',
				toArrayBuffer(hexToBytes(ONE_ASYMMETRIC_KEY_V2)),
				'Ed25519',
				true,
				['sign'],
			);
			expect(key.type).toBe('private');
		},
	);

	test('rejects malformed OneAsymmetricKey tails per RFC 5958/RFC 8410', async () => {
		const { integerFromNumber, objectIdentifier, octetString, sequence } = await import(
			'#micro509/internal/asn1/der'
		);
		const seedHex = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
		const pubHex = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
		const version1 = integerFromNumber(1);
		const version0 = integerFromNumber(0);
		const algorithm = sequence([objectIdentifier('1.3.101.112')]);
		const privateKey = octetString(octetString(hexToBytes(seedHex)));
		const attributes = hexToBytes('a000');
		const publicKey = hexToBytes(`812100${pubHex}`);
		const cases: ReadonlyArray<{ name: string; version: Uint8Array; tail: Uint8Array[] }> = [
			{
				name: 'attributes [0] as primitive 80',
				version: version1,
				tail: [hexToBytes('8000'), publicKey],
			},
			{
				name: 'publicKey [1] as constructed a1',
				version: version1,
				tail: [attributes, hexToBytes(`a12100${pubHex}`)],
			},
			{ name: 'duplicate publicKey [1]', version: version1, tail: [publicKey, publicKey] },
			{
				name: 'publicKey [1] before attributes [0]',
				version: version1,
				tail: [publicKey, attributes],
			},
			{
				name: 'publicKey present but version v1',
				version: version0,
				tail: [attributes, publicKey],
			},
			{ name: 'version v2 but no publicKey', version: version1, tail: [attributes] },
			{ name: 'empty publicKey BIT STRING', version: version1, tail: [hexToBytes('810100')] },
		];
		// Requesting ECDSA over an Ed25519 body: the algorithm check runs after the
		// structure is read, so an accepted tail would surface as a mismatch instead.
		for (const { name, version, tail } of cases) {
			const der = sequence([version, algorithm, privateKey, ...tail]);
			try {
				await expectImportFailure(
					importPkcs8Der(der, { kind: 'ecdsa', curve: 'P-256' }),
					'malformed',
					'Malformed PKCS#8 private key',
				);
			} catch (cause) {
				throw new Error(`case "${name}" failed`, { cause });
			}
		}
	});

	it('importPkcs8Der and base64 throw on PKCS#8 with wrong privateKey tag', async () => {
		const { integerFromNumber, nullValue, objectIdentifier, sequence } = await import(
			'#micro509/internal/asn1/der'
		);
		const malformed = sequence([
			integerFromNumber(0),
			sequence([objectIdentifier('1.2.840.113549.1.1.1'), nullValue()]),
			integerFromNumber(1),
		]);
		await expectImportFailure(
			importPkcs8Der(malformed, { kind: 'rsa' }),
			'malformed',
			'Malformed PKCS#8 private key',
		);
		await expectImportFailure(
			importPkcs8Base64(Buffer.from(malformed).toString('base64'), { kind: 'rsa' }),
			'malformed',
			'Malformed PKCS#8 private key',
		);
	});

	it('importPkcs8Der throws on algorithm identifiers missing an OID', async () => {
		const { integerFromNumber, octetString, sequence } = await import(
			'#micro509/internal/asn1/der'
		);
		const malformed = sequence([
			integerFromNumber(0),
			sequence([integerFromNumber(1)]),
			octetString(Uint8Array.of(0x01)),
		]);
		await expectImportFailure(
			importPkcs8Der(malformed, { kind: 'rsa' }),
			'malformed',
			'Malformed PKCS#8 private key',
		);
	});

	it('importPkcs8 base64 and PEM preserve algorithm mismatch errors', async () => {
		const rsa = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const base64 = await exportBinaryBase64(rsa.privateKey);
		const pem = await exportPkcs8Pem(rsa.privateKey);
		await expectImportFailure(
			importPkcs8Base64(base64, { kind: 'ecdsa', curve: 'P-256' }),
			'malformed',
			'PKCS#8 private key algorithm does not match requested import algorithm',
		);
		await expectImportFailure(
			importPkcs8Pem(pem, { kind: 'ecdsa', curve: 'P-256' }),
			'malformed',
			'PKCS#8 private key algorithm does not match requested import algorithm',
		);
	});

	it('importSec1Der cross-checks the embedded RFC 5915 parameters curve', async () => {
		const { explicitContext, objectIdentifier, readSequenceChildren, sequence } = await import(
			'#micro509/internal/asn1/der'
		);
		const { OIDS } = await import('#micro509/internal/asn1/oids');
		const keys = await generateKeyPair({ kind: 'ecdsa', curve: 'P-384' });
		const sec1Der = await exportSec1Der(keys.privateKey);
		// Re-encode with the `parameters [0]` named-curve field OpenSSL always writes.
		const children = readSequenceChildren(sec1Der);
		const raw = (child: (typeof children)[number]): Uint8Array =>
			sec1Der.slice(child.start - child.headerLength, child.end);
		const withParameters = sequence([
			...children.slice(0, 2).map(raw),
			explicitContext(0, objectIdentifier(OIDS.secp384r1)),
			...children
				.slice(2)
				.filter((child) => child.tag !== 0xa0)
				.map(raw),
		]);
		// Matching curve with parameters present still imports.
		const reimported = unwrap(
			await importSec1Der(withParameters, { kind: 'ecdsa', curve: 'P-384' }),
		);
		expect(reimported.type).toBe('private');
		// Claiming P-256 fails in the library, not with a WebCrypto internal error.
		await expectImportFailure(
			importSec1Der(withParameters, { kind: 'ecdsa', curve: 'P-256' }),
			'malformed',
			'SEC 1 private key curve does not match requested import algorithm',
		);
		await expectImportFailure(
			importSec1Pem(pemEncode('EC PRIVATE KEY', withParameters), {
				kind: 'ecdsa',
				curve: 'P-256',
			}),
			'malformed',
			'SEC 1 private key curve does not match requested import algorithm',
		);
		expect(importSec1DerOrThrow(withParameters, { kind: 'ecdsa', curve: 'P-256' })).rejects.toThrow(
			'SEC 1 private key curve does not match requested import algorithm',
		);
	});

	it('importSec1Der reports malformed for bytes that are not an ECPrivateKey', async () => {
		const { integerFromNumber, sequence } = await import('#micro509/internal/asn1/der');
		await expectImportFailure(
			importSec1Der(Uint8Array.of(0x01, 0x02, 0x03), { kind: 'ecdsa', curve: 'P-256' }),
			'malformed',
			'Malformed SEC 1 private key',
		);
		// Valid DER SEQUENCE, but not an ECPrivateKey shape.
		const notEcPrivateKey = sequence([integerFromNumber(1), integerFromNumber(2)]);
		await expectImportFailure(
			importSec1Der(notEcPrivateKey, { kind: 'ecdsa', curve: 'P-256' }),
			'malformed',
			'Malformed SEC 1 private key',
		);
		expect(
			importSec1DerOrThrow(notEcPrivateKey, { kind: 'ecdsa', curve: 'P-256' }),
		).rejects.toThrow('Malformed SEC 1 private key');
	});

	it('encryptTraditionalPem throws on non-16-byte IV', async () => {
		const keys = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		expect(
			exportEncryptedPkcs1Pem(keys.privateKey, {
				password: 'test',
				iv: new Uint8Array(8), // too short — must be 16
			}),
		).rejects.toThrow('16-byte IV');
	});

	it('decryptTraditionalPem throws on wrong PEM label', async () => {
		// Encrypt as RSA, try to import as EC — label mismatch
		const rsa = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const encrypted = await exportEncryptedPkcs1Pem(rsa.privateKey, { password: 'test' });
		await expectImportFailure(
			importEncryptedSec1Pem(encrypted, 'test', { kind: 'ecdsa', curve: 'P-256' }),
			'malformed',
			'Expected EC PRIVATE KEY PEM block',
		);
	});

	it('decryptTraditionalPem throws when Proc-Type/DEK-Info headers are missing', async () => {
		// A plain (unencrypted) RSA PEM has no encryption headers
		const rsa = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const plainPem = await exportPkcs1Pem(rsa.privateKey);
		await expectImportFailure(
			importEncryptedPkcs1Pem(plainPem, 'test', { kind: 'rsa' }),
			'malformed',
			'encryption headers missing',
		);
	});

	it('decryptTraditionalPem throws on unsupported cipher', async () => {
		// Build a PEM with a non-AES-256-CBC cipher header
		const rsa = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const encrypted = await exportEncryptedPkcs1Pem(rsa.privateKey, { password: 'test' });
		// Replace AES-256-CBC with DES-EDE3-CBC in the header
		const tampered = encrypted.replace('AES-256-CBC', 'DES-EDE3-CBC');
		await expectImportFailure(
			importEncryptedPkcs1Pem(tampered, 'test', { kind: 'rsa' }),
			'malformed',
			'Only AES-128-CBC, AES-192-CBC, and AES-256-CBC',
		);
	});

	it('decryptTraditionalPem throws on malformed DEK-Info IV hex', async () => {
		const rsa = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const encrypted = await exportEncryptedPkcs1Pem(rsa.privateKey, { password: 'test' });
		const tampered = encrypted.replace(/DEK-Info: [^,]+,.+/, 'DEK-Info: AES-256-CBC,XYZ');
		await expectImportFailure(
			importEncryptedPkcs1Pem(tampered, 'test', { kind: 'rsa' }),
			'malformed',
			'16-byte IV encoded as 32 hex characters',
		);
	});

	it('decryptTraditionalPem rejects duplicate encryption headers', async () => {
		const rsa = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const encrypted = await exportEncryptedPkcs1Pem(rsa.privateKey, { password: 'test' });
		const withDuplicateProcType = encrypted.replace(
			'Proc-Type: 4,ENCRYPTED',
			'Proc-Type: 4,ENCRYPTED\nProc-Type: 4,ENCRYPTED',
		);
		await expectImportFailure(
			importEncryptedPkcs1Pem(withDuplicateProcType, 'test', { kind: 'rsa' }),
			'malformed',
			'Duplicate PEM header: Proc-Type',
		);
		const withDuplicateDekInfo = encrypted.replace(
			/DEK-Info: .+/,
			(match) => `${match}\nDEK-Info: AES-128-CBC,00000000000000000000000000000000`,
		);
		await expectImportFailure(
			importEncryptedPkcs1Pem(withDuplicateDekInfo, 'test', { kind: 'rsa' }),
			'malformed',
			'Duplicate PEM header: DEK-Info',
		);
	});

	it('parseTraditionalPem throws on non-PEM input', async () => {
		await expectImportFailure(
			importEncryptedPkcs1Pem('not a pem block', 'test', { kind: 'rsa' }),
			'malformed',
			'Invalid PEM block',
		);
	});

	it('parseTraditionalPem throws when BEGIN/END labels mismatch', async () => {
		const badPem = '-----BEGIN RSA PRIVATE KEY-----\nYWJj\n-----END EC PRIVATE KEY-----';
		await expectImportFailure(
			importEncryptedPkcs1Pem(badPem, 'test', { kind: 'rsa' }),
			'malformed',
			'PEM boundaries do not match',
		);
	});

	/** Read `namedCurve` off a CryptoKey algorithm without a type assertion. */
	function namedCurveOf(algorithm: KeyAlgorithm): string {
		if ('namedCurve' in algorithm && typeof algorithm.namedCurve === 'string') {
			return algorithm.namedCurve;
		}
		throw new Error('expected an EC key algorithm with a namedCurve');
	}

	it('importSpkiDer infers the algorithm and curve from the DER when none is given', async () => {
		const rsa = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const rsaDer = await rsa.exportSpkiDer();
		const rsaPublic = unwrap(await importSpkiDer(rsaDer));
		expect(rsaPublic.algorithm.name).toBe('RSASSA-PKCS1-v1_5');
		expect(await exportSpkiDer(rsaPublic)).toEqual(rsaDer);

		for (const curve of ['P-256', 'P-384', 'P-521'] as const) {
			const ec = await generateKeyPair({ kind: 'ecdsa', curve });
			const ecDer = await ec.exportSpkiDer();
			const ecPublic = unwrap(await importSpkiDer(ecDer));
			expect(ecPublic.algorithm.name).toBe('ECDSA');
			expect(namedCurveOf(ecPublic.algorithm)).toBe(curve);
			expect(await exportSpkiDer(ecPublic)).toEqual(ecDer);
		}

		const ed = await generateKeyPair({ kind: 'ed25519' });
		const edDer = await ed.exportSpkiDer();
		const edPublic = unwrap(await importSpkiDer(edDer));
		expect(edPublic.algorithm.name).toBe('Ed25519');
		expect(await exportSpkiDer(edPublic)).toEqual(edDer);
	});

	it('importSpkiPem/Base64 infer the algorithm from the encoded key', async () => {
		const ec = await generateKeyPair({ kind: 'ecdsa', curve: 'P-384' });
		const fromPem = unwrap(await importSpkiPem(await ec.exportSpkiPem()));
		const fromBase64 = unwrap(await importSpkiBase64(await exportBinaryBase64(ec.publicKey)));
		expect(namedCurveOf(fromPem.algorithm)).toBe('P-384');
		expect(namedCurveOf(fromBase64.algorithm)).toBe('P-384');
	});

	it('importSpkiDer still asserts against an explicitly requested algorithm', async () => {
		const rsa = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		await expectImportFailure(
			importSpkiDer(await rsa.exportSpkiDer(), { kind: 'ecdsa', curve: 'P-256' }),
			'malformed',
			'SubjectPublicKeyInfo algorithm does not match requested import algorithm',
		);
	});

	it('importSpkiDer without a hint rejects an unsupported algorithm OID', async () => {
		const { bitString, sequence, objectIdentifier } = await import('#micro509/internal/asn1/der');
		// A well-formed SPKI whose AlgorithmIdentifier OID the library does not support (DSA).
		const unsupported = sequence([
			sequence([objectIdentifier('1.2.840.10040.4.1')]),
			bitString(Uint8Array.of(0x00), 0),
		]);
		await expectImportFailure(
			importSpkiDer(unsupported),
			'malformed',
			'Unsupported SubjectPublicKeyInfo algorithm',
		);
	});

	describe('RSA-OAEP', () => {
		/** One shared OAEP pair — RSA keygen is the slow part, every test reuses it. */
		let pairCache: Promise<KeyPairMaterial> | undefined;
		function oaepPair(): Promise<KeyPairMaterial> {
			pairCache ??= generateKeyPair({ kind: 'rsa', scheme: 'oaep', modulusLength: 2048 });
			return pairCache;
		}

		/** Assert an OAEP Result failed with the given code and message substring. */
		function expectOaepFailure(
			result:
				| { readonly ok: true; readonly value: Uint8Array }
				| { readonly ok: false; readonly code: string; readonly message: string },
			code: string,
			messagePart: string,
		): void {
			expect(result.ok).toBe(false);
			if (result.ok) {
				return;
			}
			expect(result.code).toBe(code);
			expect(result.message).toContain(messagePart);
		}

		it('generates encrypt/decrypt pairs and roundtrips a message', async () => {
			const pair = await oaepPair();
			expect(pair.publicKey.algorithm.name).toBe('RSA-OAEP');
			expect(pair.publicKey.usages).toContain('encrypt');
			expect(pair.privateKey.usages).toContain('decrypt');

			const plaintext = new TextEncoder().encode('booga booga session key');
			const ciphertext = unwrap(await encryptRsaOaep(pair.publicKey, plaintext));
			expect(ciphertext.length).toBe(256); // always modulus-sized for RSA-2048
			expect(unwrap(await decryptRsaOaep(pair.privateKey, ciphertext))).toEqual(plaintext);
		});

		it('binds the label: decryption requires the exact same label', async () => {
			const pair = await oaepPair();
			const plaintext = Uint8Array.of(1, 2, 3);
			const label = new TextEncoder().encode('context-v1');
			const ciphertext = unwrap(await encryptRsaOaep(pair.publicKey, plaintext, { label }));

			expect(unwrap(await decryptRsaOaep(pair.privateKey, ciphertext, { label }))).toEqual(
				plaintext,
			);
			expectOaepFailure(
				await decryptRsaOaep(pair.privateKey, ciphertext),
				'decryption_failed',
				'RSA-OAEP decryption failed',
			);
			expectOaepFailure(
				await decryptRsaOaep(pair.privateKey, ciphertext, {
					label: new TextEncoder().encode('context-v2'),
				}),
				'decryption_failed',
				'RSA-OAEP decryption failed',
			);
		});

		it('fails with decryption_failed on tampered ciphertext', async () => {
			const pair = await oaepPair();
			const ciphertext = unwrap(await encryptRsaOaep(pair.publicKey, Uint8Array.of(42)));
			const tampered = Uint8Array.from(ciphertext);
			const first = tampered[0];
			if (first === undefined) {
				throw new Error('empty ciphertext');
			}
			tampered[0] = first ^ 0xff;
			expectOaepFailure(
				await decryptRsaOaep(pair.privateKey, tampered),
				'decryption_failed',
				'RSA-OAEP decryption failed',
			);
		});

		it('rejects non-OAEP and wrong-type keys with invalid_key', async () => {
			const pair = await oaepPair();
			const signingRsa = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
			const payload = Uint8Array.of(1);

			expectOaepFailure(
				await encryptRsaOaep(signingRsa.publicKey, payload),
				'invalid_key',
				"generate or import the key with scheme: 'oaep'",
			);
			expectOaepFailure(
				await encryptRsaOaep(pair.privateKey, payload),
				'invalid_key',
				'requires a public CryptoKey',
			);
			expectOaepFailure(
				await decryptRsaOaep(pair.publicKey, payload),
				'invalid_key',
				'requires a private CryptoKey',
			);
			expectOaepFailure(
				await decryptRsaOaep(signingRsa.privateKey, payload),
				'invalid_key',
				"generate or import the key with scheme: 'oaep'",
			);
		});

		it('reports message_too_long past the OAEP capacity boundary', async () => {
			const pair = await oaepPair();
			// RSA-2048 + SHA-256: capacity = 256 − 2·32 − 2 = 190 bytes.
			const atCapacity = new Uint8Array(190).fill(7);
			const roundTripped = unwrap(
				await decryptRsaOaep(
					pair.privateKey,
					unwrap(await encryptRsaOaep(pair.publicKey, atCapacity)),
				),
			);
			expect(roundTripped).toEqual(atCapacity);
			expectOaepFailure(
				await encryptRsaOaep(pair.publicKey, new Uint8Array(191)),
				'message_too_long',
				'exceeds the RSA-OAEP capacity',
			);
		});

		it('OrThrow variants throw with the same diagnostics', async () => {
			const pair = await oaepPair();
			const plaintext = Uint8Array.of(9, 9, 9);
			const ciphertext = await encryptRsaOaepOrThrow(pair.publicKey, plaintext);
			expect(await decryptRsaOaepOrThrow(pair.privateKey, ciphertext)).toEqual(plaintext);
			expect(decryptRsaOaepOrThrow(pair.publicKey, ciphertext)).rejects.toThrow(
				'requires a private CryptoKey',
			);
			expect(
				decryptRsaOaepOrThrow(pair.privateKey, ciphertext, { label: Uint8Array.of(1) }),
			).rejects.toThrow('RSA-OAEP decryption failed');
		});

		it('roundtrips OAEP keys through PKCS#8, SPKI, and JWK', async () => {
			const pair = await oaepPair();
			const plaintext = Uint8Array.of(4, 5, 6);

			const privatePem = await pair.exportPkcs8Pem();
			const privateFromPem = unwrap(
				await importPkcs8Pem(privatePem, { kind: 'rsa', scheme: 'oaep' }),
			);
			expect(privateFromPem.algorithm.name).toBe('RSA-OAEP');

			const publicFromDer = unwrap(
				await importSpkiDer(await pair.exportSpkiDer(), { kind: 'rsa', scheme: 'oaep' }),
			);
			const publicFromJwk = unwrap(
				await importPublicJwk(await pair.exportPublicJwk(), { kind: 'rsa', scheme: 'oaep' }),
			);
			const privateFromJwk = unwrap(
				await importPrivateJwk(await pair.exportPrivateJwk(), { kind: 'rsa', scheme: 'oaep' }),
			);

			for (const publicKey of [publicFromDer, publicFromJwk]) {
				const ciphertext = unwrap(await encryptRsaOaep(publicKey, plaintext));
				expect(unwrap(await decryptRsaOaep(privateFromPem, ciphertext))).toEqual(plaintext);
				expect(unwrap(await decryptRsaOaep(privateFromJwk, ciphertext))).toEqual(plaintext);
			}
		});

		it('derivePublicKey yields an encrypting public key from an OAEP private key', async () => {
			const pair = await oaepPair();
			const derived = await derivePublicKey(pair.privateKey);
			expect(derived.algorithm.name).toBe('RSA-OAEP');
			expect(derived.usages).toContain('encrypt');
			const plaintext = Uint8Array.of(7, 8);
			const ciphertext = unwrap(await encryptRsaOaep(derived, plaintext));
			expect(unwrap(await decryptRsaOaep(pair.privateKey, ciphertext))).toEqual(plaintext);
		});
	});
});

describe('keys: algorithm inference', () => {
	it('imports PKCS#8 without an algorithm across key families', async () => {
		const ec = await generateKeyPair({ kind: 'ecdsa', curve: 'P-384' });
		const ecKey = unwrap(await importPkcs8Pem(await exportPkcs8Pem(ec.privateKey)));
		expect(ecKey.algorithm).toMatchObject({ name: 'ECDSA', namedCurve: 'P-384' });
		expect(ecKey.usages).toContain('sign');

		const ed = await generateKeyPair({ kind: 'ed25519' });
		const edKey = unwrap(await importPkcs8Der(await exportPkcs8Der(ed.privateKey)));
		expect(edKey.algorithm.name).toBe('Ed25519');

		const rsa = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const rsaKey = unwrap(await importPkcs8Base64(await exportBinaryBase64(rsa.privateKey)));
		expect(rsaKey.algorithm).toMatchObject({
			name: 'RSASSA-PKCS1-v1_5',
			hash: { name: 'SHA-256' },
		});
	});

	it('imports encrypted PKCS#8 without an algorithm and keeps the invalid_password code', async () => {
		const ec = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
		const pem = await exportEncryptedPkcs8Pem(ec.privateKey, {
			password: 'secret',
			iterations: 1000,
		});
		const key = unwrap(await importEncryptedPkcs8Pem(pem, 'secret'));
		expect(key.algorithm).toMatchObject({ name: 'ECDSA', namedCurve: 'P-256' });

		const wrongPassword = await importEncryptedPkcs8Pem(pem, 'not-the-password');
		expect(wrongPassword.ok).toBe(false);
		if (!wrongPassword.ok) expect(wrongPassword.code).toBe('invalid_password');
	});

	it('rejects PKCS#8 inference for an unsupported private key algorithm', async () => {
		const { objectIdentifier, octetString, sequence } = await import('#micro509/internal/asn1/der');
		// PrivateKeyInfo with the X25519 OID (1.3.101.110) — valid envelope,
		// unsupported algorithm family.
		const x25519Pkcs8 = sequence([
			Uint8Array.of(0x02, 0x01, 0x00),
			sequence([objectIdentifier('1.3.101.110')]),
			octetString(octetString(new Uint8Array(32))),
		]);
		await expectImportFailure(importPkcs8Der(x25519Pkcs8), 'malformed');
	});

	it('returns typed failures when inferred key material is malformed', async () => {
		const { integerFromNumber, nullValue, objectIdentifier, octetString, sequence } = await import(
			'#micro509/internal/asn1/der'
		);
		const malformedRsaPkcs8 = sequence([
			integerFromNumber(0),
			sequence([objectIdentifier('1.2.840.113549.1.1.1'), nullValue()]),
			octetString(Uint8Array.of(0x01)),
		]);
		await expectImportFailure(importPkcs8Der(malformedRsaPkcs8), 'malformed');
		await expectImportFailure(
			importPublicJwk({ kty: 'EC', crv: 'P-256', x: 'AA', y: 'AA' }),
			'malformed',
		);
	});

	it('imports SEC 1 without an algorithm via the embedded named curve', async () => {
		const keys = await generateKeyPair({ kind: 'ecdsa', curve: 'P-521' });
		// exportSec1Der injects RFC 5915 `parameters [0]`, so the curve is self-describing.
		const sec1Der = await exportSec1Der(keys.privateKey);
		const fromDer = unwrap(await importSec1Der(sec1Der));
		expect(fromDer.algorithm).toMatchObject({ name: 'ECDSA', namedCurve: 'P-521' });
		const fromPem = unwrap(await importSec1Pem(await exportSec1Pem(keys.privateKey)));
		expect(await exportPkcs8Der(fromPem)).toEqual(await exportPkcs8Der(keys.privateKey));
	});

	it('rejects SEC 1 inference when the parameters field is absent', async () => {
		const { readSequenceChildren, sequence } = await import('#micro509/internal/asn1/der');
		const keys = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
		const sec1Der = await exportSec1Der(keys.privateKey);
		// Strip `parameters [0]` to model a minimal RFC 5915 encoding.
		const children = readSequenceChildren(sec1Der);
		const withoutParameters = sequence(
			children
				.filter((child) => child.tag !== 0xa0)
				.map((child) => sec1Der.slice(child.start - child.headerLength, child.end)),
		);
		await expectImportFailure(
			importSec1Der(withoutParameters),
			'malformed',
			'SEC 1 private key does not encode a supported named curve',
		);
		// The explicit curve keeps working for minimal encodings.
		const explicit = unwrap(
			await importSec1Der(withoutParameters, { kind: 'ecdsa', curve: 'P-256' }),
		);
		expect(explicit.type).toBe('private');
	});

	it('imports JWKs without an algorithm using kty, crv, and alg', async () => {
		const ec = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
		const ecPrivate = unwrap(await importPrivateJwk(await exportPrivateJwk(ec.privateKey)));
		expect(ecPrivate.algorithm).toMatchObject({ name: 'ECDSA', namedCurve: 'P-256' });
		const ecPublic = unwrap(await importPublicJwk(await exportPublicJwk(ec.publicKey)));
		expect(ecPublic.usages).toContain('verify');

		const ed = await generateKeyPair({ kind: 'ed25519' });
		const edKey = unwrap(await importPrivateJwk(await exportPrivateJwk(ed.privateKey)));
		expect(edKey.algorithm.name).toBe('Ed25519');

		const pss = await generateKeyPair({ kind: 'rsa', scheme: 'pss', hash: 'SHA-384' });
		// Bun exports alg: 'PS384' — inference must honor it or WebCrypto rejects the JWK.
		const pssKey = unwrap(await importPrivateJwk(await exportPrivateJwk(pss.privateKey)));
		expect(pssKey.algorithm).toMatchObject({ name: 'RSA-PSS', hash: { name: 'SHA-384' } });

		const oaep = await generateKeyPair({ kind: 'rsa', scheme: 'oaep' });
		// alg: 'RSA-OAEP-256' selects the OAEP scheme and decrypt usage.
		const oaepKey = unwrap(await importPrivateJwk(await exportPrivateJwk(oaep.privateKey)));
		expect(oaepKey.algorithm.name).toBe('RSA-OAEP');
		expect(oaepKey.usages).toContain('decrypt');

		const rsaJwk = await exportPublicJwk(pss.publicKey);
		if (typeof rsaJwk.n !== 'string' || typeof rsaJwk.e !== 'string') {
			throw new Error('expected an RSA public JWK');
		}
		const rsaCases = [
			{
				expectedName: 'RSASSA-PKCS1-v1_5',
				expectedHash: 'SHA-256',
				expectedUsages: ['verify'],
			},
			{
				alg: 'RS256',
				expectedName: 'RSASSA-PKCS1-v1_5',
				expectedHash: 'SHA-256',
				expectedUsages: ['verify'],
			},
			{
				alg: 'RS384',
				expectedName: 'RSASSA-PKCS1-v1_5',
				expectedHash: 'SHA-384',
				expectedUsages: ['verify'],
			},
			{
				alg: 'RS512',
				expectedName: 'RSASSA-PKCS1-v1_5',
				expectedHash: 'SHA-512',
				expectedUsages: ['verify'],
			},
			{
				alg: 'PS256',
				expectedName: 'RSA-PSS',
				expectedHash: 'SHA-256',
				expectedUsages: ['verify'],
			},
			{
				alg: 'PS512',
				expectedName: 'RSA-PSS',
				expectedHash: 'SHA-512',
				expectedUsages: ['verify'],
			},
			{
				alg: 'RSA-OAEP-384',
				expectedName: 'RSA-OAEP',
				expectedHash: 'SHA-384',
				expectedUsages: ['encrypt'],
			},
			{
				alg: 'RSA-OAEP-512',
				expectedName: 'RSA-OAEP',
				expectedHash: 'SHA-512',
				expectedUsages: ['encrypt'],
			},
		] as const satisfies readonly {
			readonly alg?: string;
			readonly expectedName: string;
			readonly expectedHash: string;
			readonly expectedUsages: readonly KeyUsage[];
		}[];
		for (const rsaCase of rsaCases) {
			const imported = unwrap(
				await importPublicJwk({
					kty: 'RSA',
					n: rsaJwk.n,
					e: rsaJwk.e,
					...('alg' in rsaCase ? { alg: rsaCase.alg } : {}),
				}),
			);
			expect(imported.algorithm).toMatchObject({
				name: rsaCase.expectedName,
				hash: { name: rsaCase.expectedHash },
			});
			expect(imported.usages).toEqual([...rsaCase.expectedUsages]);
		}
	});

	it('rejects JWK inference for unsupported curves and RSA algs', async () => {
		await expectImportFailure(
			importPublicJwk({ kty: 'EC', crv: 'secp256k1', x: 'AA', y: 'AA' }),
			'malformed',
			'Unsupported EC JWK curve',
		);
		// Plain 'RSA-OAEP' means OAEP with SHA-1, which this library does not support.
		await expectImportFailure(
			importPublicJwk({ kty: 'RSA', alg: 'RSA-OAEP', n: 'AA', e: 'AQAB' }),
			'malformed',
			'Unsupported RSA JWK alg',
		);
		await expectImportFailure(
			importPublicJwk({ kty: 'oct', k: 'AA' }),
			'malformed',
			'Unsupported JWK key type',
		);
	});
});

describe('encrypted PKCS#8 KDF work-factor limit', () => {
	it('rejects PBKDF2 iteration counts above maxKdfIterations before deriving', async () => {
		const keyPair = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
		const der = await exportEncryptedPkcs8Der(keyPair.privateKey, {
			password: 'secret',
			iterations: 4096,
		});

		const rejected = await importEncryptedPkcs8Der(der, 'secret', undefined, {
			maxKdfIterations: 2048,
		});
		expect(rejected.ok).toBe(false);
		if (!rejected.ok) {
			expect(rejected.error.code).toBe('kdf_iterations_exceeded');
		}

		const accepted = await importEncryptedPkcs8Der(der, 'secret', undefined, {
			maxKdfIterations: 4096,
		});
		expect(accepted.ok).toBe(true);
	});

	it('rejects a maxKdfIterations that is not a positive integer', async () => {
		const keyPair = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
		const der = await exportEncryptedPkcs8Der(keyPair.privateKey, { password: 'secret' });

		expect(
			importEncryptedPkcs8Der(der, 'secret', undefined, { maxKdfIterations: 0 }),
		).rejects.toThrow(RangeError);
	});

	it('caps PBKDF2 iterations at 2,000,000 by default', async () => {
		const algorithmIdentifier = encodePbes2AlgorithmIdentifier({
			iterations: 2_000_001,
			salt: new Uint8Array(8),
			iv: new Uint8Array(16),
			cipher: 'AES-256-CBC',
			prf: 'HMAC-SHA-256',
		});
		const der = sequence([algorithmIdentifier, octetString(new Uint8Array(16))]);

		const result = await importEncryptedPkcs8Der(der, 'secret');
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.code).toBe('kdf_iterations_exceeded');
		}
	});
});
