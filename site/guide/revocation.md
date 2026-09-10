---
outline: [2, 3]
---

# Revocation

The examples below build their own `ca`, `leaf`, CRL, and OCSP material
inline so each one runs on its own.

::: warning Revocation checking defaults to hard-fail
Revocation checking only runs when you supply evidence — and once you do,
`RevocationPolicy.mode` defaults to `'hard-fail'`: certificates whose
revocation status is **indeterminate** (no applicable CRL/OCSP evidence,
expired evidence, untrusted signer) are **denied**. If availability matters
more than strictness — partial evidence is normal in your setup — opt out
explicitly with `policy: { mode: 'soft-fail' }`, which allows indeterminate
status and denies only on a confirmed `revoked` verdict.
:::

## CRL lifecycle

### Create a CRL

<LiveCode>

```ts
import {
  createSelfSignedCertificate,
  createCertificateRevocationList,
} from 'micro509';

const ca = await createSelfSignedCertificate({
  subject: { commonName: 'My CA' },
  extensions: {
    basicConstraints: { ca: true },
    keyUsage: ['keyCertSign', 'cRLSign'],
  },
});

const crl = await createCertificateRevocationList({
  issuer: { commonName: 'My CA' },
  signerPrivateKey: ca.keyPair.privateKey,
  issuerPublicKey: ca.keyPair.publicKey,
  thisUpdate: new Date(),
  nextUpdate: new Date(
    Date.now() + 7 * 24 * 60 * 60 * 1000,
  ),
  revokedCertificates: [
    {
      serialNumber: Uint8Array.of(0x01),
      revocationDate: new Date(),
      reasonCode: 'keyCompromise',
    },
  ],
});

console.log(crl.pem);
```

</LiveCode>

### Parse and validate a CRL

<LiveCode>

```ts
import { createSelfSignedCertificate } from 'micro509';
import {
  createCertificateRevocationList,
  isCertificateRevoked,
  validateCertificateRevocationList,
} from 'micro509/revocation';

const ca = await createSelfSignedCertificate({
  subject: { commonName: 'My CA' },
  extensions: {
    basicConstraints: { ca: true },
    keyUsage: ['keyCertSign', 'cRLSign'],
  },
});

const crl = await createCertificateRevocationList({
  issuer: { commonName: 'My CA' },
  signerPrivateKey: ca.keyPair.privateKey,
  issuerPublicKey: ca.keyPair.publicKey,
  revokedCertificates: [
    {
      serialNumber: Uint8Array.of(0x01),
      reasonCode: 'keyCompromise',
    },
  ],
});

const validationResult =
  await validateCertificateRevocationList({
    crl: crl.pem,
    issuerCertificate: ca.certificate.pem,
  });

if (!validationResult.ok) {
  console.log(
    `validation failed: ${validationResult.code}`,
  );
} else {
  const parsed = validationResult.value;
  const entry = parsed.revokedCertificates[0];
  const body = crl.pem
    .trimEnd()
    .split('\n')
    .slice(1, -1)
    .join('');
  console.log(`\
validated:  true
sig algo:   ${parsed.signatureAlgorithmName}
signature:  …${body.slice(-44)}
thisUpdate: ${parsed.thisUpdate.toISOString()}
entry 01:   revoked ${entry?.revocationDate.toISOString().slice(0, 10)}, reason ${entry?.reasonCode}
revoked 01: ${isCertificateRevoked('01', parsed)}
revoked 02: ${isCertificateRevoked('02', parsed)}`);
}
```

</LiveCode>

`nextUpdate` is optional in RFC 5280, and a CRL without one never goes stale
on its own, so a replayed pre-revocation CRL would validate forever. Set
`maxAgeMs` to bound how old `thisUpdate` may be; the same knob is
`crlMaxAgeMs` on the chain-level revocation policy.

## OCSP

### Build a request

<LiveCode>

```ts
import {
  createCertificate,
  createSelfSignedCertificate,
  generateKeyPair,
} from 'micro509';
import {
  createOcspRequest,
  parseOcspRequestDerOrThrow,
} from 'micro509/revocation';

const ca = await createSelfSignedCertificate({
  subject: { commonName: 'Demo CA' },
  extensions: {
    basicConstraints: { ca: true },
    keyUsage: ['keyCertSign', 'cRLSign'],
  },
});

const leafKeys = await generateKeyPair();
const leaf = await createCertificate({
  issuer: { commonName: 'Demo CA' },
  subject: { commonName: 'app.example.com' },
  publicKey: leafKeys.publicKey,
  signerPrivateKey: ca.keyPair.privateKey,
  issuerPublicKey: ca.keyPair.publicKey,
});

const request = await createOcspRequest({
  requests: [
    {
      certificate: leaf.pem,
      issuerCertificate: ca.certificate.pem,
    },
  ],
});

// Parse it back to see the CertID the responder will look up
const certId = parseOcspRequestDerOrThrow(request.der)
  .requests[0];
console.log(`\
serial:   ${certId?.serialNumberHex}
hashed:   with ${certId?.hashAlgorithmName} (RFC 9919 default)
key hash: ${certId?.issuerKeyHashHex}`);
console.log(request.pem);
```

</LiveCode>

### Parse and validate a response

<LiveCode>

```ts
import {
  createCertificate,
  createSelfSignedCertificate,
  generateKeyPair,
} from 'micro509';
import {
  createOcspRequest,
  createOcspResponse,
  parseOcspResponseDerOrThrow,
  validateOcspResponse,
} from 'micro509/revocation';

const ca = await createSelfSignedCertificate({
  subject: { commonName: 'Demo CA' },
  extensions: {
    basicConstraints: { ca: true },
    keyUsage: ['keyCertSign', 'cRLSign'],
  },
});

const leafKeys = await generateKeyPair();
const leaf = await createCertificate({
  issuer: { commonName: 'Demo CA' },
  subject: { commonName: 'app.example.com' },
  publicKey: leafKeys.publicKey,
  signerPrivateKey: ca.keyPair.privateKey,
  issuerPublicKey: ca.keyPair.publicKey,
});

const nonce = crypto.getRandomValues(new Uint8Array(16));
const nonceHex = Array.from(nonce, (byte) =>
  byte.toString(16).padStart(2, '0'),
).join('');
const request = await createOcspRequest({
  nonce,
  requests: [
    {
      certificate: leaf.pem,
      issuerCertificate: ca.certificate.pem,
    },
  ],
});

// Responder signs an OCSP response for the leaf
const ocsp = await createOcspResponse({
  signerPrivateKey: ca.keyPair.privateKey,
  signerCertificate: ca.certificate.pem,
  nonce,
  responses: [
    {
      certificate: leaf.pem,
      issuerCertificate: ca.certificate.pem,
      certStatus: 'good',
    },
  ],
});

const response = parseOcspResponseDerOrThrow(ocsp.der);

// Verifies the signature, binds and authorizes the
// responder against the issuer, matches the nonce and
// every requested CertID, and checks freshness
const result = await validateOcspResponse({
  response,
  request: request.der,
  issuerCertificate: ca.certificate.pem,
});

if (result.ok) {
  const entry = result.value.responses?.[0];
  const responder = response.responderId;
  console.log(`\
status:     ${response.responseStatus}, ${entry?.certStatus}
serial:     ${entry?.certId.serialNumberHex}
certId:     hashed with ${entry?.certId.hashAlgorithmName} (RFC 9919 default)
responder:  ${responder?.type === 'byKeyHash' ? `key hash ${responder.keyHashHex}` : 'by name'}
signature:  ${response.signatureAlgorithmName}, verified
nonce:      ${response.nonce === nonceHex ? 'echoed' : response.nonce}
window:     ${entry?.thisUpdate.toISOString()} → ${entry?.nextUpdate?.toISOString() ?? 'no commitment'}
producedAt: ${response.producedAt?.toISOString()}`);
} else {
  console.log(`invalid: ${result.error.code}`);
}
```

</LiveCode>

## Orchestrated revocation check

<LiveCode>

```ts
import {
  createCertificate,
  createSelfSignedCertificate,
  generateKeyPair,
  parseCertificatePem,
  unwrap,
} from 'micro509';
import {
  checkCertificateRevocation,
  createCertificateRevocationList,
  createOcspResponse,
  revocationReasonFromCode,
} from 'micro509/revocation';

const ca = await createSelfSignedCertificate({
  subject: { commonName: 'Demo CA' },
  extensions: {
    basicConstraints: { ca: true },
    keyUsage: ['keyCertSign', 'cRLSign'],
  },
});

const leafKeys = await generateKeyPair();
const leaf = await createCertificate({
  issuer: { commonName: 'Demo CA' },
  subject: { commonName: 'app.example.com' },
  publicKey: leafKeys.publicKey,
  signerPrivateKey: ca.keyPair.privateKey,
  issuerPublicKey: ca.keyPair.publicKey,
});

// Leaf serial as bytes for the CRL entry
const parsedLeaf = unwrap(parseCertificatePem(leaf.pem));
const serialHex = parsedLeaf.serialNumberHex;
const leafSerial = Uint8Array.from(
  serialHex.match(/.{2}/g) ?? [],
  (byte) => parseInt(byte, 16),
);

// CRL evidence that revokes the leaf
const crl = await createCertificateRevocationList({
  issuer: { commonName: 'Demo CA' },
  signerPrivateKey: ca.keyPair.privateKey,
  issuerPublicKey: ca.keyPair.publicKey,
  revokedCertificates: [
    {
      serialNumber: leafSerial,
      revocationDate: new Date(),
      reasonCode: 'keyCompromise',
    },
  ],
});

// OCSP evidence that also reports revoked
const ocsp = await createOcspResponse({
  signerPrivateKey: ca.keyPair.privateKey,
  signerCertificate: ca.certificate.pem,
  responses: [
    {
      certificate: leaf.pem,
      issuerCertificate: ca.certificate.pem,
      certStatus: 'revoked',
      revokedAt: new Date(),
      revocationReasonCode: 1,
    },
  ],
});

const result = await checkCertificateRevocation({
  certificate: leaf.pem,
  issuerCertificate: ca.certificate.pem,
  evidence: [
    { kind: 'crl', crl: crl.pem },
    { kind: 'ocsp', response: ocsp.der },
  ],
});

// Check ok, then the status discriminator
if (!result.ok) {
  throw new Error('unreachable: evidence was supplied');
}
if (result.value.status === 'revoked') {
  // CRL evidence reports a RevocationReason name,
  // OCSP a raw CRLReason integer;
  // revocationReasonFromCode() maps the integer to
  // the same name so either path yields one answer
  const reason =
    result.value.revocationReason ??
    revocationReasonFromCode(
      result.value.revocationReasonCode,
    );
  console.log(`\
status:     revoked
serial:     ${serialHex}
revoked at: ${result.value.revokedAt?.toISOString()}
reason:     ${reason}`);
} else {
  console.log('status:', result.value.status);
}
```

</LiveCode>

## Chain-level revocation

`checkChainRevocation()` evaluates CRL **and** OCSP evidence for every
certificate in a validated chain (the trust anchor is never checked). Each
OCSP response is fully validated — signature, responder binding and
authorization, freshness — before its verdict is trusted, and a validated
`revoked` verdict from either evidence kind always wins, regardless of
`policy.prefer`.

When both sources yield a validated `good` verdict, `policy.prefer` decides
which one is reported: the default `'best-available'` picks the source with
the fresher evidence (later `thisUpdate`, ties favoring OCSP), while `'ocsp'`
and `'crl'` pin the reported source unconditionally. The winning evidence's
timestamp is reported as `source.thisUpdate` on each certificate's status,
so callers can enforce their own maximum evidence age.

The same inputs are available on `verifyCertificateChain()` via the
`revocation` option:

<LiveCode>

```ts
import {
  createCertificate,
  createOcspResponse,
  createSelfSignedCertificate,
  generateKeyPair,
  verifyCertificateChain,
} from 'micro509';

const ca = await createSelfSignedCertificate({
  subject: { commonName: 'Demo CA' },
  extensions: {
    basicConstraints: { ca: true },
    keyUsage: ['keyCertSign', 'cRLSign'],
  },
});

const leafKeys = await generateKeyPair();
const leaf = await createCertificate({
  issuer: { commonName: 'Demo CA' },
  subject: { commonName: 'app.example.com' },
  publicKey: leafKeys.publicKey,
  signerPrivateKey: ca.keyPair.privateKey,
  issuerPublicKey: ca.keyPair.publicKey,
});

const ocsp = await createOcspResponse({
  signerPrivateKey: ca.keyPair.privateKey,
  signerCertificate: ca.certificate.pem,
  responses: [
    {
      certificate: leaf.pem,
      issuerCertificate: ca.certificate.pem,
      certStatus: 'good',
      thisUpdate: new Date(Date.now() - 60_000),
      nextUpdate: new Date(Date.now() + 3_600_000),
    },
  ],
});

const result = await verifyCertificateChain({
  leaf: leaf.pem,
  roots: [ca.certificate.pem],
  revocation: {
    // hard-fail is the default: indeterminate status ⇒ verification fails
    ocspResponses: [ocsp.der],
  },
});

if (result.ok) {
  const parsedLeaf = result.value.leaf;
  console.log(`\
verified: true
leaf:     ${parsedLeaf.subject.values.commonName}
serial:   ${parsedLeaf.serialNumberHex}
chain:    ${result.value.chain.length} certificates`);
} else {
  console.log(`verified: false (${result.error.code})`);
}
```

</LiveCode>
