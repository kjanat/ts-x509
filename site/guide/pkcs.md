---
outline: [2, 3]
---

# PKCS

## PFX / PKCS#12

### Create a PFX bundle

<LiveCode>

```ts
import {
  createSelfSignedCertificate,
  unwrap,
} from 'micro509';
import { createPfx } from 'micro509/pkcs';

const ca = await createSelfSignedCertificate({
  subject: { commonName: 'Demo CA' },
  extensions: { basicConstraints: { ca: true } },
});
const cert = await createSelfSignedCertificate({
  subject: { commonName: 'leaf.example' },
});

// createPfx returns a typed result; unwrap once inputs are validated
const pfx = unwrap(
  await createPfx({
    certificates: [
      { certificate: cert.certificate.pem },
      { certificate: ca.certificate.pem },
    ],
    privateKeys: [{ privateKey: cert.keyPair.privateKey }],
    encryption: { password: 'secret' },
    mac: { password: 'secret' },
  }),
);

console.log(`\
der bytes:  ${pfx.der.length}
base64 len: ${pfx.base64.length}`);

console.log(pfx.pem);
```

</LiveCode>

### Parse a PFX bundle

<LiveCode>

```ts
import {
  createSelfSignedCertificate,
  unwrap,
} from 'micro509';
import { createPfx, parsePfxDer } from 'micro509/pkcs';

// Build a PFX inline to parse back
const cert = await createSelfSignedCertificate({
  subject: { commonName: 'leaf.example' },
});
const pfx = unwrap(
  await createPfx({
    certificates: [{ certificate: cert.certificate.pem }],
    privateKeys: [{ privateKey: cert.keyPair.privateKey }],
    encryption: { password: 'secret' },
    mac: { password: 'secret' },
  }),
);

const result = await parsePfxDer(pfx.der, {
  password: 'secret',
});

if (result.ok) {
  const { certificates, privateKeys, bags, macData } =
    result.value;
  const leafCert = certificates[0];
  console.log(`\
bags:    ${bags.map((bag) => bag.kind).join(', ')}
subject: ${leafCert?.subject.values.commonName}, serial ${leafCert?.serialNumberHex}
key:     ${privateKeys[0]?.length} bytes of PKCS#8 DER
MAC:     ${macData?.verification} (${macData?.digestAlgorithmName})`);
} else {
  console.log(`parse failed: ${result.error.code}`);
}
```

</LiveCode>

Both the MAC and the PBES2 key bags carry their own KDF iteration counts, and
parsing refuses a count above its ceiling with `kdf_iterations_exceeded`. The
PBES2 bags allow 2,000,000, matching encrypted PKCS#8. The MAC allows 100,000,
because RFC 7292 Appendix B derives its key one digest at a time rather than
through native PBKDF2, so a round costs far more. `maxKdfIterations` in the
options overrides both.

## PKCS#7 / CMS

### Create a certificate bag

<LiveCode>

```ts
import {
  createSelfSignedCertificate,
  unwrap,
} from 'micro509';
import { createPkcs7CertBag } from 'micro509/pkcs';

// Two real certificates to bundle
const a = await createSelfSignedCertificate({
  subject: { commonName: 'a.example' },
});
const b = await createSelfSignedCertificate({
  subject: { commonName: 'b.example' },
});

// createPkcs7CertBag returns a typed result; unwrap on the success path
const bag = unwrap(
  createPkcs7CertBag([
    a.certificate.pem,
    b.certificate.pem,
  ]),
);

console.log(`der bytes: ${bag.der.length}`);
console.log(bag.pem);
```

</LiveCode>

### Parse a certificate bag

<LiveCode>

```ts
import {
  createSelfSignedCertificate,
  unwrap,
} from 'micro509';
import {
  createPkcs7CertBag,
  parsePkcs7CertBagPem,
} from 'micro509/pkcs';

// Build a real cert bag inline
const a = await createSelfSignedCertificate({
  subject: { commonName: 'a.example' },
});
const b = await createSelfSignedCertificate({
  subject: { commonName: 'b.example' },
});
const bag = unwrap(
  createPkcs7CertBag([
    a.certificate.pem,
    b.certificate.pem,
  ]),
);

const result = parsePkcs7CertBagPem(bag.pem);

if (result.ok) {
  const certificates = result.value;
  console.log(`certs: ${certificates.length}`);
  for (const cert of certificates) {
    console.log(
      `${cert.subject.values.commonName}, serial ${cert.serialNumberHex}, ${cert.publicKeyAlgorithmName}`,
    );
  }
} else {
  console.log(`parse failed: ${result.error.code}`);
}
```

</LiveCode>

### Sign and verify content

<LiveCode>

```ts
import { createSelfSignedCertificate } from 'micro509';
import {
  createPkcs7SignedData,
  verifyPkcs7SignedData,
} from 'micro509/pkcs';

// A signer is a certificate + its matching private key
const signer = await createSelfSignedCertificate({
  subject: { commonName: 'signer.example' },
  extensions: { keyUsage: ['digitalSignature'] },
});

// Sign content -> attached CMS SignedData (RFC 5652)
const content = new TextEncoder().encode('hello');
const signed = await createPkcs7SignedData({
  content,
  signers: [
    {
      certificate: signer.certificate.pem,
      privateKey: signer.keyPair.privateKey,
    },
  ],
});

// Creation returns a typed result; verify on success
if (!signed.ok) {
  console.log(`sign failed: ${signed.error.code}`);
} else {
  const result = await verifyPkcs7SignedData(
    signed.value.pem,
  );
  if (result.ok) {
    // result.signers pairs each SignerInfo with the
    // certificate that verified its signature
    const entry = result.signers[0];
    console.log(`\
verified:  true
signers:   ${result.signers.length}
signed by: ${entry?.certificate.subject.values.commonName}, serial ${entry?.certificate.serialNumberHex}
digest:    ${entry?.signerInfo.digestAlgorithmName}
signature: ${entry?.signerInfo.signatureAlgorithmName}, ${entry?.signerInfo.signatureHex.slice(0, 48)}…
der size:  ${signed.value.der.length} bytes`);
  } else {
    console.log(`verify: ${result.error.code}`);
  }
}
```

</LiveCode>

### Detached signatures

Pass `detached: true` to omit the content from the SignedData (RFC 5652 §5.2):
the signature still covers it via the `messageDigest` signed attribute, but
the verifier must supply the bytes externally. This is the shape git x509
commit signing and S/MIME detached signatures use — git stores only the CMS
blob in the commit header and provides the commit bytes at verification time.

<LiveCode>

```ts
import { createSelfSignedCertificate } from 'micro509';
import {
  createPkcs7SignedData,
  verifyPkcs7SignedData,
} from 'micro509/pkcs';

const signer = await createSelfSignedCertificate({
  subject: { commonName: 'detached.example' },
  extensions: { keyUsage: ['digitalSignature'] },
});

const content = new TextEncoder().encode('tree abc…');
const signed = await createPkcs7SignedData({
  content,
  detached: true,
  signers: [
    {
      certificate: signer.certificate.pem,
      privateKey: signer.keyPair.privateKey,
    },
  ],
});

if (!signed.ok) {
  console.log(`sign failed: ${signed.error.code}`);
} else {
  // Without the content, verification fails typed:
  const missing = await verifyPkcs7SignedData(
    signed.value.der,
  );

  // Tampered content: digest check catches it
  const forged = await verifyPkcs7SignedData(
    signed.value.der,
    { content: new TextEncoder().encode('tree evil…') },
  );

  // The externally-held original bytes verify
  const result = await verifyPkcs7SignedData(
    signed.value.der,
    { content },
  );

  const info = result.ok
    ? result.value.signerInfos[0]
    : undefined;
  console.log(`\
blob size:   ${signed.value.der.length} bytes (no eContent)
no content:  ok=${missing.ok} (${missing.ok ? '' : missing.error.code})
forged:      ok=${forged.ok} (${forged.ok ? '' : forged.error.code})
original:    ok=${result.ok}
signature:   ${info?.signatureAlgorithmName}, ${info?.signatureHex.slice(0, 48)}…
digest:      ${info?.digestAlgorithmName}`);
}
```

</LiveCode>

When the SignedData embeds its own content (the attached default), the
embedded content is what gets verified and `options.content` is ignored.

## PEM utilities

<LiveCode>

```ts
import {
  createSelfSignedCertificate,
  unwrap,
} from 'micro509';
import {
  categorizePemBlocks,
  pemDecode,
  pemEncode,
  splitPemBlocks,
} from 'micro509/pem';

// A real certificate to feed the PEM helpers
const { certificate } = await createSelfSignedCertificate({
  subject: { commonName: 'pem.example' },
});
const pem = certificate.pem;

// Decode a single PEM block to DER (typed result)
const der = unwrap(pemDecode('CERTIFICATE', pem));

// Encode DER back to PEM
const pemEncoded = pemEncode('CERTIFICATE', der);

// Split a multi-block PEM file
const multiPem = `${pem}\n${pem}`;
const blocks = unwrap(splitPemBlocks(multiPem));

// Categorize blocks by type
const { certificates, certificateRequests, privateKeys } =
  unwrap(categorizePemBlocks(multiPem));

console.log(`\
der bytes:    ${der.length}
der tail:     ${[...der.slice(-8)]
  .map((byte) => byte.toString(16).padStart(2, '0'))
  .join(' ')}
round-trip:   ${pemEncoded === pem}
blocks:       ${blocks.map((block) => block.label).join(', ')}
certs:        ${certificates.length}
csrs:         ${certificateRequests.length}
private keys: ${privateKeys.length}`);
```

</LiveCode>
