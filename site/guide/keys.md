---
outline: [2, 3]
---

# Keys

## Generate a key pair

<LiveCode>

```ts
import { generateKeyPair } from 'micro509';
import { exportBinaryBase64 } from 'micro509/keys';

// Ed25519
const ed = await generateKeyPair({ kind: 'ed25519' });

// ECDSA P-256
const ec = await generateKeyPair({
  kind: 'ecdsa',
  curve: 'P-256',
});

// RSA 2048
const rsa = await generateKeyPair({
  kind: 'rsa',
  modulusLength: 2048,
});

const spki = async (key: CryptoKey) =>
  `…${(await exportBinaryBase64(key)).slice(-32)}`;

console.log(`\
ed25519: ${ed.publicKey.algorithm.name} (${ed.privateKey.usages.join('/')}), spki ${await spki(ed.publicKey)}
ecdsa:   ${JSON.stringify(ec.publicKey.algorithm)}, spki ${await spki(ec.publicKey)}
rsa:     ${rsa.publicKey.algorithm.name} (${rsa.privateKey.usages.join('/')}), spki ${await spki(rsa.publicKey)}`);
```

</LiveCode>

## Import and export

### PKCS#8 (private keys)

<LiveCode>

```ts
import { generateKeyPair, unwrap } from 'micro509';
import {
  exportPkcs8Pem,
  importPkcs8Pem,
} from 'micro509/keys';

const keys = await generateKeyPair({
  kind: 'ecdsa',
  curve: 'P-256',
});
const pem = await exportPkcs8Pem(keys.privateKey);

const privateKey = unwrap(
  await importPkcs8Pem(pem, {
    kind: 'ecdsa',
    curve: 'P-256',
  }),
);
const exported = await exportPkcs8Pem(privateKey);

const body = pem
  .trimEnd()
  .split('\n')
  .slice(1, -1)
  .join('');
console.log(`\
algorithm:  ${JSON.stringify(privateKey.algorithm)}
usages:     ${privateKey.usages.join(', ')}
PEM tail:   …${body.slice(-44)}
round-trip: ${exported === pem}`);
```

</LiveCode>

The algorithm argument is optional. A PKCS#8 PrivateKeyInfo encodes its own
`privateKeyAlgorithm` (and, for EC keys, the curve), so `importPkcs8Pem`,
`importPkcs8Der`, and `importPkcs8Base64` — and their encrypted siblings —
infer it when no hint is given, which is what you want for user-provided key
material whose type isn't known ahead of time:

```ts
// Inferred from the DER — no { kind, curve } needed.
const privateKey = unwrap(await importPkcs8Pem(pem));
```

Passing an explicit algorithm still works and additionally asserts that the key
matches it, failing with a `'malformed'` result on a mismatch. An RSA key
inferred without a hint defaults to `pkcs1-v1_5` with SHA-256 (a plain
`rsaEncryption` envelope encodes neither padding scheme nor hash) — pass
`{ kind: 'rsa', scheme: 'pss' }` or an explicit `hash` when you need
something else.

### SPKI (public keys)

<LiveCode>

```ts
import { generateKeyPair, unwrap } from 'micro509';
import {
  exportSpkiPem,
  importSpkiPem,
} from 'micro509/keys';

const keys = await generateKeyPair({
  kind: 'ecdsa',
  curve: 'P-256',
});
const pem = await exportSpkiPem(keys.publicKey);

const publicKey = unwrap(
  await importSpkiPem(pem, {
    kind: 'ecdsa',
    curve: 'P-256',
  }),
);
const exported = await exportSpkiPem(publicKey);

const body = pem
  .trimEnd()
  .split('\n')
  .slice(1, -1)
  .join('');
console.log(`\
algorithm:  ${JSON.stringify(publicKey.algorithm)}
usages:     ${publicKey.usages.join(', ')}
PEM tail:   …${body.slice(-44)}
round-trip: ${exported === pem}`);
```

</LiveCode>

The algorithm argument is optional for SPKI imports. A SubjectPublicKeyInfo
already encodes its algorithm OID (and, for EC keys, the curve), so
`importSpkiPem`, `importSpkiDer`, and `importSpkiBase64` infer it when no hint
is given — handy when the key type isn't known ahead of time:

```ts
// Inferred from the DER — no { kind, curve } needed.
const publicKey = unwrap(await importSpkiPem(pem));
```

Passing an explicit algorithm still works and additionally asserts that the key
matches it, failing with a `'malformed'` result on a mismatch.

### Derive a public key from a private key

The `import*` functions for private keys hand back a bare `CryptoKey` with only
`sign` usage — there is no matching public handle. `derivePublicKey` bridges
that gap, so a private key loaded from disk can go straight to
`exportSpkiPem`/`exportSpkiDer` (e.g. to rebuild a self-signed certificate or
distribute the public key). It supports RSA, ECDSA, and Ed25519.

<LiveCode>

```ts
import { generateKeyPair, unwrap } from 'micro509';
import {
  derivePublicKey,
  exportBinaryBase64,
  exportSpkiPem,
  importPkcs8Pem,
} from 'micro509/keys';

const keys = await generateKeyPair({
  kind: 'ecdsa',
  curve: 'P-256',
});

// Start from a private key that carries no public handle.
const privateKey = unwrap(
  await importPkcs8Pem(await keys.exportPkcs8Pem(), {
    kind: 'ecdsa',
    curve: 'P-256',
  }),
);

const publicKey = await derivePublicKey(privateKey);
const spki = await exportSpkiPem(publicKey);

console.log(`\
derived: ${JSON.stringify(publicKey.algorithm)} (${publicKey.usages.join(', ')})
spki:    …${(await exportBinaryBase64(publicKey)).slice(-44)}
matches: ${spki === (await keys.exportSpkiPem())}`);
```

</LiveCode>

### JWK

<LiveCode>

```ts
import { generateKeyPair, unwrap } from 'micro509';
import {
  exportPrivateJwk,
  exportPublicJwk,
  importPrivateJwk,
  importPublicJwk,
} from 'micro509/keys';

const keys = await generateKeyPair({
  kind: 'ecdsa',
  curve: 'P-256',
});
const pubJwk = await exportPublicJwk(keys.publicKey);
const privJwk = await exportPrivateJwk(keys.privateKey);

const publicKey = unwrap(
  await importPublicJwk(pubJwk, {
    kind: 'ecdsa',
    curve: 'P-256',
  }),
);
const privateKey = unwrap(
  await importPrivateJwk(privJwk, {
    kind: 'ecdsa',
    curve: 'P-256',
  }),
);

console.log(`\
kty/crv: ${pubJwk.kty}/${pubJwk.crv}
x:       ${pubJwk.x}
y:       ${pubJwk.y}
usages:  ${publicKey.usages.join(', ')} | ${privateKey.usages.join(', ')}`);
```

</LiveCode>

The algorithm argument is optional for JWK imports too: `kty`, `crv`, and
`alg` already describe the key, so `importPublicJwk(jwk)` and
`importPrivateJwk(jwk)` infer it. The JWA `alg` member selects the RSA scheme
and hash (`RS384` → PKCS#1 v1.5/SHA-384, `PS256` → PSS/SHA-256,
`RSA-OAEP-256` → OAEP/SHA-256); an RSA JWK without `alg` defaults to
PKCS#1 v1.5 with SHA-256.

### PKCS#1 (RSA-specific)

<LiveCode>

```ts
import { generateKeyPair, unwrap } from 'micro509';
import {
  exportPkcs1Pem,
  importPkcs1Pem,
} from 'micro509/keys';

const keys = await generateKeyPair({
  kind: 'rsa',
  modulusLength: 2048,
});
const pem = await exportPkcs1Pem(keys.privateKey);

const privateKey = unwrap(
  await importPkcs1Pem(pem, {
    kind: 'rsa',
    scheme: 'pkcs1-v1_5',
  }),
);
const exported = await exportPkcs1Pem(privateKey);

console.log(`\
algorithm:  ${privateKey.algorithm.name}
pem lines:  ${pem.split('\n').length}
PEM base64: ${pem.split('\n')[2]?.slice(0, 44)}…
round-trip: ${exported === pem}`);
```

</LiveCode>

### SEC1 (EC-specific)

<LiveCode>

```ts
import { generateKeyPair, unwrap } from 'micro509';
import {
  exportSec1Pem,
  importSec1Pem,
} from 'micro509/keys';

const keys = await generateKeyPair({
  kind: 'ecdsa',
  curve: 'P-256',
});
const pem = await exportSec1Pem(keys.privateKey);

const privateKey = unwrap(
  await importSec1Pem(pem, {
    kind: 'ecdsa',
    curve: 'P-256',
  }),
);
const exported = await exportSec1Pem(privateKey);

console.log(`\
algorithm:  ${JSON.stringify(privateKey.algorithm)}
PEM base64: ${pem.split('\n')[1]?.slice(0, 44)}…
round-trip: ${exported === pem}`);
```

</LiveCode>

Exported SEC1 keys always embed the RFC 5915 `parameters [0]` named curve
(matching OpenSSL), so `importSec1Pem(pem)` infers the curve when the
algorithm argument is omitted. A minimal SEC1 encoding without the embedded
curve still needs the explicit `{ kind: 'ecdsa', curve }`.

## Encrypted keys

### Encrypted PKCS#8

<LiveCode>

```ts
import { generateKeyPair } from 'micro509';
import {
  exportEncryptedPkcs8Pem,
  importEncryptedPkcs8Pem,
} from 'micro509/keys';

const keys = await generateKeyPair({
  kind: 'ecdsa',
  curve: 'P-256',
});

// Export with PBES2 encryption
const pem = await exportEncryptedPkcs8Pem(keys.privateKey, {
  password: 'password',
});

// Import with the same password — returns a Result
const result = await importEncryptedPkcs8Pem(
  pem,
  'password',
  {
    kind: 'ecdsa',
    curve: 'P-256',
  },
);

if (!result.ok) {
  // result.error.code is 'invalid_password' on a wrong password,
  // or 'malformed' on structurally invalid input
  throw new Error(result.error.code);
}

// A wrong password is a typed failure, not an exception
const wrong = await importEncryptedPkcs8Pem(pem, 'nope');

const body = pem
  .trimEnd()
  .split('\n')
  .slice(1, -1)
  .join('');
console.log(`\
algorithm:  ${JSON.stringify(result.value.algorithm)}
ciphertext: …${body.slice(-44)}
wrong pw:   ok=${wrong.ok} (${wrong.ok ? '' : wrong.error.code})`);
```

</LiveCode>

The PBKDF2 iteration count comes from the file, so a hostile envelope can ask
for billions of rounds before the password is even checked. Import refuses
counts above 2,000,000 with `kdf_iterations_exceeded`; pass
`{ maxKdfIterations }` as the fourth argument to raise or lower that bound.

### Inspect encryption parameters

`inspectEncryptedPkcs8Der()` reads the PBES2 parameters of an encrypted key
without the password, so you can audit how strongly a key is protected
before deciding to import it.

<LiveCode>

```ts
import { generateKeyPair } from 'micro509';
import {
  exportEncryptedPkcs8Der,
  inspectEncryptedPkcs8Der,
} from 'micro509/keys';

const keys = await generateKeyPair({
  kind: 'ecdsa',
  curve: 'P-256',
});

const der = await exportEncryptedPkcs8Der(keys.privateKey, {
  password: 'password',
  iterations: 600_000,
});

const params = inspectEncryptedPkcs8Der(der);

const hex = (bytes: Uint8Array) =>
  Array.from(bytes, (byte) =>
    byte.toString(16).padStart(2, '0'),
  ).join('');
console.log(`\
cipher:     ${params.cipher}
prf:        ${params.prf}
iterations: ${params.iterations}
salt:       ${hex(params.salt)}
iv:         ${hex(params.iv)}`);
```

</LiveCode>

### Legacy encrypted PEM (OpenSSL format)

<LiveCode>

```ts
import { generateKeyPair, unwrap } from 'micro509';
import {
  exportEncryptedPkcs1Pem,
  importEncryptedPkcs1Pem,
} from 'micro509/keys';

const keys = await generateKeyPair({
  kind: 'rsa',
  modulusLength: 2048,
});

// Export RSA key with AES-256-CBC
const pem = await exportEncryptedPkcs1Pem(keys.privateKey, {
  password: 'password',
  cipher: 'AES-256-CBC',
});

// Import with the same password
const privateKey = unwrap(
  await importEncryptedPkcs1Pem(pem, 'password', {
    kind: 'rsa',
    scheme: 'pkcs1-v1_5',
  }),
);

// The DEK-Info header carries the (random) AES-CBC IV
const dekInfo = pem
  .split('\n')
  .find((line) => line.startsWith('DEK-Info'));

console.log(`\
DEK-Info:  ${dekInfo?.slice('DEK-Info: '.length)}
algorithm: ${privateKey.algorithm.name}
usages:    ${privateKey.usages.join(', ')}`);
```

</LiveCode>

## RSA-OAEP encryption

Generate or import RSA keys with `scheme: 'oaep'` to get an encryption pair
(`encrypt`/`decrypt` usages instead of `sign`/`verify`), then use
`encryptRsaOaep` / `decryptRsaOaep`. RSA-OAEP fits at most
modulus bytes − 2 × hash bytes − 2 per call (190 bytes for RSA-2048 with
SHA-256) — encrypt a symmetric key, not bulk data.

An optional `label` is bound to the ciphertext: decryption fails unless the
exact same label is presented. Decryption failures are deliberately opaque
(`decryption_failed`) — OAEP does not reveal whether the key, label, or
ciphertext was wrong.

<LiveCode>

```ts
import { generateKeyPair, unwrap } from 'micro509';
import {
  decryptRsaOaep,
  encryptRsaOaep,
} from 'micro509/keys';

const keys = await generateKeyPair({
  kind: 'rsa',
  scheme: 'oaep',
  modulusLength: 2048,
});

const label = new TextEncoder().encode('context-v1');
const ciphertext = unwrap(
  await encryptRsaOaep(
    keys.publicKey,
    new TextEncoder().encode('session key'),
    { label },
  ),
);

const plaintext = unwrap(
  await decryptRsaOaep(keys.privateKey, ciphertext, {
    label,
  }),
);

// Wrong label: opaque failure, never a partial plaintext
const wrongLabel = await decryptRsaOaep(
  keys.privateKey,
  ciphertext,
);

console.log(`\
ciphertext:  ${ciphertext.length} bytes, starts ${[...ciphertext.slice(0, 4)].join(' ')}
roundtrip:   ${new TextDecoder().decode(plaintext)}
wrong label: ok=${wrongLabel.ok} (${wrongLabel.ok ? '' : wrongLabel.code})`);
```

</LiveCode>
