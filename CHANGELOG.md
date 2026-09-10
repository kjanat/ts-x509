# Changelog

<!--
Release checklist — every box, every release:
- [ ] Move [Unreleased] entries under a new `## [X.Y.Z] - YYYY-MM-DD` header + intro line
- [ ] Bump version in package.json AND jsr.json
- [ ] Bump the `micro509` range in examples/vite/package.json and examples/browser/index.html's `<script type="importmap">`
- [ ] Run `bun install` after the example bump so bun.lock matches; CI installs with a frozen lockfile
- [ ] Link definitions at the BOTTOM of this file: add [X.Y.Z] compare link, repoint [Unreleased]
- [ ] Signed tag on the release commit: git tag -s vX.Y.Z -m "vX.Y.Z - summary"
- [ ] Push master + tag, gh release create with milestone notes
- [ ] Verify npm dist-tag latest + JSR after the publish workflow
-->

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `maxKdfIterations` on the encrypted PKCS#8 imports (`ImportEncryptedKeyOptions`,
  fourth argument), `parsePfxDer` / `parsePfxPem` options, and
  `parsePkcs12MacData` bounds the PBKDF2 and PKCS#12 KDF iteration counts a
  file may demand. Above the bound the import fails with
  `kdf_iterations_exceeded` before any derivation runs. The default is
  2,000,000 for PBKDF2 and 100,000 for the PKCS#12 KDF, which RFC 7292
  Appendix B derives one digest at a time. See Security.
- `maxAgeMs` on `validateCertificateRevocationList` and
  `checkCertificateRevocationAgainstCrl`, `crlMaxAgeMs` on
  `checkCertificateRevocation` and the chain-level `RevocationPolicy`, bound
  how old a CRL's `thisUpdate` may be. See Security.

### Changed

- npm and JSR packages include `CHANGELOG.md` in the published tarball
  (`package.json` `files`, `jsr.json` `publish.include`).
- `trustedOcspResponders` on `checkChainRevocation()` and
  `verifyCertificateChain({ revocation })` takes `TrustedOcspResponder`
  entries (`{ issuerCertificate, responderCertificate }`) instead of bare
  certificates. See Security.

### Fixed

- A CRL rejected by `crlMaxAgeMs` reported `no_applicable_crl` on the chain
  result, hiding the configured freshness policy's actual outcome. It now
  reports `crl_expired`.
- Two `site/guide/keys.md` LiveCode examples used TypeScript parameter types
  (`key: CryptoKey`, `bytes: Uint8Array`). LiveCode injects examples as browser
  JS modules, so Run failed with `missing ) after argument list` and
  `Unexpected token ':'`. The annotations are removed.

### Security

- Chain-level OCSP evaluation returned on the first validated `good` response,
  so a `revoked` response later in `ocspResponses` was never read and a
  revoked certificate passed with `decision: 'allow'`. Every applicable
  response is now validated; any validated `revoked` verdict wins regardless
  of position, and otherwise the freshest validated `good` response by
  `thisUpdate` is reported. A `certificateHold` (RFC 5280 §5.3.1 reason 6)
  still denies unless a validated `good` response carries a later
  `thisUpdate`, which clears the hold.
  (https://github.com/kjanat/micro509/pull/108,
  https://github.com/kjanat/micro509/pull/110)
- `trustedOcspResponders` on chain-level revocation was a flat list applied to
  every issuer in the chain, so a responder trusted for one CA could assert
  status for certificates issued by any other CA in the same path (RFC 6960
  §4.2.2.2 criterion 1 binds local trust to the issuing CA). Each entry now
  names the issuer it is trusted for, and only responders bound to the issuer
  under evaluation reach `validateOcspResponse`.
  (https://github.com/kjanat/micro509/pull/111)
- URI-ID matching accepted a scheme-specific path as an authority, so a
  hostless SAN such as `https:verify.example` matched the reference identifier
  `https://verify.example` in `verifyCertificateChain` and
  `validateForTlsServer`. A URI now needs a syntactically valid scheme and an
  explicit `//` authority (RFC 3986 §3.2), and its reg-name must normalize as a
  DNS name; `sip:` and `sips:` keep their authority-less form (RFC 3261 §19.1).
  (https://github.com/kjanat/micro509/pull/109)
- `ecdsaSignatureDerToRaw` and the ECDSA verify path trimmed leading zero
  bytes from each `ECDSA-Sig-Value` INTEGER without checking the encoding, so
  an empty, negative, or non-minimally encoded `r` or `s` (X.690 §8.3)
  normalized into a raw signature WebCrypto could verify, giving a second
  accepted encoding of one signature. Such INTEGERs are now rejected.
  (https://github.com/kjanat/micro509/pull/100)
- `verifyPkcs7SignedData` reported `ok: true` for a detached `SignedData`
  whose `signerInfos` set was empty when the caller supplied `content`,
  verifying nothing. A `SignedData` with no signer now fails with `malformed`.
  (https://github.com/kjanat/micro509/pull/106)
- Distinguished-name comparison classified combining marks with the runtime's
  `\p{M}`, which tracks the host Unicode version. RFC 4518 §2.6.1 keys
  insignificant-space handling on combining marks, and Appendix A lists them
  definitively against the Unicode 3.2 repertoire §2.1 fixes. A code point
  reclassified since 3.2 (U+1885, U+06DE) changed which spaces survived, so a
  directoryName excluded subtree could fail to match. The Appendix A set is
  now generated from the vendored RFC text and guarded by a test that
  re-derives it. (https://github.com/kjanat/micro509/pull/102)
- A caller-supplied extension decoder that threw a native error (for example
  `TextDecoder` with `fatal: true` on invalid UTF-8) escaped the
  Result-returning certificate and CSR parse functions as an exception. The
  decoder boundary now maps such errors to `code: 'malformed'`, so attacker
  bytes in an extension cannot crash a parser call.
  (https://github.com/kjanat/micro509/pull/107)
- The `site/guide/revocation.md` CRL example looked up revoked entries after a
  failed signature check. It now calls `validateCertificateRevocationList` and
  reads entries only from the validated value.
  (https://github.com/kjanat/micro509/pull/104)
- Third-party GitHub Actions in the release, test, and site workflows are
  pinned to commit SHAs again; mutable tags had let upstream ref movement run
  unreviewed code with `id-token: write` and `contents: write`.
  (https://github.com/kjanat/micro509/pull/103)
- Encrypted PKCS#8 import and PFX parsing ran PBKDF2, and PFX MAC
  verification ran the PKCS#12 KDF, for whatever iteration count the file
  encoded before the password or ciphertext could be rejected. A 122-byte
  EncryptedPrivateKeyInfo or a 177-byte PFX carrying `0x7fffffff` iterations
  held the CPU for minutes. Counts above the ceiling are now refused before
  derivation; `maxKdfIterations` adjusts it.
- A PFX gave every encrypted entry the full `maxKdfIterations` allowance, so a
  file with many small entries could demand unbounded work without any encoded
  count standing out: 100 entries at the default ceiling ask for 200 million
  PBKDF2 rounds. One budget now covers the whole file.
- Bare trust anchors were re-verified on every visit to a certificate, because
  the anchor match ran before the dead-end lookup. A bundle of same-subject CAs
  plus a few subject-matching anchors made anchor signature checks grow with
  the search graph rather than the input: 40 candidates and 20 anchors cost
  3.7s. Each certificate-and-anchor pair is now checked once per search.
- Path building memoized dead ends per visited set, so a bundle of `n`
  same-subject CA certificates sharing one key cost on the order of `n³`
  signature verifications before `no_trusted_root` (30 candidates: 9,426 key
  imports and 18,852 verify calls). Dead ends are now memoized per certificate
  and CA count, and each certificate-to-key signature check runs once per
  search.
- A CRL without `nextUpdate` validated at any later time, so a replayed CRL
  from before a revocation stayed usable indefinitely. RFC 5280 §5.1.2.5 makes
  `nextUpdate` optional, so the check remains opt-in: `maxAgeMs` /
  `crlMaxAgeMs` reject a CRL whose `thisUpdate` is older than the bound with
  `stale_crl`.
- The dprint TOML formatter installed `tombi` unversioned and globally from
  npm on every fresh setup, so the registry chose the code that ran. `tombi`
  is now a catalog-pinned devDependency; the exec plugin runs
  `node_modules/.bin/tombi` and its setup command is `bun install`.
- The OpenSSL differential job ran against whatever OpenSSL the runner image
  shipped. It now pins `ubuntu-26.04` and fails unless `openssl version`
  reports 3.5.5, so an oracle change surfaces as a version assertion instead
  of as verdict or formatting drift.

## [0.14.0] - 2026-07-29

Everything that already worked but had no export: a `micro509/crypto`
entrypoint for detached signatures, extension decoders, RFC 5280 §7.1
distinguished-name comparison, PKCS#7 signer resolution, and PBES2
inspection. Plus three wrongful-acceptance fixes under Security and a
stricter typed-contract pass.

### Added

- `ParsedCertificate.issuerAltNames` decodes the issuerAltName extension
  (RFC 5280 §4.2.1.7, OID 2.5.29.18) with the subjectAltName GeneralNames
  decoder.
- `checkCertificateRevocationAgainstCrl` reports `coveredReasons` on a `good`
  value: the RFC 5280 §6.3.3 (d) interim_reasons_mask computed from the matched
  distribution point's `reasons` and the CRL's `onlySomeReasons`.
- `verifyPkcs7SignedData` success values carry `signers`, pairing each
  SignerInfo with the certificate that verified its signature
  (`VerifiedPkcs7Signer`), so callers can check trust, EKU, or identity of the
  actual signer without reimplementing the issuerAndSerial DN match.
  (https://github.com/kjanat/micro509/issues/67)
- `micro509/crypto`, a new entrypoint for detached signatures: `verifySignature`
  checks raw bytes against a signer's SubjectPublicKeyInfo across RSA PKCS#1
  v1.5, RSA-PSS, ECDSA P-256/P-384/P-521, and Ed25519, retrying the alternate
  DER/raw ECDSA encoding; `signData` signs with a WebCrypto key and returns the
  signature beside its `AlgorithmIdentifier` material; `ecdsaSignatureDerToRaw`
  and `ecdsaSignatureRawToDer` convert between the DER `ECDSA-Sig-Value` X.509
  and CMS embed and the raw `r || s` form WebCrypto and JOSE use.
  (https://github.com/kjanat/micro509/issues/65)
- `micro509/x509` exports its extension-value decoders as the `decode*`
  inverses of the existing encoders (`decodeKeyUsage`, `decodeBasicConstraints`,
  `decodeSubjectAltNames`, …, `decodeAuthorityKeyIdentifier`), the RFC 5280
  §7.1 semantic DN comparison (`compareDistinguishedNames`, `canonicalDnKey`,
  `isWithinDirectoryNameSubtree`), `parseDistinguishedNameDer` for a bare
  `Name`, the `parseCertificateFromSource` / `parseCertificatesFromSource`
  input normalizers, `subjectKeyIdentifier` (RFC 5280 §4.2.1.2 method (1)),
  and the IP helpers name-constraint inputs demand (`parseIpAddressToBytes`,
  `decodeIpAddress`, `allOnesMaskForIpAddress`, `normalizeIpAddress`).
  (https://github.com/kjanat/micro509/issues/64)
- `isSelfIssuedCertificate` from `micro509/verify`: the RFC 5280 §7.1
  subject-equals-issuer predicate path validation already used internally.
  (https://github.com/kjanat/micro509/issues/65)
- `inspectEncryptedPkcs8Der` reads the PBES2 parameters of an encrypted PKCS#8
  key without the password (iterations, salt, PRF, AES-CBC variant, IV), and
  `micro509/keys` exports `parsePbes2AlgorithmIdentifier` with the
  `Pbes2Parameters` types behind it.
  (https://github.com/kjanat/micro509/issues/66)
- `revocationReasonFromCode` maps a raw CRLReason integer to the
  `RevocationReason` name the CRL path already returns, giving OCSP's
  `revocationReasonCode` the same vocabulary.
  (https://github.com/kjanat/micro509/issues/68)
- `micro509/result` exports `rethrowIfInvariant`, the boundary guard the
  library's own catch blocks use to keep programmer errors from being
  flattened into malformed-input failures.
  (https://github.com/kjanat/micro509/issues/69)

### Changed

- Tighten four exported TypeScript contracts to make invalid states
  unrepresentable. These changes can require source updates:
  - `CrlEncoderErrorCode` now contains only
    `'distribution_point_full_name_empty'`.
    `'distribution_point_name_conflict'` and
    `'distribution_point_name_empty'` are removed because
    `DistributionPointName` is now a discriminated union that cannot express
    either invalid shape.
  - `ParsedOcspSingleResponse` is now discriminated by `certStatus`.
    `revokedAt` and `revocationReasonCode` are available only after narrowing to
    `certStatus === 'revoked'`; `revokedAt` is then required.
  - `CreateOcspCertStatusInput` rejects `revokedAt` and
    `revocationReasonCode` unless `certStatus` is `'revoked'`, including when a
    previously declared object is passed instead of an object literal.
  - `CreateSelfSignedCertificateInput` no longer accepts both `keyPair` and
    `algorithm`. Supply `keyPair` to reuse existing keys, or `algorithm` to
    generate a new pair.

  ```ts
  if (singleResponse.certStatus === 'revoked') {
    singleResponse.revokedAt; // Date
    singleResponse.revocationReasonCode; // number | undefined
  }

  await createSelfSignedCertificate({ subject, keyPair });
  await createSelfSignedCertificate({
    subject,
    algorithm: { kind: 'ecdsa', curve: 'P-256' },
  });
  ```

- `ParsedPkcs7SignedData.certificates: readonly ParsedCertificate[]` becomes
  `certificateChoices: readonly ParsedCertificateChoice[]`, modelling RFC 5652
  §10.2.2 CertificateChoices as a discriminated union rather than discarding
  four of its five alternatives. `certificate` carries the decoded X.509;
  `extendedCertificate` (`[0]`, obsolete), `attributeCertificateV1` (`[1]`,
  obsolete), `attributeCertificateV2` (`[2]`), and `other` (`[3]`, with its
  `otherCertFormat` OID decoded) keep their DER including the context tag, so a
  CertificateSet round-trips and a caller can tell an X.509-only bag from a
  mixed one. A certificate set entry whose tag is none of these is rejected as
  `malformed`; previously any non-SEQUENCE element was silently dropped.
  `parsePkcs7CertBagDer` and `parsePkcs7CertBagPem` still return
  `readonly ParsedCertificate[]`, now the X.509 projection of the set.
- Builder input-validation now throws a `ResultError` carrying a stable
  machine-readable `code` rather than a bare `Error`. `createCertificate`, the
  `encode*` extension helpers, distinguished-name encoding, and CRL/IDP encoding
  reject invalid construction input (an empty `keyUsage`, a duplicate policy OID,
  a `DisplayText` out of range, an invalid country code) with a coded throw that
  `isResultError` detects and `error.code` discriminates. Codes are per-operation
  unions (`ExtensionEncoderErrorCode`, `NameEncoderErrorCode`,
  `CrlEncoderErrorCode`, `CreateCertificateErrorCode`). DER decode guards and
  exhaustiveness invariants keep throwing a plain `Error`. The thrown message
  gains a `code: ` prefix. <!-- markdownlint-disable-line MD038 -->
- `AuthorityInformationAccess.uri: string` becomes `location: GeneralName`, the
  full accessLocation RFC 5280 §4.2.2.1 defines. The parser threw
  `Unsupported authorityInfoAccess location tag` for any location that was not a
  URI, so a certificate carrying a directoryName or dNSName accessLocation (both
  conformant) failed to parse entirely. An OCSP entry requires a URI location
  (its discovery reads only URIs); `directoryName` is defined for `caIssuers`,
  and other GeneralName forms are syntactically representable. GeneralName
  encoding and parsing now reject any tag, class, or constructedness that is not
  one of the nine RFC 5280 §4.2.1.6 alternatives (`x400Address [3]`,
  `ediPartyName [5]`, and `registeredID [8]` are preserved as unknown). The
  IA5String alternatives (`dNSName`, `rfc822Name`,
  `uniformResourceIdentifier`) reject non-ASCII input on encode and decode.
  (https://github.com/kjanat/micro509/pull/78)

### Fixed

- Signature verification accepts an absent parameters field on the
  sha256WithRSAEncryption, sha384WithRSAEncryption, and sha512WithRSAEncryption
  AlgorithmIdentifiers. RFC 4055 §5 requires the parameters to be NULL and
  requires implementations to accept them absent as well as present; every
  surface that resolves a signature algorithm reported
  `unsupported_signature_algorithm_parameters` for the absent encoding, so a
  conformant certificate, CRL, OCSP response, CSR, or PKCS#7 signature that
  omits the NULL could not be verified. Parameters that are neither absent nor
  a DER NULL are still rejected, and signatures this library produces still
  carry the NULL.
- `verifyCertificateChain` and `validateCandidatePath` no longer reject a
  self-issued leaf that another key signed. RFC 5280 §3.2 calls a self-issued
  certificate self-signed only when the public key it binds verifies its
  signature, but the guard behind `allowSelfSignedLeaf` fired on matching issuer
  and subject DNs alone. The RFC 8410 §10.2 example certificate is exactly that
  case, a self-issued X25519 certificate signed by a separate Ed25519 key, and
  failed with `self_signed_leaf_not_allowed` when anchored on the §10.1 key. The
  guard now verifies the leaf against its own public key first and only reports
  `self_signed_leaf_not_allowed` when that verification succeeds.
- Legacy OpenSSL-style encrypted PEM (`Proc-Type: 4,ENCRYPTED`) parsing accepts
  an encapsulated header with no space after the colon (`DEK-Info:AES-256-CBC,…`).
  The parser keyed on `': '`, so a conformant no-space header ended the header
  scan early and folded into the base64 body.
  (https://github.com/kjanat/micro509/pull/89)
- Legacy encrypted PEM parsing unfolds folded encapsulated headers. RFC 1421
  §4.6 defines encapsulated header folding by reference to RFC 822, and its
  Figure 2 folds a `Key-Info:` field across two lines. Every line was treated as
  a complete header, so a folded field was misparsed and its continuation fell
  into the base64 body. A line opening with an RFC 822 §3.3 `LWSP-char` (SPACE
  or HTAB) now continues the preceding field; per §3.1.1 unfolding drops the
  CRLF and keeps the whitespace, so the field-body and the `Proc-Type` and
  `DEK-Info` field comparisons strip the SPACE and HTAB unfolding leaves behind.
  Only those two characters are stripped: `String.prototype.trim` also removes
  VT, FF, NBSP, and every Unicode `Zs`, none of which RFC 822 admits, so a
  header such as `Proc-Type: 4,<NBSP>ENCRYPTED` is rejected rather than read as
  `4,ENCRYPTED`. (https://github.com/kjanat/micro509/issues/92)
- Certificate and CSR builders reject RFC 5280 MUST-NOT constructions with coded
  throws. `pathLenConstraint` requires the keyUsage extension to assert
  `keyCertSign`; absent, empty, or `keyCertSign`-less keyUsage is rejected
  (§4.2.1.9, `path_length_requires_key_cert_sign`). An empty subject DN requires
  a critical subjectAltName carrying at least one non-empty GeneralName; an empty
  typed value (`{ type: 'dns', value: '' }`), an empty `subjectAltNames` array,
  and a critical `customExtensions` SAN whose value holds no usable GeneralName
  are all rejected (§4.2.1.6, `empty_subject_requires_subject_alt_name`), so
  `subject: {}` can no longer sign a certificate with no identity. Encoding a
  GeneralName with an empty `dNSName`, `rfc822Name`, URI, or SRV value is
  rejected (§4.2.1.6, `empty_general_name_value`). A `cRLIssuer`, when present,
  may only contain `directoryName` entries, rejecting a non-DN entry or a
  directoryName smuggled through an `unknown` general name; a
  `nameRelativeToCRLIssuer` distribution point additionally permits only one
  (§4.2.1.13, `distribution_point_crl_issuer_not_directory_name`,
  `distribution_point_relative_name_multiple_crl_issuers`). Known extensions
  supplied through `customExtensions` participate in these cross-field checks.
  A `customExtensions` entry carrying a known OID must decode as that extension,
  rather than reaching the wire as opaque bytes the parser then rejects
  (`malformed_known_extension_value`). Extension OIDs resolve by their encoded
  value, so a non-canonical spelling such as `2.5.029.17` is the same extension
  as `2.5.29.17` for registry lookup, certificate-versus-CSR context
  restrictions, and duplicate detection; the diagnostic still quotes the OID as
  submitted. A custom `cRLDistributionPoints` payload runs the same §4.2.1.13
  cRLIssuer checks as the typed field, since decoding proves structure but not
  the profile the builder promises. `validateOid` also rejects an OID that parses
  as decimals but breaks the X.660 arc bounds (`3.1`, `1.40`) with `invalid_oid`
  rather than an uncoded `Error`.
  (https://github.com/kjanat/micro509/pull/88)
- CRL applicability follows the RFC 5280 §6.3.3 relying-party algorithm in
  three places it diverged. A certificate without a CRLDP extension accepts a
  CRL whose issuing distribution point names the certificate issuer or one of
  its issuerAltName entries, per the §6.3.3 assumed-distribution-point rule;
  such a CRL previously reported `non_applicable`. A distribution point that
  omits `distributionPoint` matches the CRL IDP name against its `cRLIssuer`
  names (§6.3.3 (b)(2)(i)); an in-scope indirect CRL was previously rejected.
  Reason coverage uses the §6.3.3 (d) interim_reasons_mask, unioned across every
  matching distribution point, instead of the CRL's `onlySomeReasons` alone, so
  a distribution point scoped to a subset of reasons no longer grants full
  coverage. Every consumer of a CRL `good` — `checkChainRevocation`,
  `checkCertificateRevocation`, delegated OCSP-responder validation, and
  recursive CRL-signer validation — now treats a reason-scoped `good` as
  definitive only once the applicable CRLs together cover all eight reasons; a
  revoked verdict from any CRL still wins immediately. GeneralName applicability
  comparisons apply the RFC 5280 name comparison rules: dNSName is
  case-insensitive (§7.2), the rfc822Name host-part is case-insensitive (§7.5),
  an `otherName` SRV-ID is case-insensitive in both halves (RFC 4985 §2), and a
  uniformResourceIdentifier is prepared per §7.4 — IDN labels to ASCII
  Compatible Encoding, lowercased scheme and host, percent-encoding and path
  segment normalization, and scheme-based normalization for `ftp`, `http`,
  `https`, and `ldap`. Certificate and CRL parsing now share one canonical
  GeneralName decoder, so an SRV-ID matches across issuerAltName and the IDP.
  `verifyCertificateChain` recognises a critical
  issuerAltName rather than rejecting it. A delta-CRL `removeFromCRL` entry for
  an expired certificate now measures expiry against the delta's `thisUpdate`
  (§5.2.4), not the evaluation time.
  (https://github.com/kjanat/micro509/pull/87)
- `importEncryptedPkcs1Pem` and `importEncryptedSec1Pem` report a wrong password
  as `invalid_password` rather than occasionally as `malformed`. Traditional PEM
  encrypts with unauthenticated AES-CBC, so a wrong key clears the PKCS#7 padding
  check roughly once in every 256 attempts and yields random plaintext; the
  decrypted bytes are now required to parse as an `RSAPrivateKey` or
  `ECPrivateKey`, which is the check the PBES2 path already applied.
- `importPkcs8Der` accepts a `OneAsymmetricKey` (RFC 5958 §2 / RFC 8410 §7) that
  carries both `attributes [0]` and `publicKey [1]`. The parser capped at four
  elements, so a five-element v2 key that OpenSSL and Node WebCrypto both accept
  returned `malformed`. The tail is now validated structurally rather than by
  ASN.1 class alone: `attributes [0]` must be a constructed `SET OF`, an optional
  `publicKey [1]` must be a primitive BIT STRING after it, the version is coupled
  to the public key's presence (`v2` iff present), and well-formed unknown
  extension additions are tolerated per the type's X.680 extensibility marker.
- SEC1 `ECPrivateKey` parsing rejects a version other than 1, comparing content
  octets (RFC 5915 §3, "version SHALL be ... one"). Only the tag was checked, so
  version 0 or 2 was deferred to the WebCrypto backend as a misleading error.
- PBES2 decryption no longer rejects a PBKDF2 salt shorter than eight bytes. RFC
  8018 §4.1 makes the eight-octet minimum a "should" for salt _selection_ and
  says the salt need not be checked on receipt, so `openssl pkcs8 -saltlen 4`
  could not be decrypted. The encrypt path keeps the minimum.
  (https://github.com/kjanat/micro509/pull/85)
- Distinguished-name encoding enforces the RFC 5280 Appendix A.1 attribute
  constraints: no attribute value may be empty (`SIZE (1..ub-…)`), and
  `commonName`/`organization`/`organizationalUnit`/`title`/`serialNumber` cap at
  64 characters, `locality`/`state` at 128, `emailAddress` at 255, and
  `surname`/`givenName` at 32768 (`ub-name`). Only the country exact-length-2
  rule was enforced before. `street` stays unbounded (no A.1 bound applies).
  Bounds count code points.
- `createCertificate` rejects an empty issuer distinguished name, per RFC 5280
  §4.1.2.4 ("The issuer field MUST contain a non-empty distinguished name"). An
  empty subject with a critical subjectAltName stays valid (§4.1.2.6).
  (https://github.com/kjanat/micro509/pull/84)
- PKCS#12 `MacData` omits `iterations` when it equals its `DEFAULT 1`, and the
  parser accepts a two-element `MacData`, defaulting `iterations` to 1
  (RFC 7292 §4, X.690 §11.5). A conformant PFX with iteration count 1 previously
  failed to parse.
- PBES2 `PBKDF2-params` omits the `prf` when it is the `DEFAULT`
  `algid-hmacWithSHA1` (RFC 8018 A.2, X.690 §11.5); `keyLength`, being OPTIONAL
  rather than DEFAULT, is still emitted. `exportEncryptedPkcs8Der(key, { prf: 'HMAC-SHA-1' })`
  produced a non-DER structure.
  (https://github.com/kjanat/micro509/pull/83)
- PKCS#7/CMS `SignedData` emits SHA-2 digest `AlgorithmIdentifier`s with absent
  parameters, per RFC 5754 §2 (a MUST). Both `digestAlgorithms` and each
  `SignerInfo.digestAlgorithm` carried an explicit `05 00` NULL.
- `createPkcs7CertBag` orders the `certificates` `CertificateSet` canonically
  (DER SET OF, X.690 §11.6), matching `createPkcs7SignedData`. It concatenated
  certificates in caller order, so the output was not valid DER and depended on
  input order.
  (https://github.com/kjanat/micro509/pull/82)
- PEM decoding handles every RFC 7468 §3 newline convention (`CRLF`, `CR`, `LF`).
  `pemDecode` and `splitPemBlocks` stripped `\r` outright, which joins every line
  of a CR-only file into one, so such a file failed to decode.
- `splitPemBlocks` accepts RFC 7468 labels with an internal `-` separator and no
  longer discards unrelated blocks in the same file when it meets a label it does
  not recognise.
- `pemEncode` emits the RFC 7468 strict trailing end-of-line, so concatenating
  two blocks no longer produces `-----END … ----------BEGIN …-----`, which
  `openssl storeutl` rejects. (https://github.com/kjanat/micro509/pull/81)
- `subjectAltName` parsing rejects an empty or non-SEQUENCE extension value, per
  RFC 5280 §4.2.1.6 (`GeneralNames ::= SEQUENCE SIZE (1..MAX)`). An empty SAN
  previously decoded to `[]`, indistinguishable from an absent extension, so
  common-name fallback suppression did not engage. `directoryName [4]` now
  requires exactly one explicit X.501 Name with valid RDN and attribute
  structure instead of repairing malformed implicit encodings, including in
  CRL GeneralNames.
- `extendedKeyUsage` parsing rejects an empty SEQUENCE and any child that is not
  an OBJECT IDENTIFIER, per RFC 5280 §4.2.1.12. `decodeObjectIdentifier` ran on
  every child regardless of tag, so `30 03 02 01 01` fabricated the OID `0.1`
  from an INTEGER. (https://github.com/kjanat/micro509/pull/80)
- Extension encoders reject input RFC 5280 forbids rather than emitting
  non-conformant DER: an empty `keyUsage` (§4.2.1.3), `extendedKeyUsage`
  (§4.2.1.12), `authorityInfoAccess`/`cRLDistributionPoints` (§4.2.2.1,
  §4.2.1.13) or `nameConstraints` (§4.2.1.10) SEQUENCE, a duplicate certificate
  policy OID compared by encoded identity so leading-zero aliases collide
  (§4.2.1.4), a policy qualifier reusing the built-in `cps` or `userNotice` OID
  in the opaque `oid` variant (§4.2.1.4), a `DisplayText` outside SIZE (1..200)
  (§4.2.1.4), and an IP name constraint whose address and mask do not total 8 or
  32 octets (§4.2.1.10). Each previously encoded a structure the library's own
  parser, or OpenSSL, rejects.
  (https://github.com/kjanat/micro509/pull/79)
- A `directoryName` SubjectAltName or name constraint now encodes the complete
  Name TLV inside `[4]`, per RFC 5280 §4.2.1.6 (Name is an untagged CHOICE, so
  `[4]` is EXPLICIT). The encoder stripped the Name's SEQUENCE header, emitting
  `a4 12 31 10 ...` where OpenSSL emits `a4 14 30 12 31 10 ...`.
- An `otherName` SubjectAltName now decodes with the type-id and value as the
  direct children of `[0]`, per RFC 5280 §4.2.1.6 (`otherName [0]` is IMPLICIT,
  so `[0]` replaces the SEQUENCE tag). The parser required an inner SEQUENCE, so
  any real `otherName` (an SRV-ID, a Microsoft UPN) failed the whole certificate
  parse; the SRV-ID encoder emitted the same non-conformant nesting. A
  structurally valid `otherName` with an unsupported type is preserved as
  `{ type: 'unknown' }`, but a malformed `otherName` envelope or a malformed
  value of a recognised `id-on-dnsSRV` is rejected rather than erased to
  `unknown`. Path validation rejects a critical `subjectAltName` carrying a
  GeneralName the verifier cannot interpret (RFC 5280 §4.2), while a
  non-critical one keeps the unknown entry.
  (https://github.com/kjanat/micro509/pull/77)
- OCSP responses now encode `ResponderID` `byKey` as `[2]` EXPLICIT wrapping an
  OCTET STRING and every time field as GeneralizedTime, per RFC 6960 Appendix
  B.1. The `byKey` responder was written as `[2]` IMPLICIT over the raw hash and
  the times as UTCTime, so OpenSSL and Go's `crypto/ocsp` could not parse a
  response this library produced. The parser reads the EXPLICIT form and
  requires the `byKey` hash to be a 20-byte SHA-1 digest. Embedded certificates
  are wrapped in the `certs [0] EXPLICIT SEQUENCE OF Certificate` the field's
  syntax requires rather than concatenated, so a response with `includedCertificates`
  is parseable. An end-to-end differential test confirms OpenSSL accepts a
  micro509-produced response.
  (https://github.com/kjanat/micro509/pull/76)
- The certificate builder enforces the RFC 8410 §5 keyUsage rules for the four
  1.3.101 curves. A keyUsage extension on a certificate whose subject key names
  id-X25519 or id-X448 must set `keyAgreement`
  (`montgomery_key_usage_requires_key_agreement`); one whose subject key names
  id-Ed25519 or id-Ed448 must set `nonRepudiation` or `digitalSignature`, widened
  in a certification authority certificate to also accept `keyCertSign` or
  `cRLSign` (`edwards_key_usage_requires_signing_bit`). The X25519 and X448
  clause admits "one of the following MAY also be present: encipherOnly; or
  decipherOnly", so a keyUsage setting both is rejected
  (`montgomery_key_usage_forbids_both_cipher_bits`); the two Ed clauses say "one
  or both" and "one or more", and keep combining. All three codes join
  `ExtensionEncoderErrorCode`. The rules bind only a keyUsage that reaches the
  wire, and read the effective value across the typed field and a
  `customExtensions` entry carrying the keyUsage OID. `OIDS` gains `x25519`,
  `x448`, and `ed448` alongside the existing `ed25519`.
- PKCS#8 import requires the `privateKey` field of an id-X25519, id-X448,
  id-Ed25519, or id-Ed448 key to hold exactly one DER `CurvePrivateKey` OCTET
  STRING, per RFC 8410 §7. The field's content was passed to WebCrypto
  unexamined, so a BER long-form length (`04 81 20 …`) around an otherwise
  valid Ed25519 key imported.
- `publicKeyAlgorithmName` reports `X25519`, `X448`, and `Ed448` alongside the
  existing `Ed25519`, and `signatureAlgorithmName` reports `Ed448`, the
  human-readable names RFC 8410 §8 establishes. Every one of those OIDs was
  reported as `Unknown (1.3.101.…)`, including the subject key of the X25519
  certificate the RFC prints in §10.2. The names reach certificate, CSR, CRL,
  OCSP, and PKCS#7 parse output.
- CSR parsing rejects a `CertificationRequestInfo` that omits `attributes [0]`,
  per RFC 2986 §4.1, which lists it as a component without `OPTIONAL`. A
  three-field request parsed and came back with an empty `requestedExtensions`,
  so a truncated structure was indistinguishable from one requesting no
  extensions. RFC 7468 §7 requires the octets under the `CERTIFICATE REQUEST`
  label to be a `CertificationRequest` as described in RFC 2986.
- PKCS#7/CMS PEM parsing accepts the RFC 7468 §9 `CMS` label alongside `PKCS7`.
  `parsePkcs7SignedDataPem`, `parsePkcs7CertBagPem`, and `verifyPkcs7SignedData`
  read only `PKCS7` blocks, so the RFC 5652 ContentInfo that §9 armors was
  unreadable, including the RFC's own Figure 11.
- `createPkcs7SignedData` armors a version 3 SignedData under the `CMS` label.
  Version 3 (an `encapContentInfo` `eContentType` other than `id-data`, RFC 5652
  §5.1) is outside RFC 2315, whose SignedData version "shall be 1" (§9.1), and
  RFC 7468 §8 requires the octets under `PKCS7` to be an RFC 2315 ContentInfo. A
  version 1 SignedData and the degenerate certificate bag keep the `PKCS7` label.
- The certificate builder rejects a keyUsage that gives one 1.3.101 subject key
  both applications RFC 8410 §12 separates: "the same public key cannot be used
  for both ECDH and EdDSA". A certificate whose subject key names id-X25519 or
  id-X448 must not set `digitalSignature`, `nonRepudiation`, `keyCertSign`, or
  `cRLSign` (`montgomery_key_usage_forbids_signature_bit`); one whose subject key
  names id-Ed25519 or id-Ed448 must not set `keyAgreement`, `encipherOnly`, or
  `decipherOnly` (`edwards_key_usage_forbids_agreement_bit`). RFC 5280 §4.2.1.3
  defines the first four bits over a key used to verify signatures and
  `keyAgreement` over a key used for key agreement, and leaves `encipherOnly` and
  `decipherOnly` undefined without it. Both codes join
  `ExtensionEncoderErrorCode`.
- The certificate builder rejects a `serialNumber` RFC 5280 §4.1.2.2 forbids a CA
  to issue: a zero value ("the serial number MUST be a positive integer",
  `serial_number_not_positive`) and one whose DER INTEGER runs past 20 octets
  ("Conforming CAs MUST NOT use serialNumber values longer than 20 octets",
  `serial_number_too_long`, counting the leading zero octet a high bit forces).
  The bytes were encoded unexamined, so `new Uint8Array(21)` or an empty array
  produced a certificate no conforming CA may issue. Both codes join
  `CreateCertificateErrorCode`.
- The CRL builder rejects an empty issuer distinguished name
  (`issuer_distinguished_name_empty`, joining `CrlEncoderErrorCode`). RFC 5280
  §5.1.2.3 requires the issuer field to contain a non-empty X.500 distinguished
  name, and RFC 7468 §6 requires the octets under the `X509 CRL` label to be a
  `CertificateList` as described in RFC 5280 §5. `createCertificateRevocationList`
  encoded an empty `SEQUENCE` for `issuer: {}`, naming an entity no certificate
  can identify. The certificate builder already enforced the same rule from
  RFC 5280 §4.1.2.4.
- Parsing checks the ASN.1 tag of an `AlgorithmIdentifier`, of a `Name` and its
  `RelativeDistinguishedName` and `AttributeTypeAndValue` components, and of a
  PKCS#10 attribute and its `type` and `values` fields. RFC 7468 §7 requires the
  octets under the `CERTIFICATE REQUEST` label to be a `CertificationRequest` as
  described in RFC 2986, whose §4.1 and §4.2 give each of those fields a type.
  A CSR could carry its subject as a `SET`, its signature algorithm as a `SET`,
  or an attribute whose `type` was an OCTET STRING holding the extensionRequest
  OID's content octets, and parse; the last one had its extensions decoded as if
  the type had been an OBJECT IDENTIFIER. An attribute `values` field is now also
  required to be a non-empty `SET`, per the `SET SIZE(1..MAX)` in RFC 2986 §4.1.
  The `AlgorithmIdentifier` and `Name` checks apply to certificate, CRL, and OCSP
  parsing as well.
- PKCS#7/CMS parsing rejects a SignedData whose `EXPLICIT [0]` content tag holds
  more than one value, and one whose signed `contentInfo` is not the two-field
  `SEQUENCE` of RFC 2315 §7 with an OBJECT IDENTIFIER `contentType`. RFC 7468 §8
  requires the octets under `PKCS7` to be an RFC 2315 ContentInfo, whose `content`
  is `[0] EXPLICIT ANY DEFINED BY contentType OPTIONAL`. A value appended inside
  the `eContent` tag was ignored and `verifyPkcs7SignedData` still returned `ok`,
  because RFC 2315 §9.3 digests only the contents octets of the first value, so
  two encodings verified under one signature; a `contentType` carrying another
  tag was decoded as if it were an OBJECT IDENTIFIER, yielding a fabricated OID.
- `createPkcs7SignedData` and `createOcspResponse` reject a signer certificate
  whose subject public key cannot verify the algorithm the signer private key
  produces. RFC 8410 §12: "the same public key cannot be used for both ECDH and
  EdDSA", and both builders accepted an id-X25519 certificate beside an Ed25519
  key, emitting a SignerInfo or a BasicOCSPResponse that named id-Ed25519 over a
  certificate that can never verify it. `CreatePkcs7SignedDataErrorCode` gains
  `signer_certificate_key_mismatch`; `createOcspResponse` throws a `ResultError`
  carrying the same code, from the new `OcspEncoderErrorCode`.
- Base64 decoding rejects a final quantum that is not the RFC 4648 §4 encoding
  of its own octets. RFC 7468 §2 takes the encapsulated data as base64 "according
  to Section 4 of [RFC4648]", which completes a short final quantum with pad
  characters and "bits with value zero", and §14 names data encoding ambiguity as
  an opportunity for side channels. `atob` ignores the pad bits and the padding
  alike, so four texts decoded to a one-pad structure and sixteen to a two-pad
  one: Figure 6 of RFC 7468 parsed to the same certificate from a body ending
  `Ipo=`, `Ipp=`, `Ipq=`, or `Ipr=`,
  and an unpadded `AQ` decoded as `AQ==` does. `pemDecode`, `splitPemBlocks`,
  every PEM parser above them, `importSpkiBase64`, `importPkcs8Base64`, and
  legacy encrypted PEM now reject both.

### Security

- `verifyCertificateChain` reported `ok: true` for a chain containing a
  certificate whose `id-ecPublicKey` public key carries no namedCurve OID,
  which RFC 5480 §2.1.1 requires clients to reject. The caller received a
  "verified" certificate binding a key `certificatePublicKey` cannot import.
  Chain validation now fails such a path with `ec_domain_parameters_missing`
  (joining `VERIFY_ERROR_CODES`); absent parameters, an `implicitCurve` NULL,
  and a `specifiedCurve` SEQUENCE all fail it.
- Parsing rejects a zero-length `dNSName`, `rfc822Name`, or
  `uniformResourceIdentifier` GeneralName, which RFC 5280 §4.2.1.6 forbids. An
  external certificate could previously carry an empty subjectAltName value and
  parse, leaving chain verification to accept a certificate with no usable
  identity when no identity match was requested. Certificate and CRL parsing
  share the decoder, so this covers subjectAltName, issuerAltName,
  authorityInfoAccess locations, CRL distribution points, `cRLIssuer`, the
  issuing distribution point, and `certificateIssuer`. Name constraints keep
  their own decoder, where an empty base is meaningful.
  (https://github.com/kjanat/micro509/pull/88)
- CRL parsing rejects a `CertificateList` whose `signatureAlgorithm` differs
  from the `signature` field of the signed `tbsCertList`, per RFC 5280 §5.1.1.2.
  The outer field is outside the signature, and it was the one reported as the
  CRL's signature algorithm, so a CRL could name one algorithm to the caller and
  another to the signer. Certificate parsing already enforced the same rule from
  RFC 5280 §4.1.1.2.

## [0.13.0] - 2026-07-23

A public `micro509/der` entrypoint, and RFC-conformance fixes across path
validation: name constraints, issuer chaining, CRL issuer paths,
distinguished-name comparison, and policy node sets.

### Added

- `micro509/der` exposes the DER reader, writer, and value decoders that back
  every built-in parser. `defineExtensionDecoder` hands a consumer `valueDer` and
  expects raw DER back from `encode`, and nothing in the public API could read or
  write those bytes, so a custom extension needed a second ASN.1 library.
  Readers and decoders take untrusted bytes and come in pairs: `decodeDerInteger`
  returns a `Result`, `decodeDerIntegerOrThrow` throws. Writers take typed input
  and throw, matching `encodeName` and `pemEncode`.
  (https://github.com/kjanat/micro509/issues/63)
- `bmpString` and `universalString` encode the two string types that already
  decoded, so a PKCS#12 `friendlyName` can now be written as well as read. Both
  reject lone surrogates, and `bmpString` rejects code points above U+FFFF.
- `decodeBitString` returns a BIT STRING's payload with its unused-bit count.
  `extractBitStringValue` rejects a non-zero count, which excluded KeyUsage, the
  most common BIT STRING in a certificate. Unused trailing bits are returned as
  encoded, matching how the extension decoders already treat non-conformant
  certificates.

### Changed

- `decodeIntegerNumber` accepts a non-negative, minimally encoded INTEGER up to
  `Number.MAX_SAFE_INTEGER` and rejects above it. Negative and non-minimal
  encodings are still rejected, as before. It stopped at 6 bytes while
  `integerFromNumber` encoded any non-negative safe integer, so values from 2^47
  up encoded and would not decode.
  The old limit cited 48 bits as the safe-integer boundary; that boundary is 53.
  A 7- or 8-byte INTEGER inside a certificate that previously threw now parses.

### Security

- Name constraints reject a URI SAN whose authority has no FQDN host (an IP
  literal, a single-label host such as `localhost`, or no authority at all)
  when a uniformResourceIdentifier constraint applies, per RFC 5280 §4.2.1.10.
  Such a URI previously slipped past the
  constraint. Email constraint matching now compares the local part
  case-sensitively and only the host case-insensitively (RFC 5280 §7.5, as
  replaced by RFC 9549 §7.5.1), so `admin@example.com` no longer matches
  `ADMIN@example.com` and widens the permitted subtrees.
  (https://github.com/kjanat/micro509/pull/71)
- `validateCandidatePath` compares each certificate's issuer DN against the
  candidate issuer's subject DN, per RFC 5280 §6.1.3(a)(4). It verified only the
  signature, so a leaf whose issuer DN was unrelated to the signing CA validated
  as ok on the pre-built-path API. `buildChainInternal` already compared them,
  so `verifyCertificateChain` was unaffected.
  (https://github.com/kjanat/micro509/pull/72)
- CRL evidence validates the CRL issuer's own certification path to the trust
  anchor before trusting its verdict (RFC 5280 §6.3.3(f)). A forged
  indirect-CRL signer whose subject DN collided with a chain certificate was
  accepted on a name match, its signature never checked against a trusted key,
  so a forged empty CRL reported a revoked certificate as `good`. Each
  candidate CRL issuer runs the full pipeline as one step (signature, then
  §6.3.3(f) path, then signer revocation), so an unusable candidate no longer
  shadows a later authorized one, and the signer's path is validated against a
  pool that includes the validated chain intermediates, so a delegated signer
  issued by a chain CA authorizes. Without these, a genuine revoked CRL became
  `crl_signer_not_authorized` and soft-fail allowed the revoked certificate.
  (https://github.com/kjanat/micro509/pull/73)
- Distinguished name comparison implements the RFC 4518 string-preparation
  profile that RFC 5280 §7.1 requires, against the frozen Unicode 3.2 repertoire
  RFC 4518 §2.1 fixes: the Map, Normalize, Prohibit, and Insignificant Space
  steps with the complete RFC 3454 Appendix B.2 case fold and Table A.1
  unassigned set. The old NFKC-plus-lowercase shortcut left ignorable code
  points in place (so an excluded subtree failed to exclude a name carrying a
  SOFT HYPHEN), folded with `toLowerCase` alone (so `Straße` did not equal
  `STRASSE`), and delegated the repertoire to the running Unicode version. That
  last part let a code point unassigned in 3.2 slip through: U+1D2C normalized
  to `a` and matched `CN=a`, U+2F868 used the Unicode 4.0 NFKC correction, and
  U+10A0 took a post-3.2 fold. The A.1 unassigned set, the B.2 fold, and the
  five CJK NFKC corrections are generated from the vendored RFC 3454 and guarded
  by a test that re-derives them from the RFC text. BMPString and UniversalString
  values are prepared alongside UTF8String and PrintableString. `domainComponent`
  compares as `caseIgnoreIA5Match` (RFC 4519), requiring the IA5String tag and
  ASCII, so a UTF8String or non-ASCII value no longer matches an IA5String one;
  `DC=Example` chains to `DC=example`. Bare-anchor selection confirms the
  anchor's subject equals the certificate's issuer rather than trusting the
  canonical-key bucket. RFC 4518 and RFC 3454 are vendored under `docs/rfc/`.
  (https://github.com/kjanat/micro509/pull/74)
- Certificate policy validation computes the RFC 9618 §5.5(g)
  `valid_policy_node_set` correctly: the nodes at any depth whose valid_policy
  is not anyPolicy and whose single parent is an anyPolicy node, plus a depth-n
  anyPolicy node. It previously took depth-n nodes tracing back to the depth-0
  anyPolicy root, which diverges under policy mapping. A CA that mapped
  `1.2.3.4` to `1.2.3.5` reported `authorityConstrainedPolicies` of `1.2.3.5`
  where the spec requires `1.2.3.4` (NIST PKITS 4.10.1), so a chain validated
  against the mapped policy instead of the authority's. `userConstrainedPolicies`
  now follows §5.5(g)(5)-(6) from the corrected set. Policy validation also
  processes the terminal certificate when a bare trust anchor is used: a path
  built to an out-of-band anchor ends at a real CA, and skipping it let a leaf
  policy satisfy `initialPolicySet` even when that CA omitted or contradicted
  the policy. `authorityConstrainedPolicies` now aggregates each policy's
  qualifiers from its node, ancestors, and descendants per §5.5(g)(4)(ii)
  rather than reporting one arbitrary node's set.
  (https://github.com/kjanat/micro509/pull/75)

## [0.12.0] - 2026-07-21

Text rendering for subject alternative names and distinguished names, and
runnable docs examples that survive client-side navigation.

### Added

- `subjectAltNameToString(name, options?)` renders one `SubjectAltName` as text.
  Printing a SAN is the most ordinary thing to do with one after parsing, and it
  took a hand-written narrowing in every consumer: `dns`/`ip`/`email`/`uri`/`srv`
  carry a `string` value, `directoryName` carries only `derHex` and has no `value`
  at all, and `unknown` carries a `Uint8Array` that stringifies itself as
  `192,0,2,1` inside a `join()`. A `directoryName` now renders as an RFC 4514
  distinguished name (`CN=Example CA,O=Acme\, Inc.,C=US`), falling back to its hex
  when the DER does not decode, and an `unknown` renders as hex. Pass
  `{ prefix: true }` for the `openssl x509 -text` labels (`DNS:`, `IP Address:`,
  `DirName:`), or call `subjectAltNameLabel(name)` for the label alone. Companion
  `distinguishedNameToString(name)` and `relativeDistinguishedNameToString(rdn)`
  render a parsed subject or issuer, which until now had no public renderer either.
  Exported from the root and `micro509/x509`, with the `SubjectAltNameTextOptions`
  type. (https://github.com/kjanat/micro509/issues/50)

- The docs site serves a permalink for the newest release. `/v0.11.0/…` used to
  404 while 0.11.0 sat at the root, then silently come into existence as an
  archive one release later, so a link to the root changed meaning on every
  release. The build now emits a `_redirects` file sending `/v<latest>/*` to the
  root with a 302; once the next release takes the root, the rule disappears and
  the same URL serves the archived copy. Temporary on purpose: browsers cache a
  301 past the release that makes it wrong.

### Changed

- The X.509 reference now identifies every asynchronous operation in one place
  and explains the split: PEM/DER parsing and transformation are synchronous,
  while hashing, signing, and key operations backed by WebCrypto return promises.
  The API summaries for `parseCertificatePem` and `certificateFingerprint` make
  their return timing explicit, avoiding a no-op `await` on the parser or reading
  properties from an unawaited fingerprint promise.
  (https://github.com/kjanat/micro509/issues/51)
- The docs site no longer co-hosts the library: each version's runnable examples
  import it from a CDN, bound to the version that page documents. A release imports
  what it published, from jsDelivr, whose `+esm` builds arrive bundled — one request
  where esm.sh's module graph took thirty-nine, and a third of the time to load.
  `/next/` imports a pkg.pr.new build of the deployed commit, which only esm.sh can
  serve, bundled with `?standalone`. The co-hosted copy put the library's own file
  layout in the site's URL space, where `x509/fingerprint.js` matched an EasyPrivacy
  rule blocking that path on every domain (`/fingerprint.js^$domain=~github.com`).
  Content blockers refused it, and because it is a static import of the root entry,
  every example on the site died for readers running one.
- CI gates the docs site on its examples actually working: `run site:import-maps`
  checks every version's map names its own library and that every URL in it resolves,
  and `run site:live-examples` clicks Run in a real browser with a content blocker
  simulated — a headless browser has none, and would have passed while the bug above
  was live.
- Materializing an archived version's pages now repairs a runnable example the tag
  shipped with a syntax error, so its Run button executes valid code. Each `<LiveCode>`
  block is parsed, and one missing the brace that closes a block gets it restored at
  the position the TypeScript parser expects. Nine `guide/getting-started` examples
  across v0.3.0 through v0.9.0 were affected. The archived page then differs from the
  code that release published. (https://github.com/kjanat/micro509/issues/53)

### Fixed

- Runnable examples now execute the version of the page they run on after
  client-side navigation. Each page shipped its own `<script type="importmap">`,
  which the browser reads once per document, so navigating from the landing page
  to an archived version and pressing Run resolved `micro509` against the entry
  page's map and imported the wrong release; only a hard refresh picked up the
  right one. Every page now ships one identical map: top-level imports for the
  root version and a scope per version prefix. Scopes match the URL of the
  importing module, and the injected example module inherits the document URL,
  so resolution follows the page at run time with no map swapping. `run
site:import-maps` now verifies the map is identical on every page and each
  scope binds its own version, and `run site:live-examples` replays the failing
  flow: enter at the root, navigate client-side to an archive, run its example,
  and require every import to carry that archive's version.

## [0.11.0] - 2026-07-13

Certificate fingerprinting and private-key ownership checks for certificate
inspection, intake, and issuance workflows.

### Added

- `certificateFingerprint(certificate, algorithm?)` computes the standard
  certificate fingerprint — a hash over the DER encoding, the identifier
  `openssl x509 -fingerprint` and TLS UIs display. It accepts the same
  `string | Uint8Array | ParsedCertificate` source union as the verification
  APIs and returns `{ bytes, hex, colonHex }`: the raw digest, lowercase hex
  with no separators, and uppercase colon-separated hex (openssl style). It
  defaults to SHA-256; SHA-1/384/512 are also supported for legacy interop
  (older certificate pinning, PGP-adjacent tooling). Exported from the root and
  `micro509/x509` as `certificateFingerprint`, with `CertificateFingerprint`,
  `CertificateFingerprintAlgorithm`, and `CertificateFingerprintSource` types.
  Interop with `openssl x509 -fingerprint` verified across all four algorithms.
  (https://github.com/kjanat/micro509/issues/45)
- `certificateMatchesPrivateKey(certificate, privateKey)` checks whether an
  uploaded private key belongs to a certificate — the first thing any
  key-intake or issuance endpoint must do. It derives the public half of the
  private key, exports it as SubjectPublicKeyInfo DER, and byte-compares it
  against the certificate's own SPKI (the canonical, algorithm-agnostic
  ownership test), returning a plain `boolean`. `certificate` accepts a PEM
  string, DER bytes, or an already-parsed `ParsedCertificate`; a private key of
  a different type simply produces different SPKI and returns `false`.
  `matchCertificatePrivateKey` is the `Result`-returning companion: `ok: true`
  on a match, or a typed failure carrying `key_mismatch`, `key_type_mismatch`,
  `malformed_certificate`, or `unsupported_private_key` — so trust boundaries
  get the reason (and no thrown errors on untrusted input). The error-code
  union is exported as `MatchCertificatePrivateKeyErrorCode`.
  (https://github.com/kjanat/micro509/issues/46)

## [0.10.0] - 2026-07-13

Detached PKCS#7 / CMS signatures — the form git x509 commit signing and S/MIME
rely on — and algorithm inference across every private-key import family.

### Added

- `createPkcs7SignedData` accepts `detached: true` to omit `eContent` from
  `encapContentInfo` (RFC 5652 §5.2 detached form), and
  `verifyPkcs7SignedData` accepts an options bag with `content` to supply the
  externally-held bytes when verifying a detached signature — the shape git
  x509 commit signing (`gpg.format=x509`) and S/MIME detached signatures use.
  The error-code union is now exported as `VerifyPkcs7SignedDataErrorCode`, the
  options as `VerifyPkcs7SignedDataOptions`. Interop with `openssl cms`
  verified in both directions.
  (https://github.com/kjanat/micro509/issues/40)
- The private-key import families infer the algorithm from the container when
  the `algorithm` parameter is omitted, mirroring the existing SPKI behavior;
  passing it still asserts and fails typed on mismatch:
  - `importPkcs8Der/Pem/Base64(+OrThrow)` and
    `importEncryptedPkcs8Der/Pem(+OrThrow)` read the PKCS#8
    `privateKeyAlgorithm` (RSA defaults to `pkcs1-v1_5`/`SHA-256`, as with
    SPKI inference).
  - `importSec1Der/Pem(+OrThrow)` and `importEncryptedSec1Pem(+OrThrow)` read
    the RFC 5915 `parameters [0]` named curve; a SEC 1 key without one still
    requires the explicit curve.
  - `importPublicJwk`/`importPrivateJwk`(+`OrThrow`) read `kty`, `crv`, and
    `alg` (`RS*`/`PS*`/`RSA-OAEP-256/384/512` select the RSA scheme and hash).
    (https://github.com/kjanat/micro509/issues/41)

### Changed

- **BREAKING** — `verifyPkcs7SignedData` reports a SignedData that carries no
  `eContent` as `'detached_content_required'`; the `'content_missing'` code is
  gone. Such a message is not malformed, it is a detached signature awaiting
  its external content, and it is now only a failure when no `content` option
  is supplied. Rename any match on `'content_missing'`; matches against the
  exported `VerifyPkcs7SignedDataErrorCode` union fail to typecheck until you
  do.
- `exportSec1Der`/`exportSec1Pem`/`exportEncryptedSec1Pem` always embed the
  RFC 5915 `parameters [0]` named curve (WebCrypto's inner ECPrivateKey omits
  it; OpenSSL writes it), so exported SEC 1 keys are self-describing and
  re-import without an explicit curve.
- Preserve public API behavior while decomposing DER, parsing, verification,
  revocation, PKCS#7, and API-documentation flows into focused helpers that
  satisfy the stricter cognitive-complexity limit. (https://github.com/kjanat/micro509/pull/39)

### Fixed

- `createPkcs7SignedData` returns the typed `'invalid_signer_certificate'` /
  `'invalid_certificate'` (new code) failures for malformed signer and
  additional-certificate inputs instead of rejecting the promise. Each
  `additionalCertificates` value is structurally validated as a real X.509
  certificate, so malformed DER also returns `'invalid_certificate'`.

## [0.9.0] - 2026-07-06

RSA-OAEP encryption support across the whole key lifecycle: generate, import,
derive, encrypt, decrypt.

### Added

- `RsaScheme` accepts `'oaep'`: `generateKeyPair`, the SPKI / PKCS#8 / JWK
  import functions, and `derivePublicKey` produce `RSA-OAEP` keys with
  `encrypt`/`decrypt` usages when the scheme is `'oaep'` (signature schemes
  keep `sign`/`verify`).
  (https://github.com/kjanat/micro509/pull/36)
- `encryptRsaOaep` / `decryptRsaOaep` (and their `…OrThrow` siblings) encrypt
  and decrypt small messages with an RSA-OAEP key pair, with an optional OAEP
  `label` bound to the ciphertext. Failures are typed:
  `'invalid_key' | 'message_too_long'` on encrypt,
  `'invalid_key' | 'decryption_failed'` on decrypt — ciphertext-level
  decryption failures are deliberately opaque (no padding-oracle detail).
- `RsaSignatureScheme` narrows `RsaScheme` to the signature schemes
  (`'pkcs1-v1_5' | 'pss'`), so certificate signature verification can never
  silently accept an OAEP key.

## [0.8.0] - 2026-07-05

Key/certificate import ergonomics and validation hardening — every API
finding from the OpenSSL differential fuzzer, shipped in one release.

### Added

- The `keys` and `x509` domain barrels (and the root barrel) re-export the 20
  `OrThrow` siblings that were implemented and documented but unreachable from
  the published package — 16 key-import variants (`importSpkiDerOrThrow`,
  `importPkcs8PemOrThrow`, …) and 4 certificate/CSR parsers
  (`parseCertificateDerOrThrow`, …). A conventions test now fails whenever a
  barrel exposes a function while omitting its `OrThrow` sibling.
  (https://github.com/kjanat/micro509/issues/26)
- `derivePublicKey(privateKey)` derives the matching public `CryptoKey` from
  an imported (or generated) private key, so a private key loaded via
  `importPkcs8*`/`importPkcs1*`/`importSec1*`/`importPrivateJwk` can go
  straight to `exportSpkiDer`/`exportSpkiPem` without hand-rolling JWK
  surgery. Supports RSA, ECDSA, and Ed25519.
  (https://github.com/kjanat/micro509/issues/19)
- `importSpkiDer`, `importSpkiPem`, `importSpkiBase64` (and their `…OrThrow`
  variants) now accept an optional algorithm argument. A SubjectPublicKeyInfo
  already encodes its algorithm OID — and the EC curve OID — so when no hint is
  given the algorithm is inferred straight from the DER, letting callers import
  keys whose type isn't known ahead of time. Passing an explicit algorithm is
  unchanged and still asserts the key matches it.
  (https://github.com/kjanat/micro509/issues/20)
- `getSubjectPublicKey(parsed)` / `getSubjectPublicKeyOrThrow(parsed)` import
  the subject public key of a parsed certificate or CSR as a WebCrypto
  `CryptoKey`, inferring the algorithm (and EC curve) from the embedded
  SubjectPublicKeyInfo — callers no longer hand-roll the
  `publicKeyAlgorithmOid` → import-algorithm mapping.
  (https://github.com/kjanat/micro509/issues/21)

### Fixed

- `importPrivateJwk` / `importPrivateJwkOrThrow` now validate the JWK against
  the requested algorithm before handing it to WebCrypto, matching what
  `importPublicJwk` already did: `kty`/`crv` must match the requested
  `kind`/`curve`, the private material the kind implies must be present
  (`d` everywhere, plus `n`/`e`/`p`/`q`/`dp`/`dq`/`qi` for RSA), and
  symmetric (`k`) or multi-prime (`oth`) material is rejected.
  Wrong-algorithm and public-only JWKs previously surfaced as opaque
  WebCrypto errors instead of the library's `'malformed'` failures.
  (https://github.com/kjanat/micro509/issues/23)
- `importSec1Der` / `importSec1Pem` / `importEncryptedSec1Pem` (and their
  `…OrThrow` variants) trusted the caller's `curve` without reading the SEC 1
  ECPrivateKey itself. The RFC 5915 `parameters [0]` field (OpenSSL always
  writes it) is now parsed and cross-checked: a curve mismatch fails with
  `SEC 1 private key curve does not match requested import algorithm`, and
  bytes that are not an ECPrivateKey fail with `Malformed SEC 1 private key` —
  instead of both surfacing as WebCrypto's opaque "Malformed PKCS#8" error.
  Keys without the optional parameters field import as before.
  (https://github.com/kjanat/micro509/issues/22)

## [0.7.2] - 2026-07-04

Error-classification fix for encrypted-key imports with a wrong password.

### Fixed

- `importEncryptedPkcs8Der` / `importEncryptedPkcs8Pem` reported
  `'malformed'` instead of `'invalid_password'` roughly once per 256
  wrong-password attempts: AES-CBC padding is unauthenticated, so a wrong
  key occasionally "decrypts" to random bytes that pass the padding check,
  and the resulting PKCS#8 parse failure was misclassified. Decrypted
  plaintext that is not a PrivateKeyInfo now reports `'invalid_password'`.
- `parsePfx` had the same wrong-password tail (reporting `'malformed'`),
  plus the reverse: structurally malformed EncryptedData could report
  `'invalid_password'`. Classification now keys on the decryption failure
  itself instead of error-message prefixes.

## [0.7.1] - 2026-07-04

ECDSA signature-encoding bug fix — re-issue any ECDSA-signed artifacts
that fail external verification.

### Fixed

- ECDSA signing embedded an invalid signature roughly once per 256
  signatures: WebCrypto's raw `r || s` output was detected by sniffing the
  first byte for the DER SEQUENCE tag, so a raw signature whose `r` began
  with `0x30` was emitted unconverted. OpenSSL rejects such certificates
  and CRLs with a signature failure (micro509's own verifier masked the
  bug by making the mirror-image guess). Detection is now by exact raw
  length. Affects all ECDSA-signed artifacts from previous releases —
  re-issue anything that fails external verification.

## [0.7.0] - 2026-07-04

Pre-1.0 API freeze cleanup: one coherent breaking pass over vocabulary,
error-handling doctrine, type shapes, and export surface, so 1.0 can freeze
a surface with no known regrets. Every rename is in the migration table
below.

### Added

- Runtime code arrays `REVOCATION_INDETERMINATE_REASON_CODES` and
  `REVOCATION_INDETERMINATE_REASONS` (the `VERIFY_ERROR_CODES` pattern);
  their unions now derive from the arrays.
- The root entry point exports every type reachable from public signatures
  that were previously subpath-only (MacData, policy-validation outcome,
  identity failure details, revocation error codes/failure payloads, and
  the new `Parse*Result` / `Pem*Result` types).
- `Pkcs7CertificateSource` and `PfxCertificateSource` accept an
  already-parsed `ParsedCertificate` (parity with the revocation source
  unions).
- Documented error-code stability policy: unions may gain members in
  minor releases — treat them as non-exhaustive.
- CI now smoke-tests the two previously untested runtime claims: Cloudflare
  Workers (real workerd via wrangler's test harness) and browsers (headless
  Chromium via Playwright, loading the built `dist/` output). All five
  supported runtimes are now exercised in CI.

### Changed

Every entry in this section is **BREAKING**; the migration table at the end
maps each old name to its replacement.

- **Revocation defaults to hard-fail once enabled.** Revocation checking
  remains opt-in (no evidence supplied ⇒ no check), but once `revocation`
  is passed, `policy.mode` now defaults to `'hard-fail'`: indeterminate
  status **denies**. Opt back into the old behavior explicitly with
  `policy: { mode: 'soft-fail' }`. Mental model: no revocation input → no
  check; revocation input → revocation matters.

- **Vocabulary unified.** The CRL/OCSP discriminant is `kind` everywhere
  (was a `kind`/`source`/`type` mix); the verifier-level can't-tell status
  is `'indeterminate'` everywhere (was `'unknown'` in standalone checks vs
  `'indeterminate'` in chain checks). Protocol-level reason codes that
  quote RFC 6960's `unknown` certificate status keep the word
  (`ocsp_status_unknown`, `certificate_status_unknown`,
  `responder_revocation_unknown`), as does `OcspCertStatus`.

- **Result doctrine completed.** The last public parsers consuming
  untrusted input that still threw now return a typed `Result`
  (`code: 'malformed'`): CRL, OCSP request/response, PKCS#12 MacData, and
  the PEM primitives. Each has an `*OrThrow` twin (same convention as the
  x509 parsers since 0.3.0).

- **Illegal states made unrepresentable.** `ParsedPkcs7SignerInfo`
  discriminates on `hasSignedAttrs` (when `true`, `signedAttrsDer` is
  guaranteed); `CertificateRevocationStatus` is a discriminated union
  (good/revoked always carry `source`, revoked always carries `revocationInfo`,
  indeterminate always carries `indeterminateReasons`); `BasicConstraints` rejects
  `{ ca: false, pathLength }` at compile time; `ParsedPkcs12MacData.valid`
  (optional boolean tri-state) became
  `verification: 'valid' | 'invalid' | 'unchecked'`; `ParsedName.values`
  is a readonly map; `ValidateCandidatePathResult` lost its duplicate
  top-level `policyValidation`.

- **pkcs7 creators match the rest of the library.** `createPkcs7CertBag`
  and `createPkcs7SignedData` return a `Result` whose value is
  `{ der, pem, base64 }` material like every other creator (check `.ok`,
  then read `.value`); the `Der`/`Pem` variants are gone.

- **Signature-only verifiers say so.** `verifyOcspResponseSignature` /
  `verifyCertificateRevocationListSignature` check the signature only —
  the bare `verify*` names read as full validation, which is
  `validateOcspResponse` / `validateCertificateRevocationList`.
  (`verifyCertificateSigningRequest` and `verifyPkcs7SignedData` keep
  their names: each is the complete operation for its object.)

- **Export surface curated.** `micro509/revocation` and `micro509/verify`
  list every export explicitly (no `export type *`); dead aliases removed
  (`MatchableServiceIdentityInput`, `VerifyServiceIdentityInput`,
  `MatchServiceIdentityEvaluation` — use `ServiceIdentityInput`);
  `rethrowIfInvariant` (internal control flow) left `micro509/result`;
  `Pbes2EncryptionOptions`/`Pbes2EncryptionScheme`/`Pbes2Prf` left the
  public barrels (`EncryptedPkcs8Options` and `PfxEncryptionOptions` are
  the canonical names); the duplicate `CertificateSource` alias on the
  revocation subpath (which collided with the root-exported verify type
  under a different shape) is gone — chain inputs use
  `RevocationCertificateSource`. `IssuingDistributionPoint*` types moved
  from the x509 surface to `micro509/revocation` (they are CRL types; the
  root still exports them).

#### Migration table

| 0.6.0                                                          | 0.7.0                                                      |
| -------------------------------------------------------------- | ---------------------------------------------------------- |
| `RevocationStatus` `'unknown'`                                 | `'indeterminate'`                                          |
| `RevocationCheckUnknownValue`                                  | `RevocationCheckIndeterminateValue`                        |
| `revocation_status_unknown`                                    | `revocation_status_indeterminate`                          |
| `RevocationSource.type`                                        | `RevocationSource.kind`                                    |
| `RevocationCheck{Good,Revoked}Value.source`                    | `.kind`                                                    |
| `RevocationIndeterminateEvidence.source`                       | `.kind`                                                    |
| `revocationInfo.date`                                          | `revocationInfo.revocationDate`                            |
| `policy.mode` default `'soft-fail'`                            | `'hard-fail'`                                              |
| `verifyOcspResponse`                                           | `verifyOcspResponseSignature`                              |
| `verifyCertificateRevocationList`                              | `verifyCertificateRevocationListSignature`                 |
| `parseCertificateRevocationList{Der,Pem}` (throwing)           | Result-returning; `*OrThrow` for the old behavior          |
| `parseOcsp{Request,Response}{Der,Pem}` (throwing)              | Result-returning; `*OrThrow` for the old behavior          |
| `parsePkcs12MacData` (throwing)                                | Result-returning; `parsePkcs12MacDataOrThrow`              |
| `pemDecode` / `splitPemBlocks` / `categorizePemBlocks`         | Result-returning; `*OrThrow` for the old behavior          |
| `ParsedPkcs12MacData.valid?: boolean`                          | `verification: 'valid' \| 'invalid' \| 'unchecked'`        |
| `createPkcs7CertBag{Der,Pem}`                                  | `createPkcs7CertBag` (Result of `{ der, pem, base64 }`)    |
| `createPkcs7SignedData{Der,Pem}`                               | `createPkcs7SignedData` (Result of `{ der, pem, base64 }`) |
| `Pkcs7CertBag`                                                 | `Pkcs7CertBagMaterial`                                     |
| `Import{Rsa,Ec,Ed25519}PublicKeyInput`                         | `Import{Rsa,Ec,Ed25519}KeyInput`                           |
| PBES2 option `encryption: 'aes256-cbc'`                        | `cipher: 'AES-256-CBC'`                                    |
| PBES2 option `prf: 'hmac-sha256'`                              | `prf: 'HMAC-SHA-256'`                                      |
| `trustedResponderCertificates` (validateOcspResponse)          | `trustedOcspResponders`                                    |
| `delta_crl_unsupported` / `indirect_crl_unsupported`           | `unsupported_delta_crl` / `unsupported_indirect_crl`       |
| `service_identity_type_unsupported`                            | `unsupported_service_identity_type`                        |
| `service_identity_service_mismatch`                            | `service_identity_mismatch`                                |
| `VerifyServiceIdentityInput` / `MatchableServiceIdentityInput` | `ServiceIdentityInput`                                     |
| `VerifyOcspResponse{Result,Failure}`                           | `VerifyOcspResponseSignature{Result,Failure}`              |
| `VerifyCertificateRevocationList{Result,Failure}`              | `VerifyCertificateRevocationListSignature{Result,Failure}` |

### Fixed

- Manual `npm publish` outside the release workflow now fails via a
  `prepublishOnly` guard: only the workflow rewrites the dev-only
  `bun → ./src/*.ts` export conditions, so a raw publish would ship an
  exports map pointing at files missing from the dist-only tarball.

## [0.6.0] - 2026-07-04

Full standards surface claimed complete: all four RFC status rows — 5280,
6960, 6125, 9618 — now read `complete`, backed by the full NIST PKITS
suite and RFC-exact name-constraint handling.

The PKITS sweep behind that claim runs the full NIST suite — all 224 test
procedures across sections 4.1–4.16, expanded to 249 runs including every
documented subtest variation — with every manifest expectation verified
against the official PKITS document, now vendored as `docs/rfc/pkits.txt`.
4.1.4/4.1.5 (DSA chains) are expected-fail per the WebCrypto algorithm
boundary.

### Changed

- Name constraints now fail closed for unsupported GeneralName forms per
  RFC 5280 §4.2.1.10. A critical `nameConstraints` extension imposing
  `otherName`, `x400Address`, `ediPartyName`, or `registeredID`
  constraints rejects a subsequent certificate **only when a SAN of that
  form actually appears** (`unsupported_name_constraints`); previously any
  such chain was rejected outright, even when the constrained form never
  occurred. SRV-ID and unknown-tag SANs now participate in that fail-closed
  check — they were previously skipped. Unsupported forms in non-critical
  extensions are ignored, and supported forms in the same extension are
  still enforced.

## [0.5.0] - 2026-07-03

OCSP responder authorization, URI/SRV service identities, and a
`best-available` revocation preference that actually compares evidence
freshness.

### Added

- URI-ID and SRV-ID service identities are now accepted by the verification
  helpers: `VerifyServiceIdentityInput` widened to the full
  `ServiceIdentityInput` union, so
  `verifyCertificateChain({ serviceIdentity })` and `validateForTlsServer`
  match `{ type: 'uri' | 'srv' }` alongside DNS/IP. An SRV service-label
  mismatch surfaces as `subject_alt_name_mismatch` with the matcher's
  details.

- OCSP responder authorization completed (RFC 6960 §4.2.2.2):
  - `trustedResponderCertificates` on `validateOcspResponse()` and
    `trustedOcspResponders` on `checkChainRevocation()` /
    `verifyCertificateChain({ revocation })` — criterion-1 local responder
    configuration; a matching signer skips delegated issuance/EKU checks and
    is consulted during responder discovery.
  - Delegated responder revocation policy (§4.2.2.2.1):
    `responderRevocationPolicy` = `'honor-nocheck'` (default) /
    `'require-evidence'` / `'skip'` with `responderRevocationCrls` as
    evidence; chain orchestration reuses its CRLs automatically. New
    failure codes `responder_revoked` and `responder_revocation_unknown`.
  - `hasOcspNoCheckExtension()` — parses `id-pkix-ocsp-nocheck`.
  - Delegated responder chains now validate at the caller-supplied `at`
    (historical-time validation) instead of always at the current time.

### Changed

- `policy.prefer: 'best-available'` (the default) now genuinely picks the
  freshest evidence: when CRL and OCSP both yield a validated `good`
  verdict, the source with the later `thisUpdate` is reported (an applied
  delta CRL counts as its own `thisUpdate`; ties favor OCSP). Previously
  `'best-available'` behaved identically to `'ocsp'`. Fail-closed
  combination is unchanged — a validated `revoked` verdict from either
  source still always wins.

- `RevocationSource` gained `thisUpdate` — the timestamp of the evidence
  backing the verdict (OCSP single-response entry or freshest contributing
  CRL), i.e. the value `'best-available'` compares. `signerCertificate` for
  a multi-CRL `good` verdict is now the freshest contributing CRL's signer
  rather than the last one processed, so it always matches the reported
  freshness.

## [0.4.0] - 2026-07-03

OCSP joins chain-level revocation, and the npm package no longer ships
broken Bun export conditions.

### Added

- OCSP evidence is now consumed by chain-level revocation:
  `checkChainRevocation()` (and `verifyCertificateChain({ revocation })`)
  validates caller-supplied `ocspResponses` — signature, responder binding
  and authorization, freshness — and combines them with CRL evidence. A
  validated `revoked` verdict from either source always denies, regardless
  of `policy.prefer` (fail-closed). Delegated responder certificates can be
  supplied via `extraCertificates`.
- `VERIFY_ERROR_CODES`: runtime array of every `VerifyErrorCode`, exported
  from the root and `micro509/verify`. The docs error-code table is now
  test-enforced against it.
- CI now builds, validates the npm tarball against the published exports
  map, and smoke-tests the dist output under Node and Deno.

### Changed

- **BREAKING** — `VerifyErrorCode`: renamed
  `initial_name_constraints_not_implemented` →
  `unsupported_initial_name_constraints` (it reports unsupported/malformed
  initial-name-constraint forms, not a missing feature). Removed
  `policy_processing_not_implemented`, which no code path emitted.

### Fixed

- npm packaging: the published `exports` map retained the dev-only
  `bun → ./src/*.ts` conditions while the tarball ships only `dist/`,
  breaking Bun consumers installing from npm (`npm publish` does not apply
  `publishConfig.exports`). The publish workflow now rewrites `exports`
  from `publishConfig.exports` before publishing, and CI fails if any
  published export target is missing from the tarball.

## [0.3.0] - 2026-07-02

Typed-error rework: trust-boundary functions (which consume untrusted
external input) now return a `Result` as the strict, correct default,
with an explicit `unwrap()` escape hatch. Typed-config constructors keep
throwing (a bad config is a programmer error, not a runtime condition).

### Added

- `unwrap(result)` / `unwrapOr(result, fallback)` (root + `micro509/result`):
  the explicit escape hatch for callers who have already validated input or
  prefer exceptions. `unwrap` throws a branded plain error carrying the
  structured `code`; `ResultError` is exported as its type and
  `isResultError(error)` is the guard. There is no class to `instanceof` —
  the library ships no classes.
- `failureResult(code, message, details?)` factory in `micro509/result`:
  one source of truth for the `{ ok, error, code, message }` shape.
- `rethrowIfInvariant(error)` in `micro509/result`: the guard the parse
  wrappers use to keep programmer errors out of `Result` failures (removed
  from the public barrel in 0.7.0).

### Changed

- **BREAKING** — `parseCertificateDer`, `parseCertificatePem`,
  `parseCertificateSigningRequestDer`, `parseCertificateSigningRequestPem`
  now return a `Result` (`{ ok, value }` / `{ ok, error: { code:
'malformed' } }`) instead of throwing. Wrap with `unwrap(...)` for the
  previous throw-on-error behavior.
- **BREAKING** — All 16 key `import*` functions now return a `Result` instead
  of throwing. Non-encrypted failures use code `'malformed'`; encrypted
  imports distinguish a typed `'invalid_password'` from `'malformed'`.
  `export*` and `generateKeyPair` are unchanged (no untrusted input).
- **BREAKING** — `createPfx`, `createPkcs7CertBagDer`, and
  `createPkcs7CertBagPem` now return a `Result` (code
  `'invalid_certificate'`) instead of throwing on a malformed certificate
  source — matching `createPkcs7SignedData`. Pure typed-config constructors
  (`createCertificate`, `createSelfSignedCertificate`,
  `createCertificateRevocationList`, …) still throw: a bad config is a
  programmer error, not a runtime result.
- Canonical docs site is now `micro509.kjanat.dev` (was `micro509.kjanat.com`,
  which stays live as a mirror). `homepage` and all documentation links point at
  the `.dev` domain.
- GitHub repository renamed `kjanat/ts-x509` → `kjanat/micro509` to match the
  published package name. `repository.url` updated; old URLs redirect.

### Fixed

- The new parse `Result` wrappers rethrow a `TypeError`, `RangeError`,
  `ReferenceError`, or `SyntaxError` raised inside a parser instead of
  reporting it as a `'malformed'` failure, so a genuine crash surfaces as a
  crash rather than masquerading as bad input.

## [0.2.0] - 2026-06-29

### Added

- PKCS#7 / CMS `SignedData` creation (`createPkcs7SignedDataDer`,
  `createPkcs7SignedDataPem`): sign content with one or more signers via the
  RFC 5652 §5.4 signed-attributes flow (`contentType` + `messageDigest`),
  producing attached SignedData that round-trips through
  `verifyPkcs7SignedData`. The content digest is selected per signer key:
  SHA-256 for ECDSA P-256 and RSA-SHA256, SHA-384 for P-384, and SHA-512
  for P-521 and Ed25519 (the latter per RFC 8419). Returns a typed result
  (`no_signers` / `invalid_signer_certificate` / `unsupported_signer_key`)
  for caller-correctable input.

## [0.1.1] - 2026-06-29

Maintenance release — release-pipeline fixes only, no library changes.

### Fixed

- Publish workflow is gated on the test suite, authenticates npm via OIDC
  trusted publishing, and emits correct JSR/npm release URLs.

## [0.1.0] - 2026-06-29

Initial prerelease. API may change before 1.0.

### Added

- X.509 certificate and CSR creation, parsing, and self-signing.
- Certificate chain verification with typed results (21 error codes, failing
  certificate index, structured failure details) and RFC 6125 service-identity
  matching (DNS, IPv6, URI-ID, SRV-ID, explicit CN opt-in).
- Revocation: CRL create/parse/verify/status and OCSP request building plus
  response parsing and responder-authorization checks.
- PKCS#7 / CMS `SignedData` parsing and signer-signature verification.
- PFX / PKCS#12 create and parse (PBES2, PKCS#12 KDF, HMAC-SHA-256 MAC).
- PEM handling and key import/export (PKCS#8, SPKI, JWK, PKCS#1, SEC1) with
  generation for RSA, ECDSA (`P-256`/`P-384`/`P-521`), and Ed25519.
- Zero runtime dependencies, WebCrypto-native, tree-shakeable subpath exports;
  runs on Node, Bun, Deno, browsers, and Cloudflare Workers.

[Unreleased]: https://github.com/kjanat/micro509/compare/v0.14.0...HEAD
[0.14.0]: https://github.com/kjanat/micro509/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/kjanat/micro509/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/kjanat/micro509/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/kjanat/micro509/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/kjanat/micro509/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/kjanat/micro509/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/kjanat/micro509/compare/v0.7.2...v0.8.0
[0.7.2]: https://github.com/kjanat/micro509/compare/v0.7.1...v0.7.2
[0.7.1]: https://github.com/kjanat/micro509/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/kjanat/micro509/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/kjanat/micro509/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/kjanat/micro509/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/kjanat/micro509/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/kjanat/micro509/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/kjanat/micro509/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/kjanat/micro509/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/kjanat/micro509/releases/tag/v0.1.0
