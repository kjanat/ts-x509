/**
 * PKCS container APIs: PFX/PKCS#12 and PKCS#7/CMS.
 *
 * Owns PFX archive creation and parsing, PKCS#7 certificate bags and SignedData,
 * and PKCS#12 MAC integrity helpers.
 *
 * @module micro509/pkcs
 */

// Re-exports owned by pfx but sourced from internal (PBES2 encryption options)
export type {
	CreatePfxErrorCode,
	CreatePfxFailure,
	CreatePfxInput,
	CreatePfxResult,
	KdfLimitOptions,
	ParsedPfx,
	ParsedPfxAttribute,
	ParsedPfxBag,
	ParsedPfxBagAttributes,
	ParsePfxErrorCode,
	ParsePfxFailure,
	ParsePfxOptions,
	ParsePfxResult,
	PfxBagAttributesInput,
	PfxCertificateBagInput,
	PfxCertificateSource,
	PfxEncryptionOptions,
	PfxMaterial,
	PfxPrivateKeyBagInput,
	PfxPrivateKeySource,
} from '#micro509/pkcs/pfx';
export { createPfx, parsePfxDer, parsePfxPem } from '#micro509/pkcs/pfx';

export type {
	CreatePkcs7CertBagErrorCode,
	CreatePkcs7CertBagFailure,
	CreatePkcs7CertBagResult,
	CreatePkcs7SignedDataErrorCode,
	CreatePkcs7SignedDataFailure,
	CreatePkcs7SignedDataInput,
	CreatePkcs7SignedDataResult,
	ParsedCertificateChoice,
	ParsedPkcs7SignedData,
	ParsedPkcs7SignerInfo,
	ParsedPkcs7SignerInfoBase,
	ParsedSignerIdentifier,
	ParsePkcs7CertBagResult,
	ParsePkcs7ErrorCode,
	ParsePkcs7Failure,
	ParsePkcs7SignedDataResult,
	Pkcs7CertBagMaterial,
	Pkcs7CertificateSource,
	Pkcs7SignedDataMaterial,
	Pkcs7Signer,
	VerifiedPkcs7Signer,
	VerifyPkcs7SignedDataErrorCode,
	VerifyPkcs7SignedDataFailure,
	VerifyPkcs7SignedDataOptions,
	VerifyPkcs7SignedDataResult,
} from '#micro509/pkcs/pkcs7';
export {
	createPkcs7CertBag,
	createPkcs7SignedData,
	parsePkcs7CertBagDer,
	parsePkcs7CertBagPem,
	parsePkcs7SignedDataDer,
	parsePkcs7SignedDataPem,
	verifyPkcs7SignedData,
} from '#micro509/pkcs/pkcs7';

export type {
	ParsedPkcs12MacData,
	ParsePkcs12MacDataErrorCode,
	ParsePkcs12MacDataFailure,
	ParsePkcs12MacDataOptions,
	ParsePkcs12MacDataResult,
	Pkcs12MacOptions,
} from '#micro509/pkcs/pkcs12-mac';
export {
	createPkcs12MacData,
	parsePkcs12MacData,
	parsePkcs12MacDataOrThrow,
} from '#micro509/pkcs/pkcs12-mac';
