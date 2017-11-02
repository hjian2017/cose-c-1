//----------------------------------------------------------------------------
//   The confidential and proprietary information contained in this file may
//   only be used by a person authorised under and to the extent permitted
//   by a subsisting licensing agreement from ARM Limited or its affiliates.
//
//          (C) COPYRIGHT 2013-2016 ARM Limited or its affiliates.
//              ALL RIGHTS RESERVED
//
//   This entire notice must be reproduced on all copies of this file
//   and copies of this file may only be made by a person if such person is
//   permitted to do so under the terms of a subsisting license agreement
//   from ARM Limited or its affiliates.
//----------------------------------------------------------------------------

#include <stdbool.h>
#include "dba_error_handling.h"
#include "cose.h"
#include "configure.h"
#include "cose_int.h"
#include "crypto.h"
#include "pal_Crypto.h"
#include "bignum.h"
#include "ecdsa.h"
#include "ecp.h"

#define COSE_Key_EC_Curve -1
#define COSE_Key_EC_X -2
#define COSE_Key_EC_Y -3

// Must add parameter for ecKeyOut size and return an error
bool GetECKeyFromCbor(const cn_cbor *coseObj, byte *ecKeyOut, size_t ecKeyBufferSize, size_t *ecKeySizeOut, int *groupSizeBytesOut, cose_errback *perr)
{
    byte rgbKey[512 + 1];
    size_t rgbKeyBytes;
    const cn_cbor *p;

    p = cn_cbor_mapget_int(coseObj, COSE_Key_EC_Curve);
    DBA_ERR_RECOVERABLE_GOTO_IF((p == NULL), (perr->err = COSE_ERR_INVALID_PARAMETER), GetECKeyError, "Failed for cn_cbor_mapget_int getting EC Curve");

    switch (p->v.sint) {
        case 1: // P-256
            *groupSizeBytesOut = 256 / 8;
            break;
        default:
            // Unsupported
            DBA_LOG_ERR("Unsupported EC group name size (only P-256 is supported)");
            perr->err = COSE_ERR_INVALID_PARAMETER;
            return false; // failure
    }

    p = cn_cbor_mapget_int(coseObj, COSE_Key_EC_X);
    DBA_ERR_RECOVERABLE_GOTO_IF(((p == NULL) && (p->type != CN_CBOR_BYTES)), (perr->err = COSE_ERR_INVALID_PARAMETER), GetECKeyError, "Failed for cn_cbor_mapget_int geting X point");
    DBA_ERR_RECOVERABLE_GOTO_IF((p->length != *groupSizeBytesOut), (perr->err = COSE_ERR_INVALID_PARAMETER), GetECKeyError, "Invalid X point group size");
    memcpy(rgbKey + 1, p->v.str, p->length);

    p = cn_cbor_mapget_int(coseObj, COSE_Key_EC_Y);
    DBA_ERR_RECOVERABLE_GOTO_IF(((p == NULL) && (p->type != CN_CBOR_BYTES)), (perr->err = COSE_ERR_INVALID_PARAMETER), GetECKeyError, "Failed for cn_cbor_mapget_int geting Y point");

    if (p->type == CN_CBOR_BYTES) {
        rgbKey[0] = 0x04; // Uncompressed
        rgbKeyBytes = (*groupSizeBytesOut * 2) + 1;
        DBA_ERR_RECOVERABLE_GOTO_IF((p->length != *groupSizeBytesOut), (perr->err = COSE_ERR_INVALID_PARAMETER), GetECKeyError, "Invalid Y point group size");
        memcpy(rgbKey + p->length + 1, p->v.str, p->length);
    } else if (p->type == CN_CBOR_TRUE) {
        rgbKeyBytes = (*groupSizeBytesOut) + 1;
        rgbKey[0] = 0x02 + (rgbKey[0] & 0x1); // Compressed
    } else if (p->type == CN_CBOR_FALSE) {
        rgbKeyBytes = (*groupSizeBytesOut) + 1;
        rgbKey[0] = 0x04; // Uncompressed
    } else {
        DBA_LOG_ERR("Invalid CBOR type");
        perr->err = COSE_ERR_INVALID_PARAMETER;
        return false; // failure
    }

    DBA_ERR_RECOVERABLE_GOTO_IF((rgbKeyBytes > ecKeyBufferSize), (perr->err = COSE_ERR_INVALID_PARAMETER), GetECKeyError, "Provided buffer of insufficient size");

GetECKeyError:
    if (perr->err != COSE_ERR_NONE) {
        return false; // failure
    }

    // success
    memcpy(ecKeyOut, rgbKey, rgbKeyBytes);
    *ecKeySizeOut = rgbKeyBytes;
    return true;
} 

bool ECDSA_Verify(
    COSE *pSigner,
    int index,
    const byte *pKey,
    size_t keySize,
    int cbitDigest,
    const unsigned char *rgbToSign,
    size_t cbToSign,
    cose_errback *perr)
{
    bool success;
    palStatus_t palStatus;
    unsigned char rgbDigest[PAL_SHA256_SIZE];
    uint32_t rgbDigestSize = sizeof(rgbDigest);

    cn_cbor *signerSig;
    int signerSigLength;

    int mbedtlsStatus;
    mbedtls_mpi r, s;
    mbedtls_ecp_group grp;

    byte rawECKey[512 + 1];
    size_t rawECKeySize;
    int groupSizeBytes;

    // FIXME: for demo purposes it is assumed that we're getting the key in DER format from the KCM,
    // when we will switch to a "proof of possession" we have to parse a CBOR object to extract the public key material.
    mbedtls_ecp_point ecKey;

    mbedtls_ecp_point_init(&ecKey);
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);

    // Import R and S points as mbedTLS entities
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    // Assume success at first
    perr->err = COSE_ERR_NONE;

    // Compute digest on the input hash data

    palStatus = pal_sha256(rgbToSign, cbToSign, rgbDigest);
    DBA_ERR_RECOVERABLE_GOTO_IF((palStatus != PAL_SUCCESS), (perr->err = COSE_ERR_CRYPTO_FAIL), EndWithError, "Failed for pal_sha256 (paStatus = %" PRIu32 ")", palStatus);


    // Get the EC raw key
/*
    success = GetECKey(pKeyObj, rawECKey, &rawECKeySize, &groupSizeBytes, perr);
    DBA_ERR_RECOVERABLE_GOTO_IF((!success), (perr->err = perr->err), EndWithError, "Failed for GetECKey");
*/

    // Fetch the signature to check against and verify it is legit

    signerSig = _COSE_arrayget_int(pSigner, index);
    DBA_ERR_RECOVERABLE_GOTO_IF((signerSig == NULL), (perr->err = COSE_ERR_INVALID_PARAMETER), EndWithError, "Failed for _COSE_arrayget_int");
    signerSigLength = signerSig->length;   
    DBA_ERR_RECOVERABLE_GOTO_IF(((signerSigLength / 2) != groupSizeBytes), (perr->err = COSE_ERR_INVALID_PARAMETER), EndWithError, "Signer invalid signature length");

    // Create mbedTLS EC key (reminder: we currently (for demo purposes) treats the key as a byte stream (not as CBOR entity)
    mbedtlsStatus = mbedtls_ecp_point_read_binary(&grp, &ecKey, rawECKey, rawECKeySize);
    DBA_ERR_RECOVERABLE_GOTO_IF((mbedtlsStatus != 0), (perr->err = COSE_ERR_INTERNAL), EndWithError, "Failed for mbedtls_ecp_point_read_binary (mbedtlsStatus = %u)", mbedtlsStatus);

    mbedtlsStatus = mbedtls_mpi_read_binary(&r, signerSig->v.bytes, (signerSigLength / 2));
    DBA_ERR_RECOVERABLE_GOTO_IF((mbedtlsStatus != 0), (perr->err = COSE_ERR_INTERNAL), EndWithError, "Failed for bedtls_mpi_read_binary (mbedtlsStatus = %u)", mbedtlsStatus);

    mbedtlsStatus = mbedtls_mpi_read_binary(&s, (signerSig->v.bytes + signerSigLength / 2), (signerSigLength / 2));
    DBA_ERR_RECOVERABLE_GOTO_IF((mbedtlsStatus != 0), (perr->err = COSE_ERR_INTERNAL), EndWithError, "Failed for bedtls_mpi_read_binary (mbedtlsStatus = %u)", mbedtlsStatus);

    // Hit the actual EC verify
    mbedtlsStatus = mbedtls_ecdsa_verify(&grp, rgbDigest, rgbDigestSize, &ecKey, &r, &s);
    DBA_ERR_RECOVERABLE_GOTO_IF((mbedtlsStatus != 0), (perr->err = COSE_ERR_CRYPTO_FAIL), EndWithError, "Failed for mbedtls_ecdsa_verify (mbedtlsStatus = %u)", mbedtlsStatus);

EndWithError:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_ecp_point_free(&ecKey);
    mbedtls_ecp_group_free(&grp);

    if (perr->err != COSE_ERR_NONE) {
        return false;
    }

    return true; // success
}

bool ECDSA_Sign(COSE * pSigner, int index, const cn_cbor * pKey, int cbitDigest, const byte * rgbToSign, size_t cbToSign, cose_errback * perr)
{
    assert(true);
    return false; //FIXME: unsupported!
}

bool HMAC_Validate(COSE_MacMessage * pcose, int HSize, int TSize, const byte * pbKey, size_t cbKey, const byte * pbAuthData, size_t cbAuthData, cose_errback * perr)
{
    assert(true);
    return false; //FIXME: unsupported!
}

bool AES_CCM_Decrypt(COSE_Enveloped * pcose, int TSize, int LSize, const byte * pbKey, size_t cbKey, const byte * pbCrypto, size_t cbCrypto, const byte * pbAuthData, size_t cbAuthData, cose_errback * perr)
{
    assert(true);
    return false; //FIXME: unsupported!
}

bool AES_GCM_Decrypt(COSE_Enveloped * pcose, const byte * pbKey, size_t cbKey, const byte * pbCrypto, size_t cbCrypto, const byte * pbAuthData, size_t cbAuthData, cose_errback * perr)
{
    assert(true);
    return false; //FIXME: unsupported!
}

bool AES_CBC_MAC_Validate(COSE_MacMessage * pcose, int TSize, const byte * pbKey, size_t cbKey, const byte * pbAuthData, size_t cbAuthData, cose_errback * perr)
{
    assert(true);
    return false; //FIXME: unsupported!
}

bool ECDH_ComputeSecret(COSE * pRecipient, cn_cbor ** ppKeyPrivate, const cn_cbor * pKeyPublic, byte ** ppbSecret, size_t * pcbSecret, CBOR_CONTEXT_COMMA cose_errback *perr)
{
    assert(true);
    return false; //FIXME: unsupported!
}

bool HKDF_Extract(COSE * pcose, const byte * pbKey, size_t cbKey, size_t cbitDigest, byte * rgbDigest, size_t * pcbDigest, CBOR_CONTEXT_COMMA cose_errback * perr)
{
    assert(true);
    return false; //FIXME: unsupported!
}

bool HKDF_Expand(COSE * pcose, size_t cbitDigest, const byte * pbPRK, size_t cbPRK, const byte * pbInfo, size_t cbInfo, byte * pbOutput, size_t cbOutput, cose_errback * perr)
{
    assert(true);
    return false; //FIXME: unsupported!
}

bool HKDF_AES_Expand(COSE * pcose, size_t cbitKey, const byte * pbPRK, size_t cbPRK, const byte * pbInfo, size_t cbInfo, byte * pbOutput, size_t cbOutput, cose_errback * perr)
{
    assert(true);
    return false; //FIXME: unsupported!
}

bool AES_KW_Decrypt(COSE_Enveloped * pcose, const byte * pbKeyIn, size_t cbitKey, const byte * pbCipherText, size_t cbCipherText, byte * pbKeyOut, int * pcbKeyOut, cose_errback * perr)
{
    assert(true);
    return false; //FIXME: unsupported!
}

bool AES_GCM_Encrypt(COSE_Enveloped * pcose, const byte * pbKey, size_t cbKey, const byte * pbAuthData, size_t cbAuthData, cose_errback * perr)
{
    assert(true);
    return false; //FIXME: unsupported!
}

bool AES_CBC_MAC_Create(COSE_MacMessage * pcose, int TSize, const byte * pbKey, size_t cbKey, const byte * pbAuthData, size_t cbAuthData, cose_errback * perr)
{
    assert(true);
    return false; //FIXME: unsupported!
}

bool HMAC_Create(COSE_MacMessage * pcose, int HSize, int TSize, const byte * pbKey, size_t cbKey, const byte * pbAuthData, size_t cbAuthData, cose_errback * perr)
{
    assert(true);
    return false; //FIXME: unsupported!
}

bool AES_KW_Encrypt(COSE_RecipientInfo * pcose, const byte * pbKeyIn, int cbitKey, const byte *  pbContent, int  cbContent, cose_errback * perr)
{
    assert(true);
    return false; //FIXME: unsupported!
}

bool AES_CCM_Encrypt(COSE_Enveloped * pcose, int TSize, int LSize, const byte * pbKey, size_t cbKey, const byte * pbAuthData, size_t cbAuthData, cose_errback * perr)
{
    assert(true);
    return false; //FIXME: unsupported!
}

void rand_bytes(byte * pb, size_t cb)
{
    assert(true);
}
