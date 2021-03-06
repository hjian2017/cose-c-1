// --------------------------------------------------------------------------------
//   Copyright (c) 2015, cose-wg
//   All rights reserved.
//
//   Redistribution and use in source and binary forms, with or without
//   modification, are permitted provided that the following conditions are met:
//
//   * Redistributions of source code must retain the above copyright notice, this
//     list of conditions and the following disclaimer.
//   
//   * Redistributions in binary form must reproduce the above copyright notice,
//     this list of conditions and the following disclaimer in the documentation
//     and/or other materials provided with the distribution.
//   
//   * Neither the name of COSE-C nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//   
//   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
//   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
//   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//   DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
//   FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
//   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
//   CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
//   OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
//   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// --------------------------------------------------------------------------------

#ifndef __COSE_H__
#define __COSE_H__

#ifndef USE_TINY_CBOR
#include "cn-cbor.h"
#else
#include "tinycbor.h"
#endif
#include "configure.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned char byte;

typedef struct _cose * HCOSE;
typedef struct _cose_sign * HCOSE_SIGN;
typedef struct _cose_signer * HCOSE_SIGNER;
typedef struct _cose_sign0 * HCOSE_SIGN0;
typedef struct _cose_encrypt * HCOSE_ENCRYPT;
typedef struct _cose_enveloped * HCOSE_ENVELOPED;
typedef struct _cose_recipient * HCOSE_RECIPIENT;
typedef struct _cose_mac * HCOSE_MAC;
typedef struct _cose_mac0 * HCOSE_MAC0;
typedef struct _cose_counterSignature * HCOSE_COUNTERSIGN;

/**
* All of the different kinds of errors
*/
typedef enum {
	/** No error has occurred */
	COSE_ERR_NONE,
	/** An invalid parameter was passed to a function */
	COSE_ERR_INVALID_PARAMETER,
	COSE_ERR_INVALID_HANDLE,
	/** Allocation failed */
	COSE_ERR_OUT_OF_MEMORY,
	/** Error in processing CBOR */
	COSE_ERR_CBOR,
	/** Unknown algorithm found */
	COSE_ERR_UNKNOWN_ALGORITHM,
	/** No usable recipient found */
	COSE_ERR_NO_RECIPIENT_FOUND,
	/** Decryption operation failed */
	COSE_ERR_DECRYPT_FAILED,
	/** Cryptographic failure */
	COSE_ERR_CRYPTO_FAIL,
	/** Internal Error */
	COSE_ERR_INTERNAL
} cose_error;

typedef enum {
	COSE_INIT_FLAGS_NONE=0,
	COSE_INIT_FLAGS_DETACHED_CONTENT=1,
	COSE_INIT_FLAGS_NO_CBOR_TAG=2,
	COSE_INIT_FLAGS_ZERO_FORM=4
} COSE_INIT_FLAGS;
/**
* Errors
*/
typedef struct _cose_errback {
	/** The error, or CN_CBOR_NO_ERROR if none */
	cose_error err;
} cose_errback;

typedef enum {
	COSE_unknown_object = 0,
	COSE_sign_object = 98,
	COSE_sign0_object = 18,
	COSE_enveloped_object = 96,
	COSE_encrypt_object = 16,
	COSE_mac_object = 97,
	COSE_mac0_object = 17,
	COSE_recipient_object = -1
} COSE_object_type;


typedef enum {
	COSE_PROTECT_ONLY = 1,
	COSE_UNPROTECT_ONLY = 2,
	COSE_DONT_SEND = 4,
	COSE_BOTH = 7
} cose_protect_state;

typedef enum {
	COSE_Algorithm_AES_GCM_128 = 1,
	COSE_Algorithm_AES_GCM_192 = 2,
	COSE_Algorithm_AES_GCM_256 = 3,

	COSE_Algorithm_HMAC_256_64 = 4,
	COSE_Algorithm_HMAC_256_256 = 5,
	COSE_Algorithm_HMAC_384_384 = 6,
	COSE_Algorithm_HMAC_512_512 = 7,

	COSE_Algorithm_CBC_MAC_128_64 = 14,
	COSE_Algorithm_CBC_MAC_256_64 = 15,
	COSE_Algorithm_CBC_MAC_128_128 = 25,
	COSE_Algorithm_CBC_MAC_256_128 = 26,

	COSE_Algorithm_AES_CCM_16_64_128 = 10,
	COSE_Algorithm_AES_CCM_16_64_256 = 11,
	COSE_Algorithm_AES_CCM_64_64_128 = 12,
	COSE_Algorithm_AES_CCM_64_64_256 = 13,
	COSE_Algorithm_AES_CCM_16_128_128 = 30,
	COSE_Algorithm_AES_CCM_16_128_256 = 31,
	COSE_Algorithm_AES_CCM_64_128_128 = 32,
	COSE_Algorithm_AES_CCM_64_128_256 = 33,

	COSE_Algorithm_ECDH_ES_HKDF_256 = -25,
	COSE_Algorithm_ECDH_ES_HKDF_512 = -26,
	COSE_Algorithm_ECDH_SS_HKDF_256 = -27,
	COSE_Algorithm_ECDH_SS_HKDF_512 = -28,

	COSE_Algorithm_ECDH_ES_A128KW = -29,
	COSE_Algorithm_ECDH_ES_A192KW = -30,
	COSE_Algorithm_ECDH_ES_A256KW = -31,
	COSE_Algorithm_ECDH_SS_A128KW = -32,
	COSE_Algorithm_ECDH_SS_A192KW = -33,
	COSE_Algorithm_ECDH_SS_A256KW = -34,

	COSE_Algorithm_AES_KW_128 = -3,
	COSE_Algorithm_AES_KW_192 = -4,
	COSE_Algorithm_AES_KW_256 = -5,

	COSE_Algorithm_Direct = -6,

	COSE_Algorithm_Direct_HKDF_HMAC_SHA_256 = -10,
	COSE_Algorithm_Direct_HKDF_HMAC_SHA_512 = -11,
	COSE_Algorithm_Direct_HKDF_AES_128 = -12,
	COSE_Algorithm_Direct_HKDF_AES_256 = -13,

//	COSE_Algorithm_PS256 = -8,
//	COSE_Algorithm_PS384 = -37,
//	COSE_Algorithm_PS512 = -38,

	COSE_Algorithm_ECDSA_SHA_256 = -7,
	COSE_Algorithm_ECDSA_SHA_384 = -35,
	COSE_Algorithm_ECDSA_SHA_512 = -36,
} COSE_Algorithms;

typedef enum {
	COSE_Header_Algorithm = 1,
	COSE_Header_Critical = 2,
	COSE_Header_Content_Type = 3,
	COSE_Header_KID = 4,
	COSE_Header_IV = 5,
	COSE_Header_Partial_IV = 6,
	COSE_Header_CounterSign = 7,
	COSE_Header_Operation_Time = 8,

	COSE_Header_HKDF_salt = -20,
	COSE_Header_KDF_U_name = -21,
	COSE_Header_KDF_U_nonce = -22,
	COSE_Header_KDF_U_other = -23,
	COSE_Header_KDF_V_name = -24,
	COSE_Header_KDF_V_nonce = -25,
	COSE_Header_KDF_V_other = -26,

	COSE_Header_KDF_PUB_other = -999,
	COSE_Header_KDF_PRIV = -998,
	COSE_Header_UseCompressedECDH = -997,

	COSE_Header_ECDH_EPHEMERAL = -1,
	COSE_Header_ECDH_STATIC = -2,
	COSE_Header_ECDH_EPK = -1,
	COSE_Header_ECDH_SPK = -2,
	COSE_Header_ECDH_SPK_KID = -3,

} COSE_Header;

typedef enum {
	COSE_Key_Type_EC2 = 2,
	COSE_Key_Type_OCTET = 4,
	COSE_Key_Type = 1,
	COSE_Key_ID = 2,
	COSE_Parameter_KID = 4,
	COSE_Key_EC2_Curve=-1,
	COSE_Key_EC2_X = -2,
	COSE_Key_EC2_Y = -3
} COSE_Constants;
#ifndef USE_TINY_CBOR
//  Generic functions for the COSE library
/**
* Create an HCOSE from a preallocated, decoded CBOR object containing a COSE.
*
* The function allocates memory dynamically, and the handle returned must be freed by COSE_<type>_Free() function (type depends on struct_type).
* Note: If a COSE is initialized using this function, coseObj provided will NOT be freed when calling COSE_<type>_Free(). caller must free it seperately.
* FIXME: Currently, coseObj will not be freed only if struct_type is COSE_sign0_object, since this is the only type currently in use.
*        to support this functionality for other types, then inside the _COSE_Create_HCOSE() functions that COSE_Init() calls,
*        we should update the correct owner flag in the COSE object of that type.
*
* @param[in]  coseObj       Pointer to an allocated decoded CBOR object containing the COSE.
* @param[out] pType         Pointer to the location where the COSE_object_type will be output to the caller.
*                           Should be the same as the provided struct_type.
* @param[in]  struct_type   Enum representing the type of COSE.
* @param[in]  CBOR_CONTEXT  Allocation context (only if USE_CBOR_CONTEXT is defined).
* @param[out] cose_errback  Pointer to COSE error object where error code will be stored. Can be NULL.
*
* @return
*       HCOSE handle which points to the specific COSE object based on the struct_type.
*       NULL if error has occurred.
*/
HCOSE COSE_Init(const cn_cbor *coseObj, int * ptype, COSE_object_type struct_type, CBOR_CONTEXT_COMMA cose_errback * perr);


/**
* Create an HCOSE from an encoded buffer containing a COSE.
*
* The function allocates memory dynamically, and the handle returned must be freed by COSE_<type>_Free() function (type depends on struct_type).
*
* @param[in]  rgbData       Pointer to a buffer containing the encoded COSE.
* @param[in]  cbData        The size of rgbData buffer.
* @param[out] pType         Pointer to the location where the COSE_object_type will be output to the caller.
*                           Should be the same as the provided struct_type.
* @param[in]  struct_type   Enum representing the type of COSE.
* @param[in]  CBOR_CONTEXT  Allocation context (only if USE_CBOR_CONTEXT is defined).
* @param[out] cose_errback  Pointer to COSE error object where error code will be stored. Can be NULL.
*
* @return
*       HCOSE handle which points to the specific COSE object based on the struct_type.
*       NULL if error has occurred.
*/
HCOSE COSE_Decode(const byte * rgbData, size_t cbData, int * type, COSE_object_type struct_type, CBOR_CONTEXT_COMMA cose_errback * perr);  //  Decode the object
size_t COSE_Encode(HCOSE msg, byte * rgb, size_t ib, size_t cb);

cn_cbor * COSE_get_cbor(HCOSE hmsg);

/*
 *  messages dealing with the Enveloped message type
 */

HCOSE_ENVELOPED  COSE_Enveloped_Init(COSE_INIT_FLAGS flags, CBOR_CONTEXT_COMMA cose_errback * perr);
bool COSE_Enveloped_Free(HCOSE_ENVELOPED cose CBOR_CONTEXT);

cn_cbor * COSE_Enveloped_map_get_int(HCOSE_ENVELOPED cose, int key, int flags, cose_errback * errp);
cn_cbor * COSE_Enveloped_map_get_string(HCOSE_ENVELOPED cose, const char * key, int flags, cose_errback * errp);
bool COSE_Enveloped_map_put_int(HCOSE_ENVELOPED cose, int key, cn_cbor * value, int flags, CBOR_CONTEXT_COMMA cose_errback * errp);
bool COSE_Enveloped_map_put_string(HCOSE_ENVELOPED cose, int key, cn_cbor * value, int flags, cose_errback * errp);


bool COSE_Enveloped_SetContent(HCOSE_ENVELOPED cose, const byte * rgbContent, size_t cbContent, cose_errback * errp);
byte * COSE_Enveloped_GetContent(HCOSE_ENVELOPED cose, size_t * pcbContent, cose_errback * errp);
bool COSE_Enveloped_SetExternal(HCOSE_ENVELOPED hcose, const byte * pbExternalData, size_t cbExternalData, cose_errback * perr);

bool COSE_Enveloped_encrypt(HCOSE_ENVELOPED cose, CBOR_CONTEXT_COMMA cose_errback * perror);
bool COSE_Enveloped_decrypt(HCOSE_ENVELOPED, HCOSE_RECIPIENT, cose_errback * perr);

extern bool COSE_Enveloped_AddRecipient(HCOSE_ENVELOPED hMac, HCOSE_RECIPIENT hRecip, CBOR_CONTEXT_COMMA cose_errback * perr);
HCOSE_RECIPIENT COSE_Enveloped_GetRecipient(HCOSE_ENVELOPED cose, int iRecipient, cose_errback * perr);

extern bool COSE_Enveloped_AddCounterSigner(HCOSE_ENCRYPT hEnv, HCOSE_COUNTERSIGN hSign, cose_errback * perr);
HCOSE_COUNTERSIGN COSE_Enveloped_GetCounterSigner(HCOSE_ENCRYPT, int iSigner, cose_errback * perr);

/*
 */

HCOSE_RECIPIENT COSE_Recipient_Init(COSE_INIT_FLAGS flags, CBOR_CONTEXT_COMMA cose_errback * perror);
bool COSE_Recipient_Free(HCOSE_RECIPIENT cose CBOR_CONTEXT);
HCOSE_RECIPIENT COSE_Recipient_from_shared_secret(byte * rgbKey, int cbKey, byte * rgbKid, int cbKid, CBOR_CONTEXT_COMMA cose_errback * perr);

bool COSE_Recipient_SetKey_secret(HCOSE_RECIPIENT h, const byte * rgb, int cb, const byte * rgbKid, int cbKid, CBOR_CONTEXT_COMMA cose_errback * perr);
bool COSE_Recipient_SetKey(HCOSE_RECIPIENT h, const cn_cbor * pKey, cose_errback * perror);
bool COSE_Recipient_SetSenderKey(HCOSE_RECIPIENT h, const cn_cbor * pKey, int destination, CBOR_CONTEXT_COMMA cose_errback * perror);
bool COSE_Recipient_SetExternal(HCOSE_RECIPIENT hcose, const byte * pbExternalData, size_t cbExternalData, cose_errback * perr);

bool COSE_Recipient_map_put_int(HCOSE_RECIPIENT h, int key, cn_cbor * value, int flags, CBOR_CONTEXT_COMMA cose_errback * perror);
cn_cbor * COSE_Recipient_map_get_string(HCOSE_RECIPIENT cose, const char * key, int flags, cose_errback * errp);
cn_cbor * COSE_Recipient_map_get_int(HCOSE_RECIPIENT cose, int key, int flags, cose_errback * errp);

extern bool COSE_Recipient_AddRecipient(HCOSE_RECIPIENT hMac, HCOSE_RECIPIENT hRecip, CBOR_CONTEXT_COMMA cose_errback * perr);
HCOSE_RECIPIENT COSE_Recipient_GetRecipient(HCOSE_RECIPIENT cose, int iRecipient, cose_errback * perr);


/*
 *  Encrypt message API
 */

HCOSE_ENCRYPT  COSE_Encrypt_Init(COSE_INIT_FLAGS flags, CBOR_CONTEXT_COMMA cose_errback * perr);
bool COSE_Encrypt_Free(HCOSE_ENCRYPT cose CBOR_CONTEXT);

cn_cbor * COSE_Encrypt_map_get_int(HCOSE_ENCRYPT cose, int key, int flags, cose_errback * errp);
cn_cbor * COSE_Encrypt_map_get_string(HCOSE_ENCRYPT cose, const char * key, int flags, cose_errback * errp);
bool COSE_Encrypt_map_put_int(HCOSE_ENCRYPT cose, int key, cn_cbor * value, int flags, CBOR_CONTEXT_COMMA cose_errback * errp);
bool COSE_Encrypt_map_put_string(HCOSE_ENCRYPT cose, int key, cn_cbor * value, int flags, cose_errback * errp);


bool COSE_Encrypt_SetContent(HCOSE_ENCRYPT cose, const byte * rgbContent, size_t cbContent, cose_errback * errp);
byte * COSE_Encrypt_GetContent(HCOSE_ENCRYPT cose, size_t * pcbContent, cose_errback * errp);
bool COSE_Encrypt_SetExternal(HCOSE_ENCRYPT hcose, const byte * pbExternalData, size_t cbExternalData, cose_errback * perr);

bool COSE_Encrypt_encrypt(HCOSE_ENCRYPT cose, const byte * pbKey, size_t cbKey, CBOR_CONTEXT_COMMA cose_errback * perror);
bool COSE_Encrypt_decrypt(HCOSE_ENCRYPT, const byte * pbKey, size_t cbKey, cose_errback * perr);


//
//

HCOSE_MAC COSE_Mac_Init(COSE_INIT_FLAGS flags, CBOR_CONTEXT_COMMA cose_errback * perr);
bool COSE_Mac_Free(HCOSE_MAC cose CBOR_CONTEXT);

bool COSE_Mac_SetContent(HCOSE_MAC cose, const byte * rgbContent, size_t cbContent, cose_errback * errp);
bool COSE_Mac_SetExternal(HCOSE_MAC hcose, const byte * pbExternalData, size_t cbExternalData, cose_errback * perr);

cn_cbor * COSE_Mac_map_get_int(HCOSE_MAC h, int key, int flags, cose_errback * perror);
bool COSE_Mac_map_put_int(HCOSE_MAC cose, int key, cn_cbor * value, int flags, cose_errback * errp);

bool COSE_Mac_encrypt(HCOSE_MAC cose, cose_errback * perror);
bool COSE_Mac_validate(HCOSE_MAC, HCOSE_RECIPIENT, cose_errback * perr);

extern bool COSE_Mac_AddRecipient(HCOSE_MAC hMac, HCOSE_RECIPIENT hRecip, CBOR_CONTEXT_COMMA cose_errback * perr);
HCOSE_RECIPIENT COSE_Mac_GetRecipient(HCOSE_MAC cose, int iRecipient, cose_errback * perr);

//  MAC0 calls
HCOSE_MAC0 COSE_Mac0_Init(COSE_INIT_FLAGS flags, CBOR_CONTEXT_COMMA cose_errback * perr);
bool COSE_Mac0_Free(HCOSE_MAC0 cose CBOR_CONTEXT);

bool COSE_Mac0_SetContent(HCOSE_MAC0 cose, const byte * rgbContent, size_t cbContent, cose_errback * errp);
bool COSE_Mac0_SetExternal(HCOSE_MAC0 hcose, const byte * pbExternalData, size_t cbExternalData, cose_errback * perr);

cn_cbor * COSE_Mac0_map_get_int(HCOSE_MAC0 h, int key, int flags, cose_errback * perror);
bool COSE_Mac0_map_put_int(HCOSE_MAC0 cose, int key, cn_cbor * value, int flags, CBOR_CONTEXT_COMMA cose_errback * errp);

bool COSE_Mac0_encrypt(HCOSE_MAC0 cose, const byte * pbKey, size_t cbKey, CBOR_CONTEXT_COMMA cose_errback * perror);
bool COSE_Mac0_validate(HCOSE_MAC0, const byte * pbKey, size_t cbKey, cose_errback * perr);


// Sign
HCOSE_SIGN COSE_Sign_Init(COSE_INIT_FLAGS flags, CBOR_CONTEXT_COMMA cose_errback * perr);
bool COSE_Sign_Free(HCOSE_SIGN cose CBOR_CONTEXT);

bool COSE_Sign_SetContent(HCOSE_SIGN cose, const byte * rgbContent, size_t cbContent, CBOR_CONTEXT_COMMA cose_errback * errp);

HCOSE_SIGNER COSE_Sign_add_signer(HCOSE_SIGN cose, const cn_cbor * pkey, int algId, CBOR_CONTEXT_COMMA cose_errback * perr);
extern bool COSE_Sign_AddSigner(HCOSE_SIGN hSign, HCOSE_SIGNER hSigner, CBOR_CONTEXT_COMMA cose_errback * perr);
bool COSE_Sign_Sign(HCOSE_SIGN h, cose_errback * perr);
HCOSE_SIGNER COSE_Sign_GetSigner(HCOSE_SIGN cose, int iSigner, cose_errback * perr);

bool COSE_Sign_validate(HCOSE_SIGN hSign, HCOSE_SIGNER hSigner, cose_errback * perr);
cn_cbor * COSE_Sign_map_get_int(HCOSE_SIGN h, int key, int flags, cose_errback * perror);
bool COSE_Sign_map_put_int(HCOSE_SIGN cose, int key, cn_cbor * value, int flags, CBOR_CONTEXT_COMMA cose_errback * errp);


HCOSE_SIGNER COSE_Signer_Init(CBOR_CONTEXT_COMMA cose_errback * perror);
bool COSE_Signer_Free(HCOSE_SIGNER cose CBOR_CONTEXT);
bool COSE_Signer_SetKey(HCOSE_SIGNER hSigner, const cn_cbor * pkey, cose_errback * perr);

extern cn_cbor * COSE_Signer_map_get_int(HCOSE_SIGNER h, int key, int flags, cose_errback * perr);
extern bool COSE_Signer_map_put_int(HCOSE_SIGNER cose, int key, cn_cbor * value, int flags, CBOR_CONTEXT_COMMA cose_errback * errp);

bool COSE_Signer_SetExternal(HCOSE_SIGNER hcose, const byte * pbExternalData, size_t cbExternalData, cose_errback * perr);

/*
 *  Sign routines
 */

HCOSE_SIGN0 COSE_Sign0_Init(COSE_INIT_FLAGS flags, CBOR_CONTEXT_COMMA cose_errback * perr);


bool COSE_Sign0_SetContent(HCOSE_SIGN0 cose, const byte * rgbContent, size_t cbContent, cose_errback * errp);
bool COSE_Sign0_SetExternal(HCOSE_SIGN0 hcose, const byte * pbExternalData, size_t cbExternalData, cose_errback * perr);

bool COSE_Sign0_Sign(HCOSE_SIGN0 h, const cn_cbor * pkey, cose_errback * perr);


// Validate with a user provided public key
bool COSE_Sign0_validate_with_raw_pk(HCOSE_SIGN0 hSign, const byte * pKey, size_t keySize, cose_errback * perr);

// Validate with a COSE_Key object (a cbor map within the cwt, check out RFC 8152)
bool COSE_Sign0_validate_with_cose_key(HCOSE_SIGN0 hSign, const cn_cbor * pKeyCose, cose_errback * perr);

cn_cbor * COSE_Sign0_map_get_int(HCOSE_SIGN0 h, int key, int flags, cose_errback * perror);
bool COSE_Sign0_map_put_int(HCOSE_SIGN0 cose, int key, cn_cbor * value, int flags, CBOR_CONTEXT_COMMA cose_errback * errp);

bool GetECKeyFromCoseKeyObj(const cn_cbor *coseObj, byte *ecKeyOut, size_t ecKeyOutSize, size_t *ecKeySizeOut, cose_errback *perr);

/*
 * Counter Signature Routines
 */

HCOSE_COUNTERSIGN COSE_CounterSign_Init(COSE_INIT_FLAGS flags, CBOR_CONTEXT_COMMA cose_errback * perr);
bool COSE_CounterSign_Free(HCOSE_COUNTERSIGN cose CBOR_CONTEXT);

cn_cbor * COSE_CounterSign_map_get_int(HCOSE_COUNTERSIGN h, int key, int flags, cose_errback * perror);
bool COSE_CounterSign_map_put_int(HCOSE_COUNTERSIGN cose, int key, cn_cbor * value, int flags, cose_errback * errp);

/*
*/

extern cn_cbor * cn_cbor_clone(const cn_cbor * pIn, CBOR_CONTEXT_COMMA cn_cbor_errback * perr);
extern cn_cbor * cn_cbor_tag_create(int tag, cn_cbor * child, CBOR_CONTEXT_COMMA cn_cbor_errback * perr);
extern cn_cbor * cn_cbor_bool_create(int boolValue, CBOR_CONTEXT_COMMA cn_cbor_errback * errp);
extern cn_cbor * cn_cbor_null_create(CBOR_CONTEXT_COMMA cn_cbor_errback * errp);
bool COSE_Sign0_Free(HCOSE_SIGN0 cose CBOR_CONTEXT);
#endif




#ifdef USE_TINY_CBOR
bool COSE_Sign0_map_put_int_tiny(HCOSE_SIGN0 cose, int key, /*cn_cbor * value,*/ int flags,  cose_errback * errp);
bool COSE_Sign0_Free(HCOSE_SIGN0 cose);
/**
* Create an HCOSE from a preallocated, decoded CBOR object containing a COSE.
*
* The function allocates memory dynamically, and the handle returned must be freed by COSE_<type>_Free() function (type depends on struct_type).
* Note: If a COSE is initialized using this function, coseObj provided will NOT be freed when calling COSE_<type>_Free(). caller must free it seperately.
* FIXME: Currently, coseObj will not be freed only if struct_type is COSE_sign0_object, since this is the only type currently in use.
*        to support this functionality for other types, then inside the _COSE_Create_HCOSE() functions that COSE_Init() calls,
*        we should update the correct owner flag in the COSE object of that type.
*
* @param[in]  coseBuffer       Pointer to an allocated encoded CBOR buffer containing the COSE.
* @param[in]  coseBufferSize   Size of an allocated encoded CBOR buffer containing the COSE.
* @param[out] pType         Pointer to the location where the COSE_object_type will be output to the caller.
*                           Should be the same as the provided struct_type.
* @param[in]  struct_type   Enum representing the type of COSE.
* @param[in]  CBOR_CONTEXT  Allocation context (only if USE_CBOR_CONTEXT is defined).
* @param[out] cose_errback  Pointer to COSE error object where error code will be stored. Can be NULL.
*
* @return
*       HCOSE handle which points to the specific COSE object based on the struct_type.
*       NULL if error has occurred.
*/
HCOSE COSE_Init_tiny(const uint8_t *coseBuffer, size_t coseBufferSize, int * ptype, COSE_object_type struct_type, cose_errback * perr);

// Validate with a user provided public key buffer
bool COSE_Sign0_validate_with_cose_key_buffer(HCOSE_SIGN0 hSign, const uint8_t * coseEncBuffer, size_t coseEncBufferSize, cose_errback * perr);


// Validate with a user provided public key
bool COSE_Sign0_validate_with_raw_pk_tiny(HCOSE_SIGN0 hSign, const byte * pKey, size_t keySize, cose_errback * perr);

/*  This function uses tiny cbor functionality */
bool GetECKeyFromCoseBuffer(const uint8_t *coseEncBuffer, size_t coseEncBufferSize, byte *ecKeyOut, size_t ecKeyBufferSize, size_t *ecKeySizeOut, cose_errback *perr);
/**
* Create an HCOSE from an encoded buffer containing a COSE.
*
* The function allocates memory dynamically, and the handle returned must be freed by COSE_<type>_Free() function (type depends on struct_type).
*
* @param[in]  rgbData       Pointer to a buffer containing the encoded COSE.
* @param[in]  cbData        The size of rgbData buffer.
* @param[out] pType         Pointer to the location where the COSE_object_type will be output to the caller.
*                           Should be the same as the provided struct_type.
* @param[in]  struct_type   Enum representing the type of COSE.
* @param[out] cose_errback  Pointer to COSE error object where error code will be stored. Can be NULL.
*
* @return
*       HCOSE handle which points to the specific COSE object based on the struct_type.
*       NULL if error has occurred.
*/
HCOSE COSE_Decode_tiny(const byte * rgbData, size_t cbData, int * ptype, COSE_object_type struct_type, cose_errback * perr);
bool  COSE_Sign0_map_get_int_tiny(HCOSE_SIGN0 h, int key, int flags, uint8_t **out_map_value, size_t *out_map_value_size, cose_errback * perror);
#endif



#ifdef __cplusplus
}
#endif
#endif

