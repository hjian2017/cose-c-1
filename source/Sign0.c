/** \file Sign.c
* Contains implementation of the functions related to HCOSE_SIGN handle objects.
*/

#include <stdlib.h>

#include "cose.h"
#include "cose_int.h"
#include "crypto.h"

bool _COSE_Signer0_sign(COSE_Sign0Message * pSigner, const cn_cbor *pKey, cose_errback * perr);
bool _COSE_Signer0_validate(COSE_Sign0Message * pSign, const byte *pKey, size_t keySize, cose_errback * perr);
void _COSE_Sign0_Release(COSE_Sign0Message * p CBOR_CONTEXT);

COSE * Sign0Root = NULL;

/*! \private
* @brief Test if a HCOSE_SIGN0 handle is valid
*
*  Internal function to test if a sign0 message handle is valid.
*  This will start returning invalid results and cause the code to
*  crash if handles are not released before the memory that underlies them
*  is deallocated.  This is an issue of a block allocator is used since
*  in that case it is common to allocate memory but never to de-allocate it
*  and just do that in a single big block.
*
*  @param h handle to be validated
*  @returns result of check
*/

bool IsValidSign0Handle(HCOSE_SIGN0 h)
{
	COSE_Sign0Message * p = (COSE_Sign0Message *)h;

	if (p == NULL) return false;
	return _COSE_IsInList(Sign0Root, (COSE *) p);
}


HCOSE_SIGN0 COSE_Sign0_Init(COSE_INIT_FLAGS flags, CBOR_CONTEXT_COMMA cose_errback * perr)
{
	CHECK_CONDITION(flags == COSE_INIT_FLAGS_NONE, COSE_ERR_INVALID_PARAMETER);
	COSE_Sign0Message * pobj = (COSE_Sign0Message *)COSE_CALLOC(1, sizeof(COSE_Sign0Message), context);
	if (pobj == NULL) {
		if (perr != NULL) perr->err = COSE_ERR_OUT_OF_MEMORY;
		return NULL;
	}

	if (!_COSE_Init(flags,&pobj->m_message, COSE_sign_object, CBOR_CONTEXT_PARAM_COMMA perr)) {
		_COSE_Sign0_Release(pobj CBOR_CONTEXT_PARAM);
		COSE_FREE(pobj);
		return NULL;
	}

	_COSE_InsertInList(&Sign0Root, &pobj->m_message);

	return (HCOSE_SIGN0)pobj;

errorReturn:
	return NULL;
}

HCOSE_SIGN0 _COSE_Sign0_Init_From_Object(cn_cbor * cbor, COSE_Sign0Message * pIn, CBOR_CONTEXT_COMMA cose_errback * perr)
{
	COSE_Sign0Message * pobj = pIn;
	cose_errback error = { 0 };

	if (perr == NULL) perr = &error;

	if (pobj == NULL) pobj = (COSE_Sign0Message *)COSE_CALLOC(1, sizeof(COSE_Sign0Message), context);
	CHECK_CONDITION(pobj != NULL, COSE_ERR_OUT_OF_MEMORY);

	if (!_COSE_Init_From_Object(&pobj->m_message, cbor, CBOR_CONTEXT_PARAM_COMMA perr)) {
		goto errorReturn;
	}

	if (pIn == NULL) _COSE_InsertInList(&Sign0Root, &pobj->m_message);

	return(HCOSE_SIGN0)pobj;

errorReturn:
	if (pobj != NULL) {
		_COSE_Sign0_Release(pobj CBOR_CONTEXT_PARAM);
		if (pIn == NULL) COSE_FREE(pobj);
	}
	return NULL;
}

bool COSE_Sign0_Free(HCOSE_SIGN0 h CBOR_CONTEXT)
{
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context context;
#endif
	COSE_Sign0Message * pMessage = (COSE_Sign0Message *)h;

	if (!IsValidSign0Handle(h)) return false;

	//  Check reference counting
	if (pMessage->m_message.m_refCount > 1) {
		pMessage->m_message.m_refCount--;
		return true;
	}

	_COSE_RemoveFromList(&Sign0Root, &pMessage->m_message);

#ifdef USE_CBOR_CONTEXT
	context = pMessage->m_message.m_allocContext;
#endif

	_COSE_Sign0_Release(pMessage CBOR_CONTEXT_PARAM);

	COSE_FREE(pMessage);

	return true;
}

void _COSE_Sign0_Release(COSE_Sign0Message * p CBOR_CONTEXT)
{
	_COSE_Release(&p->m_message CBOR_CONTEXT_PARAM);
}

bool COSE_Sign0_SetContent(HCOSE_SIGN0 h, const byte * rgb, size_t cb, cose_errback * perr)
{
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context = NULL;
#endif
	cn_cbor * p = NULL;
	COSE_Sign0Message * pMessage = (COSE_Sign0Message *)h;
	bool fRet = false;

	CHECK_CONDITION(IsValidSign0Handle(h), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(rgb != NULL, COSE_ERR_INVALID_PARAMETER);

#ifdef USE_CBOR_CONTEXT
	context = &pMessage->m_message.m_allocContext;
#endif

	p = cn_cbor_data_create(rgb, (int) cb, CBOR_CONTEXT_PARAM_COMMA NULL);
	CHECK_CONDITION(p != NULL, COSE_ERR_OUT_OF_MEMORY);

	CHECK_CONDITION(_COSE_array_replace(&pMessage->m_message, p, INDEX_BODY, CBOR_CONTEXT_PARAM_COMMA NULL), COSE_ERR_OUT_OF_MEMORY);
	p = NULL;

	fRet = true;

errorReturn:
	if (p != NULL) CN_CBOR_FREE(p);
	return fRet;
}

/*!
* @brief Set the application external data for authentication
*
* Enveloped data objects support the authentication of external application
* supplied data.  This function is provided to supply that data to the library.
*
* The external data is not copied, nor will be it freed when the handle is released.
*
* @param hcose  Handle for the COSE Enveloped data object
* @param pbEternalData  point to the external data
* @param cbExternalData size of the external data
* @param perr  location to return errors
* @return result of the operation.
*/

bool COSE_Sign0_SetExternal(HCOSE_SIGN0 hcose, const byte * pbExternalData, size_t cbExternalData, cose_errback * perr)
{
	if (!IsValidSign0Handle(hcose)) {
		if (perr != NULL) perr->err = COSE_ERR_INVALID_HANDLE;
		return false;
	}

	return _COSE_SetExternal(&((COSE_Sign0Message *)hcose)->m_message, pbExternalData, cbExternalData, perr);
}

bool COSE_Sign0_Sign(HCOSE_SIGN0 h, const cn_cbor * pKey, cose_errback * perr)
{
#ifdef USE_CBOR_CONTEXT
	// cn_cbor_context * context = NULL;
#endif
	COSE_Sign0Message * pMessage = (COSE_Sign0Message *)h;
	const cn_cbor * pcborProtected;

	if (!IsValidSign0Handle(h)) {
		CHECK_CONDITION(false, COSE_ERR_INVALID_HANDLE);
	errorReturn:
		return false;
	}
#ifdef USE_CBOR_CONTEXT
	//	context = &pMessage->m_message.m_allocContext;
#endif

	pcborProtected = _COSE_encode_protected(&pMessage->m_message, CBOR_CONTEXT_PARAM_COMMA perr);
	if (pcborProtected == NULL) goto errorReturn;

	if (!_COSE_Signer0_sign(pMessage, pKey, perr)) goto errorReturn;

	return true;
}

/** Validates a COSE based on the pKey.
* @param hSign The whole decoded COSE (get by using COSE_Decode() or COSE_Init())
* @param pKey a verification key object containing information about the key.
* @param perr Pointer to user provided COSE error object.
*
* @return
*       true in case of success or false otherwise.
*/

static bool _COSE_Sign0_validate(HCOSE_SIGN0 hSign, const byte *pKey, size_t keySize, cose_errback * perr)
{
    bool f;
    COSE_Sign0Message * pSign;
    const cn_cbor * cnContent;
    const cn_cbor * cnProtected;

    CHECK_CONDITION(IsValidSign0Handle(hSign), COSE_ERR_INVALID_HANDLE);
    CHECK_CONDITION((pKey != NULL), COSE_ERR_INVALID_HANDLE);

    pSign = (COSE_Sign0Message *)hSign;

    cnContent = _COSE_arrayget_int(&pSign->m_message, INDEX_BODY);
    CHECK_CONDITION(cnContent != NULL && cnContent->type == CN_CBOR_BYTES, COSE_ERR_INVALID_PARAMETER);

    cnProtected = _COSE_arrayget_int(&pSign->m_message, INDEX_PROTECTED);
    CHECK_CONDITION(cnProtected != NULL && cnProtected->type == CN_CBOR_BYTES, COSE_ERR_INVALID_PARAMETER);

    f = _COSE_Signer0_validate(pSign, pKey, keySize, perr);

    return f;

errorReturn:
    return false;
}


bool COSE_Sign0_validate_with_cose_key(HCOSE_SIGN0 hSign, const cn_cbor * pKeyCose, cose_errback * perr)
{
    bool status = false;
    byte pKey[1024];
    size_t keySize;

    // Does NULL check for pKeyCose
    status = GetECKeyFromCoseKeyObj(pKeyCose, pKey, sizeof(pKey), &keySize, perr);

    return (status) ? _COSE_Sign0_validate(hSign, pKey, keySize, perr) : status;
}

bool COSE_Sign0_validate_with_raw_pk(HCOSE_SIGN0 hSign, const byte * pKey, size_t keySize, cose_errback * perr)
{
    return _COSE_Sign0_validate(hSign, pKey, keySize, perr);
}


cn_cbor * COSE_Sign0_map_get_int(HCOSE_SIGN0 h, int key, int flags, cose_errback * perror)
{
	if (!IsValidSign0Handle(h)) {
		if (perror != NULL) perror->err = COSE_ERR_INVALID_HANDLE;
		return NULL;
	}

	return _COSE_map_get_int(&((COSE_Sign0Message *)h)->m_message, key, flags, perror);
}

bool COSE_Sign0_map_put_int(HCOSE_SIGN0 h, int key, cn_cbor * value, int flags, CBOR_CONTEXT_COMMA cose_errback * perr)
{
	CHECK_CONDITION(IsValidSign0Handle(h), COSE_ERR_INVALID_HANDLE);
	CHECK_CONDITION(value != NULL, COSE_ERR_INVALID_PARAMETER);

	return _COSE_map_put(&((COSE_Sign0Message *)h)->m_message, key, value, flags, CBOR_CONTEXT_PARAM_COMMA perr);

errorReturn:
	return false;
}


static bool CreateSign0AAD(COSE_Sign0Message * pMessage, byte ** ppbToSign, size_t * pcbToSign, char * szContext, cose_errback * perr)
{
	cn_cbor * pArray = NULL;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context = &pMessage->m_message.m_allocContext;
#endif
	cn_cbor_errback cbor_error;
	cn_cbor * cn = NULL;
	cn_cbor * cn2;
	size_t cbToSign = 0;
    int bytesWritten = 0;
    byte * pbToSign = NULL;

	pArray = cn_cbor_array_create(CBOR_CONTEXT_PARAM_COMMA &cbor_error);
	CHECK_CONDITION_CBOR(pArray != NULL, cbor_error);

	cn = cn_cbor_string_create(szContext, CBOR_CONTEXT_PARAM_COMMA &cbor_error);
	CHECK_CONDITION_CBOR(cn != NULL, cbor_error);
	CHECK_CONDITION_CBOR(cn_cbor_array_append(pArray, cn, &cbor_error), cbor_error);
	cn = NULL;

	cn2 = _COSE_arrayget_int(&pMessage->m_message, INDEX_PROTECTED);
	CHECK_CONDITION(cn2 != NULL, COSE_ERR_INVALID_PARAMETER);

	if ((cn2->length == 1) && (cn2->v.bytes[0] == 0xa0)) cn = cn_cbor_data_create(NULL, 0, CBOR_CONTEXT_PARAM_COMMA &cbor_error);
	else cn = cn_cbor_data_create(cn2->v.bytes, (int)cn2->length, CBOR_CONTEXT_PARAM_COMMA &cbor_error);
	CHECK_CONDITION_CBOR(cn != NULL, cbor_error);
	CHECK_CONDITION_CBOR(cn_cbor_array_append(pArray, cn, &cbor_error), cbor_error);
	cn = NULL;

	cn = cn_cbor_data_create(pMessage->m_message.m_pbExternal, (int) pMessage->m_message.m_cbExternal, CBOR_CONTEXT_PARAM_COMMA &cbor_error);
	CHECK_CONDITION_CBOR(cn != NULL, cbor_error);
	CHECK_CONDITION_CBOR(cn_cbor_array_append(pArray, cn, &cbor_error), cbor_error);
	cn = NULL;

	cn2 = _COSE_arrayget_int(&pMessage->m_message, INDEX_BODY);
	cn = cn_cbor_data_create(cn2->v.bytes, (int)cn2->length, CBOR_CONTEXT_PARAM_COMMA &cbor_error);
	CHECK_CONDITION_CBOR(cn != NULL, cbor_error);
	CHECK_CONDITION_CBOR(cn_cbor_array_append(pArray, cn, &cbor_error), cbor_error);
	cn = NULL;


    cbToSign = cn_cbor_encode_size(pArray);
    CHECK_CONDITION(cbToSign > 0, COSE_ERR_CBOR);
    pbToSign = (byte *)COSE_CALLOC(cbToSign, 1, context);
    CHECK_CONDITION(pbToSign != NULL, COSE_ERR_OUT_OF_MEMORY);
    bytesWritten = cn_cbor_encoder_write(pArray, pbToSign, cbToSign, &cbor_error);
    CHECK_CONDITION(bytesWritten > 0, COSE_ERR_CBOR);

    *ppbToSign = pbToSign;
	*pcbToSign = cbToSign;
	pbToSign = NULL;

	if (cn != NULL) CN_CBOR_FREE(cn);
	if (pArray != NULL) CN_CBOR_FREE(pArray);
	return true;

errorReturn:
	if (pbToSign != NULL) COSE_FREE(pbToSign);
	if (cn != NULL) CN_CBOR_FREE(cn);
	if (pArray != NULL) CN_CBOR_FREE(pArray);
	return false;
}

bool _COSE_Signer0_sign(COSE_Sign0Message * pSigner, const cn_cbor * pKey, cose_errback * perr)
{
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context = &pSigner->m_message.m_allocContext;
#endif
	cn_cbor * pcborBody2 = NULL;
	cn_cbor * pcborProtected2 = NULL;
	cn_cbor * pArray = NULL;
	cn_cbor * cn = NULL;
	size_t cbToSign;
	byte * pbToSign = NULL;
	bool f;
	int alg;

	pArray = cn_cbor_array_create(CBOR_CONTEXT_PARAM_COMMA NULL);
	if (pArray == NULL) {
		if (perr != NULL) perr->err = COSE_ERR_OUT_OF_MEMORY;
	errorReturn:
		if (pcborBody2 != NULL) CN_CBOR_FREE(pcborBody2);
		if (pcborProtected2 != NULL) CN_CBOR_FREE(pcborProtected2);
		if (pArray != NULL) CN_CBOR_FREE(pArray);
		if (pbToSign != NULL) COSE_FREE(pbToSign);
		return false;
	}

	cn = _COSE_map_get_int(&pSigner->m_message, COSE_Header_Algorithm, COSE_BOTH, perr);
	if (cn == NULL) goto errorReturn;

	if (cn->type == CN_CBOR_TEXT) {
		FAIL_CONDITION(COSE_ERR_UNKNOWN_ALGORITHM);
	}
	else {
		CHECK_CONDITION((cn->type == CN_CBOR_UINT || cn->type == CN_CBOR_INT), COSE_ERR_INVALID_PARAMETER);

		alg = (int)cn->v.uint;
	}


	if (!CreateSign0AAD(pSigner, &pbToSign, &cbToSign, "Signature1", perr)) goto errorReturn;

	switch (alg) {
#ifdef USE_ECDSA_SHA_256
	case COSE_Algorithm_ECDSA_SHA_256:
		f = ECDSA_Sign(&pSigner->m_message, INDEX_SIGNATURE+1, pKey, 256, pbToSign, cbToSign, perr);
		break;
#endif

#ifdef USE_ECDSA_SHA_384
	case COSE_Algorithm_ECDSA_SHA_384:
		f = ECDSA_Sign(&pSigner->m_message, INDEX_SIGNATURE+1, pKey, 384, pbToSign, cbToSign, perr);
		break;
#endif

#ifdef USE_ECDSA_SHA_512
	case COSE_Algorithm_ECDSA_SHA_512:
		f = ECDSA_Sign(&pSigner->m_message, INDEX_SIGNATURE+1, pKey, 512, pbToSign, cbToSign, perr);
		break;
#endif
	default:
		FAIL_CONDITION(COSE_ERR_UNKNOWN_ALGORITHM);
	}

	COSE_FREE(pbToSign);
	CN_CBOR_FREE(pArray);

	return f;
}

bool _COSE_Signer0_validate(COSE_Sign0Message * pSign, const byte *pKey, size_t keySize, cose_errback * perr)
{
	byte * pbToSign = NULL;
	int alg;
	const cn_cbor * cn = NULL;
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context = NULL;
#endif
	size_t cbToSign;
	bool fRet = false;

#ifdef USE_CBOR_CONTEXT
	context = &pSign->m_message.m_allocContext;
#endif

	cn = _COSE_map_get_int(&pSign->m_message, COSE_Header_Algorithm, COSE_BOTH, perr);
	if (cn == NULL) goto errorReturn;

	if (cn->type == CN_CBOR_TEXT) {
		FAIL_CONDITION(COSE_ERR_UNKNOWN_ALGORITHM);
	}
	else {
		CHECK_CONDITION((cn->type == CN_CBOR_UINT || cn->type == CN_CBOR_INT), COSE_ERR_INVALID_PARAMETER);

		alg = (int)cn->v.uint;
	}

    //  Build protected headers
    if (!CreateSign0AAD(pSign, &pbToSign, &cbToSign, "Signature1", perr)) goto errorReturn;

    switch (alg) {
#ifdef USE_ECDSA_SHA_256
	case COSE_Algorithm_ECDSA_SHA_256:
		if (!ECDSA_Verify(&pSign->m_message, INDEX_SIGNATURE+1, pKey, keySize, 256, pbToSign, cbToSign, perr)) goto errorReturn;
		break;
#endif

#ifdef USE_ECDSA_SHA_384
	case COSE_Algorithm_ECDSA_SHA_384:
		if (!ECDSA_Verify(&pSign->m_message, INDEX_SIGNATURE+1, pKey, keySize, 384, pbToSign, cbToSign, perr)) goto errorReturn;
		break;
#endif

#ifdef USE_ECDSA_SHA_512
	case COSE_Algorithm_ECDSA_SHA_512:
		if (!ECDSA_Verify(&pSign->m_message, INDEX_SIGNATURE+1, pKey, keySize, 512, pbToSign, cbToSign, perr)) goto errorReturn;
		break;
#endif

	default:
		FAIL_CONDITION(COSE_ERR_UNKNOWN_ALGORITHM);
		break;
	}

	fRet = true;

errorReturn:
	if (pbToSign != NULL) COSE_FREE(pbToSign);

	return fRet;
}
