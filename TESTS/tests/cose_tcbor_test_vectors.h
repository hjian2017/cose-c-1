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

// Test vectors based on https://github.com/cose-wg/Examples/blob/master/sign1-tests

#include <stdint.h>

///////////// POSITIVES ///////////////



char sign_pass_buffer_01[] = "{" \
"\"title\" : \"sign - pass - 01: Redo protected\","\
"\"input\" : {"\
"\"plaintext\":\"This is the content.\","\
"\"sign0_buffer\" : {"\
"\"key\":{"\
"\"kty\":\"EC\","\
"\"kid\" :\"11\","\
"\"crv\" :\"P-256\","\
"\"x\" :\"usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8\","\
"\"y\" :\"IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4\","\
"\"d\" :\"V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM\""\
"},"\
"\"unprotected\":{"\
"\"kid\":\"11\","\
"\"alg\" :\"ES256\""\
"},"\
"\"alg\" :\"ES256\""\
"},"\
"\"failures\":{"\
"\"ChangeProtected\":\"a0\""\
"},"\
"\"rng_description\" :\"seed for signature\""\
"},"\
"\"intermediates\":{"\
"\"ToBeSign_hex\":\"846A5369676E617475726531404054546869732069732074686520636F6E74656E742E\""\
"},"\
"\"output\" : {"\
"\"cbor_diag\":\"18([h'A0', { 1: -7, 4 : h'3131' }, h'546869732069732074686520636F6E74656E742E', h'87DB0D2E5571843B78AC33ECB2830DF7B6E0A4D5B7376DE336B23C591C90C425317E56127FBE04370097CE347087B233BF722B64072BEB4486BDA4031D27244F'])\","\
"\"cbor\" :\"D28441A0A201260442313154546869732069732074686520636F6E74656E742E584087DB0D2E5571843B78AC33ECB2830DF7B6E0A4D5B7376DE336B23C591C90C425317E56127FBE04370097CE347087B233BF722B64072BEB4486BDA4031D27244F\""\
"}"\
"}";

char sign_pass_buffer_02[] = "{" \
"\"title\":\"sign-pass-02: External\","\
"\"input\" : {"\
"\"plaintext\":\"This is the content.\","\
"\"sign0_buffer\" : {"\
"\"key\":{"\
"\"kty\" : \"EC\","\
"\"kid\" : \"11\","\
"\"crv\" : \"P-256\","\
"\"x\" : \"usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8\","\
"\"y\" : \"IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4\","\
"\"d\" : \"V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM\""\
"},"\
"\"unprotected\":{"\
"\"kid\":\"11\""\
"},"\
"\"protected\" : {"\
"\"alg\":\"ES256\""\
"},"\
"\"alg\" : \"ES256\","\
"\"external\" : \"11aa22bb33cc44dd55006699\""\
"},"\
"\"rng_description\":\"seed for signature\""\
"},"\
"\"intermediates\":{"\
"\"ToBeSign_hex\":\"846A5369676E61747572653143A101264C11AA22BB33CC44DD5500669954546869732069732074686520636F6E74656E742E\""\
"},"\
"\"output\" : {"\
"\"cbor_diag\":\"18([h'A10126', {4: h'3131'}, h'546869732069732074686520636F6E74656E742E', h'10729CD711CB3813D8D8E944A8DA7111E7B258C9BDCA6135F7AE1ADBEE9509891267837E1E33BD36C150326AE62755C6BD8E540C3E8F92D7D225E8DB72B8820B'])\","\
"\"cbor\" : \"D28443A10126A10442313154546869732069732074686520636F6E74656E742E584010729CD711CB3813D8D8E944A8DA7111E7B258C9BDCA6135F7AE1ADBEE9509891267837E1E33BD36C150326AE62755C6BD8E540C3E8F92D7D225E8DB72B8820B\""\
"}"\
"}";

char sign_pass_buffer_03[] = "{" \
"\"title\":\"sign-pass-03: Remove CBOR Tag\","\
"\"input\" : {"\
"\"plaintext\":\"This is the content.\","\
"\"sign0_buffer\" : {"\
"\"key\":{"\
"\"kty\":\"EC\","\
"\"kid\" : \"11\","\
"\"crv\" : \"P-256\","\
"\"x\" : \"usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8\","\
"\"y\" : \"IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4\","\
"\"d\" : \"V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM\""\
"},"\
"\"unprotected\":{"\
"\"kid\":\"11\""\
"},"\
"\"protected\" : {"\
"\"alg\":\"ES256\""\
"},"\
"\"alg\" : \"ES256\""\
"},"\
"\"failures\":{"\
"\"RemoveCBORTag\":1"\
"},"\
"\"rng_description\" : \"seed for signature\""\
"},"\
"\"intermediates\":{"\
"\"ToBeSign_hex\":\"846A5369676E61747572653143A101264054546869732069732074686520636F6E74656E742E\""\
"},"\
"\"output\" : {"\
"\"cbor_diag\":\"[h'A10126', {4: h'3131'}, h'546869732069732074686520636F6E74656E742E', h'8EB33E4CA31D1C465AB05AAC34CC6B23D58FEF5C083106C4D25A91AEF0B0117E2AF9A291AA32E14AB834DC56ED2A223444547E01F11D3B0916E5A4C345CACB36']\","\
"\"cbor\" : \"8443A10126A10442313154546869732069732074686520636F6E74656E742E58408EB33E4CA31D1C465AB05AAC34CC6B23D58FEF5C083106C4D25A91AEF0B0117E2AF9A291AA32E14AB834DC56ED2A223444547E01F11D3B0916E5A4C345CACB36\""\
"}"\
"}";

