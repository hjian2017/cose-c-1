
# COSE-C implementation 

This project is a C implementation of the IETF CBOR Encoded Message Syntax (COSE).
There are two separate versions of the COSE documentation:
* The most current work in progress draft can be found on github in the [cose-wg/cose-spec](https://cose-wg.github.io/cose-spec/) project.
* The IETF also keeps a copy of the spec in the [COSE WG](https://tools.ietf.org/html/draft-ietf-cose-msg).

## Implementation details 
* This implementation is a copy of [COSE-C](https://github.com/cose-wg/COSE-C).
* The project is using an implementation of the Concise Binary Object Representation or [CBOR](https://datatracker.ietf.org/doc/rfc7049/).
 There are two CBOR implementations available:
  * [tinycbor](https://github.com/ARMmbed/tinycbor) project. Provides memory efficient implementation of CBOR.
  * cn-cbor project. Provides performance efficient implementation of CBOR. Has large memory consumption.
  cn-cbor implementation can be found [here](https://github.com/ARMmbed/mbed-cloud-client/tree/master/factory-configurator-client/secsrv-cbor)
* To compile COSE library with tinycbor implementation, use **USE_TINY_CBOR** compilation flag.
* Most of current library uses cn-cbor. Functionality that is available for tinycbor is `Sign0 validate` **only**. Following is list of functions that we've implemented using tinycbor:
  * `COSE_Init_tiny()` - same functionality as `COSE_Init()`, but uses tinycbor instead of cn-cbor.
  * `COSE_Sign0_validate_with_raw_pk_tiny()` - same functionality as `COSE_Sign0_validate_with_raw_pk()`, but uses tinycbor instead of cn-cbor.
  * `GetECKeyFromCoseBuffer()` - same functionality as `GetECKeyFromCoseKeyObj()`, but uses tinycbor instead of cn-cbor.
  * `COSE_Sign0_validate_with_cose_key_buffer()` - same functionality as `COSE_Sign0_validate_with_cose_key()`, but uses tinycbor instead of cn-cbor.
  * `COSE_Sign0_Free()` - implemented both using tinycbor and cn-cbor
* One that compiles this library will also need **mbed-client-pal** and **mbedtls** libraries:
  * mbed-client-pal - platform abstraction layer that is used in Mbed Cloud Client and can be found [here](https://github.com/ARMmbed/mbed-cloud-client/tree/master/mbed-client-pal)
  * mbedtls - cryptographic library that can found [here](https://github.com/ARMmbed/mbedtls) or as part of Mbed OS delivery.
 
## Contributing

Go ahead, file issues, make pull requests.

## Building and tests

* The project includes unit tests. They are compiled as part of the internal infrastructure that isn't released.  
  If you want to compile them, you need to use your own build system.
* The tests only checks the `Sign0 validate` functionality. 
* If you are using the **USE_TINY_CBOR** compilation flag, the tests are compiled with the tinycbor implementation.   
  Without the flag, they are compiled using the cn-cbor.

 
## Restrictions

APIs can be broken in the future.
