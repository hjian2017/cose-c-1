
# COSE-C Implementation 

This project is a C implementation of the IETF CBOR Encoded Message Syntax (COSE).
There are currently two versions of the COSE document that can be read.
The most current work in progress draft can be found on github in the [cose-wg/cose-spec](https://cose-wg.github.io/cose-spec/) project.
The IETF also keeps a copy of the spec in the [COSE WG](https://tools.ietf.org/html/draft-ietf-cose-msg).

## Implementation Details 
* This implementation is a copy of [COSE-C](https://github.com/cose-wg/COSE-C)
* The project is using an implementation of the Concise Binary Object Representation or [CBOR](https://datatracker.ietf.org/doc/rfc7049/).
 There are 2 available implemnations of CBOR:
  * [tinycbor](https://github.com/ARMmbed/tinycbor) project. Provides memory efficient implementation of CBOR.
  * cn-cbor project. Provides performance efficient implementation of CBOR. Has large memory consumption.
  cn-cbor implementation can be found [here](https://github.com/ARMmbed/mbed-cloud-client/tree/master/factory-configurator-client/secsrv-cbor)
* In order to compile COSE library with tinycbor implementation, use **USE_TINY_CBOR** compilation flag.
* Most of current library uses cn-cbor. Functionality that use tinycbor is **Sign0 validate**. Following is list of functions that we've implemented using tinycbor:
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

## Building and Tests

The project has unit tests. They are compiled as part of internal infrastructure that isn't released.
One who would like to compile them, will need to use his own build system.
 
## Restrictions

APIs can be broken in the future.
