#
#  top level build file for COSE-C
#

## prepare CMAKE
cmake_minimum_required(VERSION 2.6)

# includes
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/cose-c)

FILE(
	GLOB_RECURSE  
	cose

	"${CMAKE_CURRENT_SOURCE_DIR}/cose-c/*.h"
	"${CMAKE_CURRENT_SOURCE_DIR}/source/cbor.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/source/Cose.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/source/Sign0.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/source/Sign.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/source/SignerInfo.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/source/mbedtls.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/source/MacMessage0.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/source/MacMessage.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/source/Encrypt0.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/source/Encrypt.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/source/bcrypt.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/source/Recipient.c"
)

message ("*********************************************************************")
message ("cose = [[${cose}]]")
message ("*********************************************************************")

CREATE_LIBRARY(cose "${cose}" "")
ADDSUBDIRS()
