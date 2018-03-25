#
#  top level build file for COSE-C
#

## prepare CMAKE
cmake_minimum_required(VERSION 2.6)

# COSE_TESTS_ENABLED is an environment variable.
# define "COSE_TESTS_ENABLED" only if you would like to build COSE unit-tests.
# By default, COSE_TESTS_ENABLED is NOT defined, meaning COSE's tests are disabled and compiled out. 

if(NOT DEFINED ENV{COSE_TESTS_ENABLED})
	return()
endif()


# PAL's example code reference
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../mbed-client-pal/Test/Unitest/Includes)

# includes
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../cose-c)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../unity)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/runner/cose_runner)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/tests)

set(TARGET_NAME "cose_tests$ENV{BINARY_SUFFIX}")
# tests includes
FILE(
	GLOB_RECURSE
	cose_tests_src

	"${CMAKE_CURRENT_SOURCE_DIR}/runner/cose_main/*.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/runner/cose_main/*.cpp"
	"${CMAKE_CURRENT_SOURCE_DIR}/runner/cose_main/*.h"

	"${CMAKE_CURRENT_SOURCE_DIR}/runner/cose_runner/*.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/runner/cose_runner/*.cpp"
	"${CMAKE_CURRENT_SOURCE_DIR}/runner/cose_runner/*.h"

	"${CMAKE_CURRENT_SOURCE_DIR}/tests/*.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/tests/*.cpp"
	"${CMAKE_CURRENT_SOURCE_DIR}/tests/*.h"

	${CMAKE_CURRENT_SOURCE_DIR}/../../mbed-client-pal/Test/Unitest/TestRunner/pal_test${OS_BRAND}.c
)

message ("*********************************************************************")
message ("cose_tests_src = [[${cose_tests_src}]]")
message ("*********************************************************************")

CREATE_TEST_LIBRARY(${TARGET_NAME} "${cose_tests_src}" "")
ADDSUBDIRS()
