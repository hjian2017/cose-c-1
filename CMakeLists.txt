#
#  top level build file for COSE-C
#

## prepare CMAKE
cmake_minimum_required(VERSION 2.6)

# includes
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/cose-c)

FILE(
	GLOB_RECURSE  
	cose-c

	"${CMAKE_CURRENT_SOURCE_DIR}/cose-c/*.h"
	"${CMAKE_CURRENT_SOURCE_DIR}/source/*.c"
)

message ("*********************************************************************")
message ("cose-c = [[${cose-c}]]")
message ("*********************************************************************")

CREATE_LIBRARY(cose-c "${cose-c}" "")
ADDSUBDIRS()
