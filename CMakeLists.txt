cmake_minimum_required ( VERSION 2.8 )

project ( flood )
set_property ( GLOBAL PROPERTY USE_FOLDERS ON )

set ( CMAKE_C_STANDARD 99 )
set ( CMAKE_CXX_STANDARD 11 )

set ( CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/$<CONFIG> )
set ( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/$<CONFIG> )

add_executable(flood
  flood.cpp
)

if ( CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows" )
  target_link_libraries ( flood PUBLIC ws2_32 )
else ()
  target_link_libraries ( flood PUBLIC pthread )
endif ()
