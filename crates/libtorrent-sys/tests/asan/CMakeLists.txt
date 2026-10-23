# The shim and its ownership cases, linked by the C++ driver against the
# instrumented libtorrent prefix.sh provisions. run.sh configures this with
# that prefix on CMAKE_PREFIX_PATH; it is not a standalone project.
cmake_minimum_required(VERSION 3.16)
project(libtorrent_shim_asan LANGUAGES C CXX)

# libtorrent's package config finds Boost, which prefix.sh installed with its
# own BoostConfig.cmake; NEW reads that rather than CMake's retired FindBoost.
if(POLICY CMP0167)
    cmake_policy(SET CMP0167 NEW)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(SHIM_ASAN_FLAGS "-fsanitize=address -fno-omit-frame-pointer"
    CACHE STRING "Sanitizer flags for the shim and the test, as libtorrent was built with")
separate_arguments(shim_asan_flags UNIX_COMMAND "${SHIM_ASAN_FLAGS}")

# The imported target carries libtorrent's PUBLIC compile definitions, the
# same list build.rs reads out of this package for the cargo build, so the
# shim sees the class layouts the archive was compiled with. It also brings
# OpenSSL and Threads.
find_package(LibtorrentRasterbar REQUIRED CONFIG)

# Every translation unit in shim/, not a list kept here: build.rs's
# SHIM_SOURCES is the list cargo compiles, and a copy would drift from it.
get_filename_component(SHIM_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../shim" ABSOLUTE)
file(GLOB SHIM_SOURCES CONFIGURE_DEPENDS "${SHIM_DIR}/*.cpp")

add_executable(shim_asan shim_asan.cpp ${SHIM_SOURCES})
target_include_directories(shim_asan PRIVATE "${SHIM_DIR}")
target_compile_definitions(shim_asan PRIVATE _GLIBCXX_USE_CXX11_ABI=1)
target_compile_options(shim_asan PRIVATE ${shim_asan_flags} -Wno-deprecated-declarations)
# Warnings are errors in the test only: the shim's own units are compiled
# with build.rs's flags, which do not make them errors either.
set_source_files_properties(shim_asan.cpp PROPERTIES COMPILE_OPTIONS "-Wall;-Wextra;-Werror")
target_link_options(shim_asan PRIVATE ${shim_asan_flags})
target_link_libraries(shim_asan PRIVATE LibtorrentRasterbar::torrent-rasterbar)
