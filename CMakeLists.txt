cmake_minimum_required(VERSION 3.16 FATAL_ERROR)

project(COCOON VERSION 0.5 LANGUAGES C CXX)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
#set(OPENSSL_USE_STATIC_LIBS TRUE)
#set(TON_USE_ROCKSDB ON)
#set(TDDB_USE_ROCKSDB ON)

# Define the two required variables before including the source code for watching a git repository.
set(PRE_CONFIGURE_FILE "git.cc.in")
set(POST_CONFIGURE_FILE "${CMAKE_CURRENT_BINARY_DIR}/git.cc")
include(git_watcher.cmake)

# Create a library out of the compiled post-configure file.
add_library(git STATIC ${POST_CONFIGURE_FILE})
target_include_directories(git PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
add_dependencies(git check_git)

# Prevent in-source build
get_filename_component(COCOON_REAL_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}" REALPATH)
get_filename_component(COCOON_REAL_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}" REALPATH)

if (COCOON_REAL_BINARY_DIR STREQUAL COCOON_REAL_SOURCE_DIR)
  message("  Out-of-source build should be used to build COCOON.")
  message("  You need to remove the files already created by CMake and")
  message("  rerun CMake from a new directory:")
  message("  rm -rf CMakeFiles CMakeCache.txt")
  message("  mkdir build")
  message("  cd build")
  message("  cmake ..")
  message(FATAL_ERROR "In-source build failed.")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)
set(CMAKE_CXX_EXTENSIONS FALSE)

#BEGIN internal
option(BUILD_SHARED_LIBS "Use \"ON\" to build shared libraries instead of static where it's not specified (not recommended)" OFF)
option(USE_EMSCRIPTEN "Use \"ON\" for config building wasm." OFF)
#END internal

option(COCOON_USE_ASAN "Use \"ON\" to enable AddressSanitizer." OFF)
option(COCOON_USE_TSAN "Use \"ON\" to enable ThreadSanitizer." OFF)
option(COCOON_USE_UBSAN "Use \"ON\" to enable UndefinedBehaviorSanitizer." OFF)
set(COCOON_ARCH "native" CACHE STRING "Architecture, will be passed to -march=")
set(PORTABLE ${COCOON_ARCH} CACHE STRING "ton -march=")

#BEGIN M1 support
EXECUTE_PROCESS( COMMAND uname -m COMMAND tr -d '\n' OUTPUT_VARIABLE ARCHITECTURE )

if ((ARCHITECTURE MATCHES "arm64") AND (CMAKE_SYSTEM_NAME STREQUAL "Darwin") AND
    (CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 13.0)) # only clang 13+ supports cpu=apple-m1
    set(COCOON_ARCH "apple-m1")
endif()
#END M1 support

set(TON_ARCH ${COCOON_ARCH} CACHE STRING "rocksdb -march=")


if (WIN32)
  message("Add wingetopt")
  function(wingetopt_scope)
    set(CMAKE_POLICY_VERSION_MINIMUM "3.10")
    add_subdirectory(third-party/wingetopt EXCLUDE_FROM_ALL)
  endfunction()
  wingetopt_scope()
  set(WINGETOPT_FOUND 1)
endif()

option(USE_COROUTINES "experimental support of coroutines" OFF)
if (USE_COROUTINES)
  if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    set(TD_HAVE_COROUTINES 1)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fcoroutines-ts")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
  endif()
endif()

message("Add cocoon")
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/CMake" ${CMAKE_MODULE_PATH})

# Configure CCache if available
find_program(CCACHE_FOUND ccache)
if (CCACHE_FOUND)
  if (NOT DEFINED CMAKE_C_COMPILER_LAUNCHER AND NOT DEFINED CMAKE_CXX_COMPILER_LAUNCHER)
    message(STATUS "Using ccache")
    set(CMAKE_C_COMPILER_LAUNCHER ccache)
    set(CMAKE_CXX_COMPILER_LAUNCHER ccache)
  endif()
else()
  message(STATUS "Could NOT find ccache")
endif()

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  set(GCC 1)
elseif (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  set(CLANG 1)
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "Intel")
  set(INTEL 1)
elseif (NOT MSVC)
  message(FATAL_ERROR "Compiler isn't supported")
endif()

include(CheckCXXCompilerFlag)

set(CMAKE_THREAD_PREFER_PTHREAD ON)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)

if (NOT ZLIB_FOUND)
  find_package(ZLIB REQUIRED)
else()
  message(STATUS "Using zlib ${ZLIB_LIBRARIES}")
endif()


if (COCOON_ARCH AND NOT MSVC)
  CHECK_CXX_COMPILER_FLAG( "-march=${COCOON_ARCH}" COMPILER_OPT_ARCH_SUPPORTED )
  if (COCOON_ARCH STREQUAL "apple-m1")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mcpu=${COCOON_ARCH}")	
  elseif(COMPILER_OPT_ARCH_SUPPORTED)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=${COCOON_ARCH}")
  elseif(NOT COCOON_ARCH STREQUAL "native")
    message(FATAL_ERROR "Compiler doesn't support arch ${COCOON_ARCH}")
  endif()
endif()
if (THREADS_HAVE_PTHREAD_ARG)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
endif()

set(MEMPROF "" CACHE STRING "Use one of \"ON\", \"FAST\" or \"SAFE\" to enable memory profiling. \
Works under macOS and Linux when compiled using glibc. \
In FAST mode stack is unwinded only using frame pointers, which may fail. \
In SAFE mode stack is unwinded using backtrace function from execinfo.h, which may be very slow. \
By default both methods are used to achieve maximum speed and accuracy")

if (CLANG OR GCC)
  if (MEMPROF)
    check_cxx_compiler_flag(-no-pie CXX_NO_PIE_FLAG)
    if (CXX_NO_PIE_FLAG)
      set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -no-pie")
    elseif (APPLE)
      set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-no_pie")
    endif()
  endif()
endif()

if (MSVC)
  if (CMAKE_CXX_FLAGS_DEBUG MATCHES "/RTC1")
    string(REPLACE "/RTC1" " " CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
  endif()
  add_definitions(-D_SCL_SECURE_NO_WARNINGS -D_CRT_SECURE_NO_WARNINGS)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MP /W4 /wd4100 /wd4127 /wd4324 /wd4456 /wd4457 /wd4458 /wd4505 /wd4702")
elseif (CLANG OR GCC)
  if (GCC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstrong-eval-order=some")
  endif()
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-omit-frame-pointer")
  if (APPLE)
    #use "-Wl,-exported_symbols_list,${CMAKE_CURRENT_SOURCE_DIR}/export_list" for exported symbols
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fvisibility=hidden -Wl,-dead_strip,-x,-S")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -fvisibility=hidden -Wl,-dead_strip,-x,-S")
    # Generate dSYM bundles for proper stack traces with libbacktrace (for Ninja/Make generators)
    if(NOT DSYMUTIL_LINK_CONFIGURED AND NOT CMAKE_GENERATOR MATCHES "Xcode" AND CMAKE_BUILD_TYPE MATCHES "Debug|RelWithDebInfo")
      set(DSYMUTIL_LINK_CONFIGURED TRUE CACHE INTERNAL "dSYM generation configured in linker")
      set(CMAKE_C_LINK_EXECUTABLE "${CMAKE_C_LINK_EXECUTABLE} && dsymutil <TARGET>")
      set(CMAKE_CXX_LINK_EXECUTABLE "${CMAKE_CXX_LINK_EXECUTABLE} && dsymutil <TARGET>")
    endif()
  else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ffunction-sections -fdata-sections")
    if (NOT USE_EMSCRIPTEN)
      set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--gc-sections -Wl,--exclude-libs,ALL")
    endif()
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections")
    if (NOT TON_USE_ASAN AND NOT TON_USE_TSAN AND NOT MEMPROF)
      if (NOT USE_EMSCRIPTEN)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--exclude-libs,ALL")
      endif()
    endif()
  endif()
endif()

if (WIN32)
  add_definitions(-DNTDDI_VERSION=0x06020000 -DWINVER=0x0602 -D_WIN32_WINNT=0x0602 -DNOMINMAX -DUNICODE -D_UNICODE)
endif()
if (CYGWIN)
  add_definitions(-D_DEFAULT_SOURCE=1 -DFD_SETSIZE=4096)
endif()

if (NOT ANDROID) # _FILE_OFFSET_BITS is broken in ndk r15 and r15b and doesn't work prior to Android 7.0
  add_definitions(-D_FILE_OFFSET_BITS=64)
endif()

set(INTERNAL_COMPILE "0")
#BEGIN internal
  add_definitions(-D_INTERNAL_COMPILE=1)
  set(INTERNAL_COMPILE "1")
#END internal

set(TONLIB_COMPILE "0")
#BEGIN tonlib
  add_definitions(-D_TONLIB_COMPILE=1)
  set(TONLIB_COMPILE "1")
#END tonlib

include(AddCXXCompilerFlag)
if (MSVC)
  add_cxx_compiler_flag("/experimental:external /external:anglebrackets /external:W0")
endif()
if (NOT MSVC)
  add_cxx_compiler_flag("-Wall")
  add_cxx_compiler_flag("-Wextra")
endif()

add_cxx_compiler_flag("-Wimplicit-fallthrough=2")
add_cxx_compiler_flag("-Wpointer-arith")
add_cxx_compiler_flag("-Wcast-qual")
add_cxx_compiler_flag("-Wsign-compare")
add_cxx_compiler_flag("-Wduplicated-branches")
add_cxx_compiler_flag("-Wduplicated-cond")
add_cxx_compiler_flag("-Walloc-zero")
add_cxx_compiler_flag("-Wlogical-op")
add_cxx_compiler_flag("-Wno-tautological-compare")
add_cxx_compiler_flag("-Wvla")
add_cxx_compiler_flag("-Wnon-virtual-dtor")
add_cxx_compiler_flag("-Wno-unused-parameter")
add_cxx_compiler_flag("-Wconversion")
add_cxx_compiler_flag("-Wno-sign-conversion")
add_cxx_compiler_flag("-Qunused-arguments")
add_cxx_compiler_flag("-Wno-unused-private-field")
add_cxx_compiler_flag("-Wno-redundant-move")

if (GCC OR CLANG)
  if (CMAKE_BUILD_TYPE MATCHES "RelWithDebInfo")
    # For historical reasons, CMake falls back to -O2 optimization level when CMAKE_BUILD_TYPE is
    # set to RelWithDebInfo.
    add_compile_options(-O3)
  endif()
endif()

#add_cxx_compiler_flag("-Wno-unused-function")
#add_cxx_compiler_flag("-Wno-unused-variable")
#add_cxx_compiler_flag("-Wno-shorten-64-to-32")
#add_cxx_compiler_flag("-Werror")

#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -isystem /usr/include/c++/v1")
if (CLANG)
  #set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
endif()
if (COCOON_USE_ASAN)
  add_cxx_compiler_flag("-fsanitize=address")
  add_definitions(-DTD_USE_ASAN=1)
endif()
if (COCOON_USE_TSAN)
  add_cxx_compiler_flag("-fsanitize=thread")
endif()
if (COCOON_USE_UBSAN)
  add_cxx_compiler_flag("-fsanitize=undefined")
endif()
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=thread")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=undefined")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=leak")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -finstrument-functions")

#Compilation database
set(CMAKE_EXPORT_COMPILE_COMMANDS 1)

function(target_link_libraries_system target)
  set(libs ${ARGN})
  foreach(lib ${libs})
    get_target_property(lib_include_dirs ${lib} INTERFACE_INCLUDE_DIRECTORIES)
    target_include_directories(${target} SYSTEM PUBLIC ${lib_include_dirs})
    target_link_libraries(${target} PUBLIC ${lib})
  endforeach(lib)
endfunction(target_link_libraries_system)

set(TDUTILS_MIME_TYPE OFF CACHE BOOL "Generate mime type conversion")
#add_subdirectory(tdutils)
#add_subdirectory(memprof)
#add_subdirectory(tdactor)
#add_subdirectory(tdnet)
#if (TON_USE_ROCKSDB)
#  option(TDDB_USE_ROCKSDB "Use rockdb" ON)
#endif()
#add_subdirectory(tdtl)
add_subdirectory(tl)
add_subdirectory(cocoon-tl-utils)
#add_subdirectory(http)
#add_subdirectory(crypto)

function(add_isolated_subdir dir)
  set(CMAKE_CXX_FLAGS "")  # scoped only to this function
  add_subdirectory(${dir} EXCLUDE_FROM_ALL)
endfunction()
add_isolated_subdir(ton)
add_subdirectory(tdport)

add_subdirectory(tee)

if (NOT CMAKE_CROSSCOMPILING)
  if (TDUTILS_MIME_TYPE)
    set(TDMIME_AUTO tdmime_auto) 
  endif()
  add_custom_target(prepare_cross_compiling_cocoon DEPENDS tl_generate_common cocoon_tl_generate_common ${TDMIME_AUTO})
endif()

set(COMMON_SOURCE
 runners/BaseRunner.cpp runners/smartcontracts/RootContractConfig.cpp runners/smartcontracts/SmartContract.cpp net/TcpConnection.cpp net/TcpClient.cpp 
 runners/smartcontracts/CocoonWallet.cpp runners/smartcontracts/ProxyContract.cpp runners/smartcontracts/ClientContract.cpp 
 runners/smartcontracts/WorkerContract.cpp runners/helpers/CountTokens.cpp runners/helpers/HttpSender.cpp runners/TonlibWrapper.cpp
 runners/helpers/ValidateRequest.cpp

 boost-http/http.cpp
 boost-http/http-client.cpp
 boost-http/www-form-urlencoded.cpp

 third-party/multipart-parser-c/multipart_parser.c
)

set(JSON_BuildTests OFF CACHE INTERNAL "")
set(JSON_Install OFF CACHE INTERNAL "")
add_subdirectory(third-party/nlohmann-json)
find_package(Boost 1.71 REQUIRED COMPONENTS thread)


set(COMMON_LIBRARIES
  tdutils tdactor tdnet tddb cocoon_tl_api tl_api cocoon-tl-utils tonhttp tonlib tdnet_ported cocoon git nlohmann_json::nlohmann_json Boost::headers Boost::thread
)

add_library(cocoon_common ${COMMON_SOURCE})
target_link_libraries(cocoon_common PUBLIC ${COMMON_LIBRARIES})

add_executable(client-runner 
  runners/ClientRunner.cpp 
  runners/client/ClientProxyConnection.cpp
  runners/client/ClientProxyInfo.cpp
  runners/client/ClientRunner.cpp
  runners/client/ClientRunningRequest.cpp
  )
target_link_libraries(client-runner PRIVATE cocoon_common )
add_executable(proxy-runner 
  runners/ProxyRunner.cpp 
  runners/proxy/OldProxyContract.cpp
  runners/proxy/ProxyClientInfo.cpp
  runners/proxy/ProxyInboundConnection.cpp
  runners/proxy/ProxyInboundClientConnection.cpp
  runners/proxy/ProxyInboundWorkerConnection.cpp
  runners/proxy/ProxyRunner.cpp
  runners/proxy/ProxyRunningRequest.cpp
  runners/proxy/ProxyWorkerConnectionInfo.cpp
  runners/proxy/ProxyWorkerInfo.cpp
  )
target_link_libraries(proxy-runner PRIVATE cocoon_common)
add_executable(worker-runner 
  runners/WorkerRunner.cpp
  runners/worker/WorkerProxyConnection.cpp
  runners/worker/WorkerProxyInfo.cpp
  runners/worker/WorkerRunner.cpp 
  runners/worker/WorkerRunningRequest.cpp
  runners/worker/WorkerUplinkMonitor.cpp
  )
target_link_libraries(worker-runner PRIVATE cocoon_common )
add_executable(key-manager-runner 
  runners/KeyManagerRunner.cpp
  runners/key-manager/KeyManagerRunner.cpp
  )
target_link_libraries(key-manager-runner PRIVATE cocoon_common )
add_executable(encrypt-message 
  runners/EncryptMessage.cpp
  )
target_link_libraries(encrypt-message PRIVATE cocoon_common )

# Sync time utility
add_executable(sync-time runners/utils/sync_time.cpp )
target_link_libraries(sync-time PRIVATE cocoon_common )

# generate cocoon wallet address utility 
add_executable(generate-cocoon-wallet-address runners/utils/generate-cocoon-wallet-address.cpp )
target_link_libraries(generate-cocoon-wallet-address PRIVATE cocoon_common )

add_custom_target(runners DEPENDS client-runner proxy-runner worker-runner key-manager-runner sync-time generate-cocoon-wallet-address)

# Build everything needed for cocoon-launch
set(COCOON_ALL_DEPS runners cocoon-subst router gen-cert)
# Add seal targets only if SGX is available
if(TARGET seal-server)
    list(APPEND COCOON_ALL_DEPS seal-server seal-client)
endif()
add_custom_target(cocoon-all DEPENDS ${COCOON_ALL_DEPS})

# Regression tests for request validation (function calling, structured output)
add_executable(test-validate-request test/test-validate-request.cpp)
target_include_directories(test-validate-request PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test-validate-request PRIVATE cocoon_common)
