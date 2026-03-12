cmake_minimum_required(VERSION 3.5)
PROJECT (FSS)

# Platform-specific compiler flags
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|i686|i386")
    # x86/x64: Enable AES-NI instructions
    set(PLATFORM_FLAGS "-maes")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64|ARM64")
    # ARM64: AES cryptographic extensions are always available on Apple Silicon
    # No special flags needed - the AES instructions are part of ARMv8-A
    set(PLATFORM_FLAGS "")
else()
    message(WARNING "Unknown platform: ${CMAKE_SYSTEM_PROCESSOR}")
    set(PLATFORM_FLAGS "")
endif()

# Find OpenSSL
if(APPLE)
    # Try Homebrew OpenSSL first
    if(EXISTS "/opt/homebrew/opt/openssl@3")
        set(OPENSSL_ROOT_DIR "/opt/homebrew/opt/openssl@3")
    elseif(EXISTS "/usr/local/opt/openssl@3")
        set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl@3")
    elseif(EXISTS "/opt/homebrew/opt/openssl")
        set(OPENSSL_ROOT_DIR "/opt/homebrew/opt/openssl")
    elseif(EXISTS "/usr/local/opt/openssl")
        set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl")
    endif()
endif()

find_package(OpenSSL REQUIRED)

ADD_EXECUTABLE(fss utils.c block.c)
TARGET_COMPILE_OPTIONS(fss PUBLIC ${PLATFORM_FLAGS})
TARGET_INCLUDE_DIRECTORIES(fss PRIVATE ${OPENSSL_INCLUDE_DIR})
TARGET_LINK_LIBRARIES(fss OpenSSL::SSL OpenSSL::Crypto)

ADD_EXECUTABLE(fssgen fssgen.c block.c b64.c)
TARGET_COMPILE_OPTIONS(fssgen PUBLIC ${PLATFORM_FLAGS})
TARGET_INCLUDE_DIRECTORIES(fssgen PRIVATE ${OPENSSL_INCLUDE_DIR})
TARGET_LINK_LIBRARIES(fssgen OpenSSL::SSL OpenSSL::Crypto)

ADD_EXECUTABLE(fsseval fsseval.c block.c b64.c)
TARGET_COMPILE_OPTIONS(fsseval PUBLIC ${PLATFORM_FLAGS})
TARGET_INCLUDE_DIRECTORIES(fsseval PRIVATE ${OPENSSL_INCLUDE_DIR})
TARGET_LINK_LIBRARIES(fsseval OpenSSL::SSL OpenSSL::Crypto)