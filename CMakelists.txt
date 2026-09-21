cmake_minimum_required(VERSION 3.15)
project(fowl)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Force custom output folder
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin/x64/")

# OPENSSL check for Windows
if(WIN32)
    set(OPENSSL_ROOT_DIR "C:/Program Files/OpenSSL-Win64" CACHE PATH "Path to OpenSSL on windows.")
    # MSVC runtime linking library configuration
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDebugDLL")
endif()

# OpenSSL for linux
find_package(OpenSSL REQUIRED)

# -------------------------------------------------------------------
# FIX: Explicitly name your source files so CMake internal files are ignored
# -------------------------------------------------------------------
set(SOURCES
    "src/main.cpp"
    # Add any other local .cpp files here, separated by spaces or new lines
)

set(HEADERS
    # Add your .h or .hpp files here if you have any
)
# -------------------------------------------------------------------

add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})
target_link_libraries(${PROJECT_NAME} PRIVATE OpenSSL::SSL OpenSSL::Crypto)


