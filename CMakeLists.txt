cmake_minimum_required(VERSION 3.15)
project(pegra_capital_backend)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

if(POLICY CMP0167)
  cmake_policy(SET CMP0167 NEW)
endif()

include(FetchContent)

FetchContent_Declare(Crow
    GIT_REPOSITORY https://github.com/CrowCpp/Crow.git
    GIT_TAG v1.2.1
)
FetchContent_MakeAvailable(Crow)

FetchContent_Declare(
    jwt-cpp
    GIT_REPOSITORY https://github.com/Thalhammer/jwt-cpp.git
    GIT_TAG v0.6.0
)
FetchContent_MakeAvailable(jwt-cpp)

FetchContent_Declare(
  curl
  GIT_REPOSITORY https://github.com/curl/curl.git
  GIT_TAG        curl-8_8_0  # You can change this to a newer tag
)
FetchContent_MakeAvailable(curl)

find_package(mongocxx REQUIRED)
find_package(bsoncxx REQUIRED)
find_package(LibXml2 REQUIRED)

add_executable(Pegra
    src/main.cpp
    src/db/connect.cpp
    src/routes/scrapeRoute.cpp

    third_party/bcrypt/bcrypt.c
    third_party/bcrypt/crypt_blowfish/wrapper.c
    third_party/bcrypt/crypt_blowfish/crypt_blowfish.c
    third_party/bcrypt/crypt_blowfish/crypt_gensalt.c
)

target_include_directories(Pegra PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/bcrypt
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/bcrypt/crypt_blowfish
)

target_link_libraries(Pegra
    PUBLIC
    Crow::Crow
    mongo::mongocxx_shared
    mongo::bsoncxx_shared
    jwt-cpp::jwt-cpp
    libcurl
    LibXml2::LibXml2
)
