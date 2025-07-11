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
    GIT_TAG v1.1.0
)
FetchContent_MakeAvailable(Crow)

find_package(mongocxx REQUIRED)
find_package(bsoncxx REQUIRED)

add_executable(Pegra main.cpp)

target_link_libraries(Pegra 
    PUBLIC 
    Crow::Crow 
    mongo::mongocxx_shared
    mongo::bsoncxx_shared
)
