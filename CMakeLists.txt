cmake_minimum_required(VERSION 3.17)
project(wsmail)

set(CMAKE_CXX_STANDARD 14)

find_package(OpenSSL REQUIRED)

set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} "-Wa,-mbig-obj -static-libgcc -static-libstdc++")

set(Boost_INCLUDE_DIR C:\\Users\\C_Camilleri\\Documents\\SDKs\\boost_1_76_0\\)
set(Boost_LIBRARY_DIR C:\\Users\\C_Camilleri\\Documents\\SDKs\\boost_1_76_0\\lib\\)
find_package(Boost)

message("* openssl " ${OPENSSL_LIBRARIES})

add_executable(wsmail main.cpp utils.h base64.cpp base64.h)
target_link_libraries(wsmail wsock32 ws2_32 ${OPENSSL_LIBRARIES})
include_directories(${Boost_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR})
target_include_directories(wsmail PRIVATE websocketpp)
