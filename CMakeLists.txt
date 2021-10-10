cmake_minimum_required(VERSION 3.8 FATAL_ERROR)

project(boost-coroutines-example LANGUAGES CXX)

add_executable(server "server.cpp" "socks5.hpp" "socks5.cpp")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(
    Boost 1.76 REQUIRED
    COMPONENTS
    chrono
    context
    log
    system
    thread
    coroutine
)

# thread support
set(THREADS_PREFER_PTHERAD_FLAG ON)
find_package(Threads REQUIRED)

target_link_libraries(server PRIVATE Boost::system)
target_link_libraries(server PUBLIC Boost::headers)
target_link_libraries(server PUBLIC Boost::log)
target_link_libraries(server PUBLIC Boost::coroutine)
target_link_libraries(server PRIVATE Threads::Threads)
