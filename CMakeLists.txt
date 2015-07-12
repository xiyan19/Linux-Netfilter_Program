cmake_minimum_required(VERSION 3.2)
project(Linux-Netfilter_Program)

include_directories(/usr/local/include)
link_directories(/usr/local/lib)

set(SOURCE_FILES ${PROJECT_SOURCE_DIR}/src/Application/main.c)

add_executable(Linux_Netfilter_Program ${SOURCE_FILES})

target_link_libraries(Linux_Netfilter_Program -lnetfilter_queue)