cmake_minimum_required(VERSION 3.2)
project(Linux_Netfilter_Program)

# Import extra kernel src: linux-3.18.17!!!
include_directories([BEFORE] /root/linux-3.18.17/include/)

set(SOURCE_FILES
    src/myhook.c)

add_executable(Linux_Netfilter_Program ${SOURCE_FILES})