cmake_minimum_required(VERSION 3.26)
project(ASCON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXE_LINKER_FLAGS "-static")

add_executable(ASCON
        ascon-util.cpp
        ascon-util.h
        ascon128.h
        ascon128.cpp
        ascon80pq.h
        ascon80pq.cpp
        ascon-hash.h
        ascon-hash.cpp
        ascon.h
        ascon128a.h
        ascon128a.cpp
        ascon-hasha.h
        ascon-hasha.cpp
        main.cpp
)
