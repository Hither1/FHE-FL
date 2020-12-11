# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.12)

project(MKHE VERSION 3.6.0 LANGUAGES CXX)

# If not called from root CMakeLists.txt
if(NOT DEFINED SEAL_BUILD_EXAMPLES)
    set(SEAL_BUILD_EXAMPLES ON)

    # Import Microsoft SEAL
    find_package(SEAL 3.6.0 EXACT REQUIRED)

    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)
endif()

if(SEAL_BUILD_EXAMPLES)
    add_executable(MKHE
            ModelProvider.cpp ModelProvider.h encryptor_mk.cpp Server.cpp Server.h)

    target_sources(MKHE
            PRIVATE
            ${CMAKE_CURRENT_LIST_DIR}/main.cpp
            ${CMAKE_CURRENT_LIST_DIR}/PublicParameter.cpp
            ${CMAKE_CURRENT_LIST_DIR}/Session.cpp
            ${CMAKE_CURRENT_LIST_DIR}/User.cpp
            ${CMAKE_CURRENT_LIST_DIR}/encryptor_mk.cpp
            )

    if(TARGET SEAL::seal)
        target_link_libraries(MKHE PRIVATE SEAL::seal)
    elseif(TARGET SEAL::seal_shared)
        target_link_libraries(MKHE PRIVATE SEAL::seal_shared)
    else()
        message(FATAL_ERROR "Cannot find target SEAL::seal or SEAL::seal_shared")
    endif()
endif()
