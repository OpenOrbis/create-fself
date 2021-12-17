cmake_minimum_required(VERSION 3.0)

project(CreateFself)

set(CMAKE_VERBOSE_MAKEFILE ON)

if(WIN32)
add_custom_target (
    OUTPUT ALL
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/scripts
    COMMAND build.bat
    COMMENT "Building win32 create-fself"
)
else()
add_custom_target(
    OUTPUT ALL
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/scripts
    COMMAND build.sh
    COMMENT "Building other create-fself"
)
endif()
