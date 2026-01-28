cmake_minimum_required(VERSION 3.15)

project(coreSNTP LANGUAGES C)

# ------------------------------------------------------------------------------
# Includes
# ------------------------------------------------------------------------------

include(${CMAKE_CURRENT_LIST_DIR}/coreSntpFilePaths.cmake)

# ------------------------------------------------------------------------------
# Library targets
# ------------------------------------------------------------------------------

add_library(core_sntp INTERFACE)

target_sources(core_sntp INTERFACE ${CORE_SNTP_SOURCES})

target_include_directories(core_sntp INTERFACE ${CORE_SNTP_INCLUDE_PUBLIC_DIRS})

message(STATUS "core_sntp library requires SNTP_DO_NOT_USE_CUSTOM_CONFIG definition or a core_sntp_config.h file.")
