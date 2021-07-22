# Include filepaths for source and include.
include( ${MODULE_ROOT_DIR}/coreSntpFilePaths.cmake )

# Target for Coverity analysis that builds the library.
add_executable( code_example_posix
                example_sntp_client_posix.c )

# Add coreSNTP library public include path.
target_link_libraries( code_example_posix
                        coverity_analysis )