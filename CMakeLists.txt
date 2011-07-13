CMAKE_MINIMUM_REQUIRED( VERSION 2.8 )

PROJECT( janus )

SET(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/modules/")

ADD_SUBDIRECTORY( src )

INSTALL( FILES doc/janus.1
         DESTINATION man/man1
         PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ )

# begin uninstall target
CONFIGURE_FILE(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY
)

ADD_CUSTOM_TARGET(
    uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake
)
# end of uninstall target
