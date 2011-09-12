IF("${CMAKE_SYSTEM_NAME}" MATCHES "Linux")
    SET(TUN "tun/tun-linux")
ELSEIF("${CMAKE_SYSTEM_NAME}" MATCHES "FreeBSD")
    SET(TUN "tun/tun-freebsd")
ELSEIF("${CMAKE_SYSTEM_NAME}" MATCHES "Darwin")
    SET(TUN "tun/tun-freebsd")
ELSE()
    MESSAGE(FATAL_ERROR "${CMAKE_SYSTEM_NAME} OS not tested yet, MAY require a system dependent tunnel implementation")
ENDIF("${CMAKE_SYSTEM_NAME}" MATCHES "Linux")

ADD_EXECUTABLE(
    janus
    packet_queue
    os_cmds
    ${TUN}
    janus
    main
)

SET( PACKAGELIST PCAP EVENT )

FOREACH( PACKAGE ${PACKAGELIST} )

    FIND_PACKAGE( ${PACKAGE} REQUIRED )
    MESSAGE( "${PACKAGE}: FOUND" )
    SET( HAVE_LIB${PACKAGE} 1 )
    INCLUDE_DIRECTORIES( ${${PACKAGE}_INCLUDE_DIRS} )
    TARGET_LINK_LIBRARIES( janus ${${PACKAGE}_LIBRARY} )
    MESSAGE( STATUS "${PACKAGE} includes: ${${PACKAGE}_INCLUDE_DIRS}" )
    MESSAGE( STATUS "${PACKAGE} libs: ${${PACKAGE}_LIBRARIES}" )

ENDFOREACH(PACKAGE ${PACKAGELIST})

SET( CMAKE_C_FLAGS "-g3 -O3 -Wall -pedantic ${CMAKE_C_FLAGS}" )

CONFIGURE_FILE(config.h.in config.h)

INSTALL(
    TARGETS janus
    RUNTIME DESTINATION /usr/local/sbin
)
