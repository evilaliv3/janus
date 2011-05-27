ADD_EXECUTABLE( janus
                packet_queue
                janus
                main )

INSTALL( TARGETS janus
         RUNTIME DESTINATION /usr/local/sbin )

SET( CMAKE_C_FLAGS "-O3 -Wall -g3 -pedantic ${CMAKE_C_FLAGS}" )

TARGET_LINK_LIBRARIES( janus "-levent" )
