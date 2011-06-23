INCLUDE (CheckIncludeFiles)

CHECK_INCLUDE_FILES(event.h _EVENT_H_)
CHECK_INCLUDE_FILES(pcap.h lib_pcap_pcap_h)

ADD_EXECUTABLE( janus
                packet_queue
                janus
                main )

INSTALL( TARGETS janus
         RUNTIME DESTINATION /usr/local/sbin )

SET( CMAKE_C_FLAGS "-O3 -Wall -pedantic ${CMAKE_C_FLAGS}" )

TARGET_LINK_LIBRARIES( janus "-levent -lpcap" )
