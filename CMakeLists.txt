cmake_minimum_required(VERSION 2.6)

PROJECT(ucentral-event C)

ADD_DEFINITIONS(-Wall -Werror)
ADD_DEFINITIONS(-Wextra -Werror=implicit-function-declaration)
ADD_DEFINITIONS(-Wformat -Werror=format-security -Werror=format-nonliteral)
ADD_DEFINITIONS(-Os -std=gnu99 -g3 -Wmissing-declarations -Wno-unused-parameter)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
SET(SOURCES main.c)

FIND_LIBRARY(ubus NAMES ubus)
FIND_LIBRARY(uci NAMES uci)
FIND_LIBRARY(ubox NAMES ubox)
FIND_LIBRARY(blobmsg_json NAMES blobmsg_json)

FIND_PATH(ubox_include_dir libubox/uloop.h)
FIND_PATH(ubus_include_dir NAMES libubus.h)
FIND_PATH(uci_include_dir NAMES uci.h)

INCLUDE_DIRECTORIES(${ubox_include_dir} ${ubus_include_dir} ${uci_include_dir})
ADD_EXECUTABLE(ucentral-event ${SOURCES})
TARGET_LINK_LIBRARIES(ucentral-event ${ubox} ${ubus} ${blobmsg_json} ${uci})

INSTALL(TARGETS ucentral-event
	RUNTIME DESTINATION sbin
)
