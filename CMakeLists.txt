project(libSSHTest)
cmake_minimum_required(VERSION 2.8)

aux_source_directory(. SRC_LIST)
add_executable(${PROJECT_NAME} ${SRC_LIST})

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

set(CMAKE_INCLUDE_PATH ${CMAKE_INCLUDE_PATH} "C:/Devel/libssh-0.7.2/include/")
set(CMAKE_LIBRARY_PATH ${CMAKE_LIBRARY_PATH} "C:/Devel/libssh-0.7.2/lib/")


find_package(LibSSH REQUIRED)

if (!LIBSSH_FOUND)
        message(STATUS "LIBSSH_not found!!!!")
endif (!LIBSSH_FOUND)


include_directories(${LIBSSH_INCLUDE_DIRS})
set(LIBS ${LIBS} ${LIBSSH_LIBRARIES})

target_link_libraries(${PROJECT_NAME} ${LIBS})

add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        "${PROJECT_SOURCE_DIR}/lib"
        $<TARGET_FILE_DIR:${PROJECT_NAME}>)
