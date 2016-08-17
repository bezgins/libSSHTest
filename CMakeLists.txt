project(libSSHTest)
cmake_minimum_required(VERSION 2.8)

aux_source_directory(. SRC_LIST)
add_executable(${PROJECT_NAME} ${SRC_LIST})

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

if(WIN32)
    set(CMAKE_INCLUDE_PATH ${CMAKE_INCLUDE_PATH} "C:/Devel/libssh-0.7.2/include/")
    set(CMAKE_LIBRARY_PATH ${CMAKE_LIBRARY_PATH} "C:/Devel/libssh-0.7.2/lib/")
    set(BOOST_ROOT "C:/Devel/boost_1_46_1/lib")
    set(BOOST_LIBRARYDIR "C:/Devel/boost_1_46_1/lib/lib")
endif()

SET(Boost_USE_STATIC_LIBS ON)

find_package(LibSSH REQUIRED)

if (!LIBSSH_FOUND)
        message(STATUS "LIBSSH_not found!!!!")
endif (!LIBSSH_FOUND)


include_directories(${LIBSSH_INCLUDE_DIRS})
set(LIBS ${LIBS} ${LIBSSH_LIBRARIES})

find_package(Boost REQUIRED COMPONENTS
             thread)

if(Boost_FOUND)
  include_directories(${Boost_INCLUDE_DIRS})
  set(LIBS ${LIBS} ${Boost_LIBRARIES})
endif()


target_link_libraries(${PROJECT_NAME} ${LIBS})

if(WIN32)
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${PROJECT_SOURCE_DIR}/lib"
            $<TARGET_FILE_DIR:${PROJECT_NAME}>)
endif()
