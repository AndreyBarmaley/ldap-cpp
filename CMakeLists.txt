cmake_minimum_required(VERSION 3.6)

project(ldap-cpp
    VERSION 20180427
    LANGUAGES CXX
    DESCRIPTION "OpenLDAP C++ API wrapper")

option(BUILD_SHARED_LIBS "Set to OFF to build static library" ON)
option(BUILD_EXAMPLES "Build test binaries in the example/ directory")

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED true)
set(CMAKE_EXPORT_COMPILE_COMMANDS true)
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g -pedantic")

set(LDAP_CPP_LIBRARY_NAME ldapc++)
set(EXTERNAL_LIBRARIES ldap lber)

set(PUBLIC_HEADER_FILES
    cldap.h
    cldap_mod.h
    cldap_entry.h
    cldap_server.h
    cldap_types.h
    )

find_library(${EXTERNAL_LIBRARIES} REQUIRED)

file(GLOB SOURCE_FILES LIST_DIRECTORIES false *.cpp)
add_library(${LDAP_CPP_LIBRARY_NAME} ${SOURCE_FILES})
target_compile_options(${LDAP_CPP_LIBRARY_NAME} PRIVATE ${EXTRA_CFLAGS})
target_link_libraries(${LDAP_CPP_LIBRARY_NAME} ${EXTERNAL_LIBRARIES})

include(GNUInstallDirs)

if(BUILD_SHARED_LIBS)
    # install just the shared library
    install(TARGETS ${LDAP_CPP_LIBRARY_NAME}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  )
else()
    # install static library plus header files
    set_target_properties(${LDAP_CPP_LIBRARY_NAME}
        PROPERTIES PUBLIC_HEADER "${PUBLIC_HEADER_FILES}")
    install(TARGETS ${LDAP_CPP_LIBRARY_NAME}
       LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
       PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${LDAP_CPP_LIBRARY_NAME}
)
endif()

if(BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()
