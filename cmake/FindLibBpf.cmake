#######################
#
#  Licensed to the Apache Software Foundation (ASF) under one or more contributor license
#  agreements.  See the NOTICE file distributed with this work for additional information regarding
#  copyright ownership.  The ASF licenses this file to you under the Apache License, Version 2.0
#  (the "License"); you may not use this file except in compliance with the License.  You may obtain
#  a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
#  or implied. See the License for the specific language governing permissions and limitations under
#  the License.
#
#######################

# FindLibBpf.cmake - Find libbpf library
#
# This module finds the libbpf library and defines:
#   LIBBPF_FOUND       - True if libbpf was found
#   LIBBPF_INCLUDE_DIRS - Include directories for libbpf
#   LIBBPF_LIBRARIES   - Libraries to link against
#   LIBBPF_VERSION     - Version of libbpf found

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
  pkg_check_modules(PC_LIBBPF QUIET libbpf)
endif()

find_path(
  LIBBPF_INCLUDE_DIR
  NAMES bpf/libbpf.h
  HINTS ${PC_LIBBPF_INCLUDE_DIRS}
  PATH_SUFFIXES include
)

find_library(
  LIBBPF_LIBRARY
  NAMES bpf
  HINTS ${PC_LIBBPF_LIBRARY_DIRS}
  PATH_SUFFIXES lib lib64
)

if(PC_LIBBPF_VERSION)
  set(LIBBPF_VERSION ${PC_LIBBPF_VERSION})
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
  LibBpf
  REQUIRED_VARS LIBBPF_LIBRARY LIBBPF_INCLUDE_DIR
  VERSION_VAR LIBBPF_VERSION
)

if(LIBBPF_FOUND)
  set(LIBBPF_LIBRARIES ${LIBBPF_LIBRARY})
  set(LIBBPF_INCLUDE_DIRS ${LIBBPF_INCLUDE_DIR})

  if(NOT TARGET LibBpf::LibBpf)
    add_library(LibBpf::LibBpf UNKNOWN IMPORTED)
    set_target_properties(
      LibBpf::LibBpf PROPERTIES IMPORTED_LOCATION "${LIBBPF_LIBRARY}" INTERFACE_INCLUDE_DIRECTORIES
                                                                      "${LIBBPF_INCLUDE_DIR}"
    )
  endif()
endif()

mark_as_advanced(LIBBPF_INCLUDE_DIR LIBBPF_LIBRARY)
