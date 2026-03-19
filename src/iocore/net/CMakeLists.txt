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

add_library(
  inknet STATIC
  ALPNSupport.cc
  AsyncSignalEventIO.cc
  BIO_fastopen.cc
  BoringSSLUtils.cc
  Connection.cc
  ConnectionTracker.cc
  EventIO.cc
  YamlSNIConfig.cc
  Net.cc
  NetHandler.cc
  NetVCOptions.cc
  NetAcceptEventIO.cc
  NetVConnection.cc
  PollCont.cc
  ProxyProtocol.cc
  ReadWriteEventIO.cc
  Server.cc
  Socks.cc
  SSLAPIHooks.cc
  SSLCertLookup.cc
  SSLClientCoordinator.cc
  SSLClientUtils.cc
  SSLConfig.cc
  SSLSecret.cc
  SSLDiags.cc
  SSLNetAccept.cc
  SSLNetProcessor.cc
  SSLNetVConnection.cc
  SSLNextProtocolAccept.cc
  SSLNextProtocolSet.cc
  SSLSNIConfig.cc
  SSLStats.cc
  SSLSessionCache.cc
  SSLSessionTicket.cc
  SSLUtils.cc
  OCSPStapling.cc
  TLSBasicSupport.cc
  TLSEventSupport.cc
  TLSCertSwitchSupport.cc
  TLSEarlyDataSupport.cc
  TLSKeyLogger.cc
  TLSSessionResumptionSupport.cc
  TLSSNISupport.cc
  TLSTunnelSupport.cc
  UDPEventIO.cc
  UDPIOEvent.cc
  UnixConnection.cc
  UnixNet.cc
  UnixNetAccept.cc
  UnixNetProcessor.cc
  UnixNetVConnection.cc
  UnixUDPConnection.cc
  UnixUDPNet.cc
  SSLDynlock.cc
  SNIActionPerformer.cc
)
add_library(ts::inknet ALIAS inknet)

if(TS_USE_QUIC)
  add_subdirectory(quic)

  target_sources(
    inknet
    PRIVATE QUICClosedConCollector.cc
            QUICMultiCertConfigLoader.cc
            QUICNet.cc
            QUICNetProcessor.cc
            QUICNetVConnection.cc
            QUICNextProtocolAccept.cc
            QUICPacketHandler.cc
            QUICSupport.cc
  )

  target_link_libraries(inknet PUBLIC quiche::quiche ts::quic)
endif()

if(BUILD_REGRESSION_TESTING OR BUILD_TESTING)
  target_sources(inknet PRIVATE NetVCTest.cc)
endif()

target_compile_options(inknet PUBLIC -Wno-deprecated-declarations)

target_link_libraries(
  inknet
  PUBLIC ts::inkevent
         ts::proxy
         ts::records
         ts::tscore
         OpenSSL::Crypto
         OpenSSL::SSL
         ts::tsapibackend
  PRIVATE ts::tsutil yaml-cpp::yaml-cpp
)

# Is this necessary?
if(TS_USE_LINUX_IO_URING)
  target_link_libraries(inknet PUBLIC ts::inkuring)
endif()

if(TS_USE_BPF_SOCKMAP)
  find_program(CLANG_BPF clang REQUIRED)
  find_program(BPFTOOL bpftool REQUIRED)

  # Generate vmlinux.h from running kernel BTF
  set(BPF_BUILD_DIR "${CMAKE_CURRENT_BINARY_DIR}/bpf")
  file(MAKE_DIRECTORY ${BPF_BUILD_DIR})

  add_custom_command(
    OUTPUT ${BPF_BUILD_DIR}/vmlinux.h
    COMMAND ${BPFTOOL} btf dump file /sys/kernel/btf/vmlinux format c > ${BPF_BUILD_DIR}/vmlinux.h
    COMMENT "Generating vmlinux.h from kernel BTF"
  )

  # Compile BPF program to .o
  add_custom_command(
    OUTPUT ${BPF_BUILD_DIR}/sockmap_tunnel.bpf.o
    COMMAND ${CLANG_BPF} -g -O2 -target bpf -D__TARGET_ARCH_x86 -I${BPF_BUILD_DIR} -I${CMAKE_CURRENT_SOURCE_DIR}/bpf -c
            ${CMAKE_CURRENT_SOURCE_DIR}/bpf/sockmap_tunnel.bpf.c -o ${BPF_BUILD_DIR}/sockmap_tunnel.bpf.o
    DEPENDS bpf/sockmap_tunnel.bpf.c bpf/sockmap_tunnel.h ${BPF_BUILD_DIR}/vmlinux.h
    COMMENT "Compiling BPF program sockmap_tunnel.bpf.c"
  )

  # Generate BPF skeleton header
  add_custom_command(
    OUTPUT ${BPF_BUILD_DIR}/sockmap_tunnel.skel.h
    COMMAND ${BPFTOOL} gen skeleton ${BPF_BUILD_DIR}/sockmap_tunnel.bpf.o > ${BPF_BUILD_DIR}/sockmap_tunnel.skel.h
    DEPENDS ${BPF_BUILD_DIR}/sockmap_tunnel.bpf.o
    COMMENT "Generating BPF skeleton sockmap_tunnel.skel.h"
  )

  # Custom target to ensure skeleton is built before inknet
  add_custom_target(bpf_sockmap_skeleton DEPENDS ${BPF_BUILD_DIR}/sockmap_tunnel.skel.h)

  target_sources(inknet PRIVATE BpfSockmapManager.cc BpfTunnelRegistry.cc BpfTunnelPoller.cc)

  add_dependencies(inknet bpf_sockmap_skeleton)
  target_include_directories(inknet PRIVATE ${BPF_BUILD_DIR})
  target_link_libraries(inknet PRIVATE LibBpf::LibBpf)
endif()

if(BUILD_TESTING)
  # libinknet_stub.cc is need because GNU ld is sensitive to the order of static libraries on the command line, and we have a cyclic dependency between inknet and proxy
  add_executable(
    test_net libinknet_stub.cc NetVCTest.cc unit_tests/test_ProxyProtocol.cc unit_tests/test_SSLSNIConfig.cc
             unit_tests/test_YamlSNIConfig.cc unit_tests/unit_test_main.cc
  )
  # Use link groups to solve circular dependency
  set(LINK_GROUP_LIBS
      ts::logging
      ts::inknet
      ts::inkhostdb
      ts::proxy
      ts::tsapibackend
      ts::inkdns
      ts::http2
      ts::inkcache
      ts::rpcpublichandlers
      ts::overridable_txn_vars
      ts::http
      ts::http_remap
  )
  if(TS_USE_QUIC)
    list(APPEND LINK_GROUP_LIBS quic http3)
  endif()
  if(CMAKE_LINK_GROUP_USING_RESCAN_SUPPORTED OR CMAKE_CXX_LINK_GROUP_USING_RESCAN_SUPPORTED)
    string(JOIN "," LINK_GROUP_LIBS_CSV ${LINK_GROUP_LIBS})
    target_link_libraries(
      test_net PRIVATE Catch2::Catch2WithMain ts::tscore "$<LINK_GROUP:RESCAN,${LINK_GROUP_LIBS_CSV}>" ts::tsutil
                       ts::inkevent libswoc::libswoc
    )
  elseif(APPLE)
    # These linkers already do the equivalent of RESCAN, so there's no support in cmake for it
    # This case is mainly for macOS
    # The reason that the list is different here, is because a careful ordering is necessary to prevent duplicate symbols, which are not allowed on macOS
    target_link_libraries(
      test_net PRIVATE Catch2::Catch2WithMain ts::tscore ts::proxy ts::inknet ts::inkevent libswoc::libswoc
    )
  else()
    # CMake <3.24 does not support LINK_GROUP. Use -Wl,--start-group and -Wl,--end-group manually.
    target_link_libraries(
      test_net
      PRIVATE Catch2::Catch2WithMain
              ts::tscore
              -Wl,--start-group
              ${LINK_GROUP_LIBS}
              -Wl,--end-group
              ts::tsutil
              ts::inkevent
              libswoc::libswoc
    )
  endif()
  if(NOT APPLE)
    target_link_options(test_net PRIVATE -Wl,--allow-multiple-definition)
  endif()
  set(LIBINKNET_UNIT_TEST_DIR "${CMAKE_SOURCE_DIR}/src/iocore/net/unit_tests")
  target_compile_definitions(test_net PRIVATE LIBINKNET_UNIT_TEST_DIR=${LIBINKNET_UNIT_TEST_DIR})
  add_catch2_test(NAME test_net COMMAND test_net)

  if(NOT APPLE)
    # Disable ORD violation caused by double definition inside a stub file libinknet_stub.cc
    # see remap_test_dlopen_leak_suppression.txt for more info.
    set_tests_properties(test_net PROPERTIES ENVIRONMENT "ASAN_OPTIONS=detect_odr_violation=0")
  endif()
endif()

clang_tidy_check(inknet)
