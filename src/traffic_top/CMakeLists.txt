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

add_executable(traffic_top traffic_top.cc ${CMAKE_SOURCE_DIR}/src/shared/rpc/IPCSocketClient.cc)
target_include_directories(traffic_top PRIVATE ${CURSES_INCLUDE_DIRS})
target_link_libraries(traffic_top PRIVATE ts::tscore ts::inkevent libswoc::libswoc ${CURSES_LIBRARIES})
install(TARGETS traffic_top)

clang_tidy_check(traffic_top)

if(BUILD_TESTING)
  add_executable(test_traffic_top_stats unit_tests/test_stats.cc ${CMAKE_SOURCE_DIR}/src/shared/rpc/IPCSocketClient.cc)
  target_link_libraries(
    test_traffic_top_stats PRIVATE ts::tscore ts::inkevent libswoc::libswoc yaml-cpp::yaml-cpp Catch2::Catch2WithMain
  )
  add_catch2_test(NAME test_traffic_top_stats COMMAND $<TARGET_FILE:test_traffic_top_stats>)
endif()
