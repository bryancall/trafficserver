/** @file

    test ink_file.h - file helpers

    @section license License

    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

#include "tscore/ink_file.h"
#include <catch2/catch_test_macros.hpp>

#include <cstring>
#include <unistd.h>

TEST_CASE("ink_file_fd_writestring returns the number of bytes written", "[ink_file]")
{
  int fds[2];
  REQUIRE(pipe(fds) == 0);

  char const *text = "/var/cache 1048576\n";
  int const   len  = static_cast<int>(strlen(text));

  CHECK(ink_file_fd_writestring(fds[1], text) == len);

  char got[64] = {};
  REQUIRE(read(fds[0], got, sizeof(got) - 1) == len);
  CHECK(strcmp(got, text) == 0);

  close(fds[0]);
  close(fds[1]);
}

TEST_CASE("ink_file_fd_writestring writes nothing for an empty or null string", "[ink_file]")
{
  int fds[2];
  REQUIRE(pipe(fds) == 0);

  CHECK(ink_file_fd_writestring(fds[1], "") == 0);
  CHECK(ink_file_fd_writestring(fds[1], nullptr) == 0);

  close(fds[0]);
  close(fds[1]);
}

TEST_CASE("ink_file_fd_writestring returns -1 when the write fails", "[ink_file]")
{
  int fds[2];
  REQUIRE(pipe(fds) == 0);

  // The read end of a pipe is not open for writing.
  CHECK(ink_file_fd_writestring(fds[0], "text") == -1);

  close(fds[0]);
  close(fds[1]);
}
