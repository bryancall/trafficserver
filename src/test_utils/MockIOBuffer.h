/** @file

  Mock IOBuffer utilities for unit testing

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

#pragma once

#include "iocore/eventsystem/IOBuffer.h"
#include <string>
#include <string_view>

/**
 * @class MockIOBuffer
 * @brief Helper class for creating and managing IOBuffers in tests
 *
 * Simplifies the creation and manipulation of IOBuffers for unit testing.
 * Handles proper allocation and cleanup.
 *
 * Usage:
 * @code
 * MockIOBuffer buf("test data");
 * IOBufferReader *reader = buf.reader();
 * // ... use reader in tests ...
 * @endcode
 */
class MockIOBuffer
{
public:
  /**
   * Create an empty MockIOBuffer
   * @param size_index Buffer size index (default: BUFFER_SIZE_INDEX_4K)
   */
  explicit MockIOBuffer(int64_t size_index = BUFFER_SIZE_INDEX_4K);

  /**
   * Create a MockIOBuffer with initial data
   * @param data Initial data to write to the buffer
   * @param size_index Buffer size index (default: BUFFER_SIZE_INDEX_4K)
   */
  MockIOBuffer(std::string_view data, int64_t size_index = BUFFER_SIZE_INDEX_4K);

  ~MockIOBuffer();

  // Non-copyable
  MockIOBuffer(const MockIOBuffer &)            = delete;
  MockIOBuffer &operator=(const MockIOBuffer &) = delete;

  // Movable
  MockIOBuffer(MockIOBuffer &&other) noexcept;
  MockIOBuffer &operator=(MockIOBuffer &&other) noexcept;

  /**
   * Write data to the buffer
   * @param data Data to write
   * @return Number of bytes written
   */
  int64_t write(std::string_view data);

  /**
   * Write data to the buffer
   * @param data Pointer to data
   * @param len Length of data
   * @return Number of bytes written
   */
  int64_t write(const void *data, int64_t len);

  /**
   * Get a reader for this buffer
   * @return Pointer to IOBufferReader (owned by the MIOBuffer)
   */
  IOBufferReader *reader();

  /**
   * Get the underlying MIOBuffer
   * @return Pointer to MIOBuffer
   */
  MIOBuffer *
  buffer()
  {
    return buffer_;
  }

  /**
   * Read all available data as a string
   * @return String containing all data in the buffer
   */
  std::string read_all();

  /**
   * Get the number of bytes available to read
   */
  int64_t available() const;

  /**
   * Reset the buffer (clear all data)
   */
  void reset();

private:
  MIOBuffer      *buffer_ = nullptr;
  IOBufferReader *reader_ = nullptr;
};

/**
 * @class MockIOBufferChain
 * @brief Helper for creating multi-block IOBuffer chains for testing
 *
 * Useful for testing code that handles data spanning multiple IOBuffer blocks.
 */
class MockIOBufferChain
{
public:
  /**
   * Create a chain with data split across multiple blocks
   * @param data Data to write
   * @param block_size Maximum size per block
   */
  MockIOBufferChain(std::string_view data, int64_t block_size);

  ~MockIOBufferChain();

  IOBufferReader *reader();
  MIOBuffer      *buffer();

private:
  MIOBuffer      *buffer_ = nullptr;
  IOBufferReader *reader_ = nullptr;
};
