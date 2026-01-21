/** @file

  Mock IOBuffer implementation

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

#include "test_utils/MockIOBuffer.h"

MockIOBuffer::MockIOBuffer(int64_t size_index)
{
  buffer_ = new_MIOBuffer(size_index);
  reader_ = buffer_->alloc_reader();
}

MockIOBuffer::MockIOBuffer(std::string_view data, int64_t size_index) : MockIOBuffer(size_index)
{
  write(data);
}

MockIOBuffer::~MockIOBuffer()
{
  if (buffer_) {
    free_MIOBuffer(buffer_);
  }
}

MockIOBuffer::MockIOBuffer(MockIOBuffer &&other) noexcept : buffer_(other.buffer_), reader_(other.reader_)
{
  other.buffer_ = nullptr;
  other.reader_ = nullptr;
}

MockIOBuffer &
MockIOBuffer::operator=(MockIOBuffer &&other) noexcept
{
  if (this != &other) {
    if (buffer_) {
      free_MIOBuffer(buffer_);
    }
    buffer_       = other.buffer_;
    reader_       = other.reader_;
    other.buffer_ = nullptr;
    other.reader_ = nullptr;
  }
  return *this;
}

int64_t
MockIOBuffer::write(std::string_view data)
{
  return write(data.data(), data.size());
}

int64_t
MockIOBuffer::write(const void *data, int64_t len)
{
  return buffer_->write(data, len);
}

IOBufferReader *
MockIOBuffer::reader()
{
  return reader_;
}

std::string
MockIOBuffer::read_all()
{
  std::string result;
  int64_t     avail = reader_->read_avail();
  if (avail > 0) {
    result.resize(avail);
    reader_->read(result.data(), avail);
  }
  return result;
}

int64_t
MockIOBuffer::available() const
{
  return reader_->read_avail();
}

void
MockIOBuffer::reset()
{
  reader_->consume(reader_->read_avail());
}

// MockIOBufferChain implementation

MockIOBufferChain::MockIOBufferChain(std::string_view data, int64_t block_size)
{
  buffer_ = new_MIOBuffer(BUFFER_SIZE_INDEX_4K);
  reader_ = buffer_->alloc_reader();

  // Write data in chunks to create multiple blocks
  size_t offset = 0;
  while (offset < data.size()) {
    size_t chunk_size = std::min(static_cast<size_t>(block_size), data.size() - offset);
    buffer_->write(data.data() + offset, chunk_size);
    offset += chunk_size;
  }
}

MockIOBufferChain::~MockIOBufferChain()
{
  if (buffer_) {
    free_MIOBuffer(buffer_);
  }
}

IOBufferReader *
MockIOBufferChain::reader()
{
  return reader_;
}

MIOBuffer *
MockIOBufferChain::buffer()
{
  return buffer_;
}
