/** @file

  Test Event Processor - Controllable event loop for unit testing

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

#include "iocore/eventsystem/EventSystem.h"
#include "iocore/eventsystem/EThread.h"
#include "iocore/eventsystem/Tasks.h"

#include <atomic>

/**
 * @class TestEventProcessor
 * @brief A simplified event processor for unit testing
 *
 * This class provides a controllable event loop that can be used in unit tests
 * without requiring the full ATS event system infrastructure. It supports:
 *
 * - Single-threaded event processing
 * - Synchronous event dispatch for deterministic testing
 * - IOBuffer operations without network I/O
 *
 * Usage:
 * @code
 * TestEventProcessor ep;
 * ep.start();
 * // ... run tests ...
 * ep.stop();
 * @endcode
 */
class TestEventProcessor
{
public:
  TestEventProcessor();
  ~TestEventProcessor();

  /**
   * Start the test event processor
   * Initializes minimal infrastructure needed for IOBuffer operations
   */
  void start();

  /**
   * Stop the test event processor
   * Cleans up all resources
   */
  void stop();

  /**
   * Check if the event processor is running
   */
  bool
  is_running() const
  {
    return running_.load();
  }

  /**
   * Get the event processor singleton
   * Ensures only one test event processor is active
   */
  static TestEventProcessor *instance();

private:
  std::atomic<bool> running_{false};
  static TestEventProcessor *instance_;
};

/**
 * @class TestEventProcessorScope
 * @brief RAII wrapper for TestEventProcessor
 *
 * Automatically starts the event processor on construction and stops on destruction.
 *
 * Usage:
 * @code
 * TEST_CASE("my test") {
 *   TestEventProcessorScope ep_scope;
 *   // Event processor is now running
 *   // ... test code ...
 * } // Event processor automatically stopped
 * @endcode
 */
class TestEventProcessorScope
{
public:
  TestEventProcessorScope() { ep_.start(); }
  ~TestEventProcessorScope() { ep_.stop(); }

  TestEventProcessorScope(const TestEventProcessorScope &)            = delete;
  TestEventProcessorScope &operator=(const TestEventProcessorScope &) = delete;

private:
  TestEventProcessor ep_;
};
