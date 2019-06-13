/** @file

  Interface for class to allow rollback of configuration files

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

#include "tscore/ink_mutex.h"
#include "tscore/List.h"

class FileManager;
class TextBuffer;

class ExpandingArray;

//
//  class Rollback
//
//  public functions
//
//  checkForUserUpdate() - compares the last known modification time
//    of the active version of the file with that files current modification
//    time.  Returns true if the file has been changed manually or false
//    if it hasn't
//
// private functions
//
//  statFile(struct stat*) - a wrapper for stat(), using layout engine
//
class Rollback
{
public:
  // fileName_ should be rooted or a base file name.
  Rollback(const char *fileName_, const char *configName_, bool root_access_needed, Rollback *parentRollback);
  ~Rollback();

  // Manual take out of lock required
  void
  acquireLock()
  {
    ink_mutex_acquire(&fileAccessLock);
  };

  void
  releaseLock()
  {
    ink_mutex_release(&fileAccessLock);
  };

  // Check if a file has changed, automatically holds the lock. Used by FileManager.
  bool checkForUserUpdate();

  // These are getters, for FileManager to get info about a particular configuration.
  const char *
  getFileName() const
  {
    return fileName;
  }

  const char *
  getConfigName() const
  {
    return configName;
  }

  bool
  isChildRollback() const
  {
    return parentRollback != nullptr;
  }

  Rollback *
  getParentRollback() const
  {
    return parentRollback;
  }

  bool
  rootAccessNeeded() const
  {
    return root_access_needed;
  }

  FileManager *configFiles = nullptr; // Manager to notify on an update.

  // noncopyable
  Rollback(const Rollback &) = delete;
  Rollback &operator=(const Rollback &) = delete;

private:
  int statFile(struct stat *buf);

  ink_mutex fileAccessLock;
  char *fileName;
  char *configName;
  bool root_access_needed;
  Rollback *parentRollback;
  time_t fileLastModified = 0;
};