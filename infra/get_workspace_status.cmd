:: Copyright 2024 EngFlow Inc. All rights reserved.
::
:: Licensed under the Apache License, Version 2.0 (the "License");
:: you may not use this file except in compliance with the License.
:: You may obtain a copy of the License at
::
::    http://www.apache.org/licenses/LICENSE-2.0
::
:: Unless required by applicable law or agreed to in writing, software
:: distributed under the License is distributed on an "AS IS" BASIS,
:: WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
:: See the License for the specific language governing permissions and
:: limitations under the License.

:: The variables defined here are available not only in BES logs, but also for
:: stamping into built binaries (version information, etc.). Removing vars or
:: changing var names may break these version stamping libraries; if this script
:: is updated, also make sure the following are up-to-date:
::
:: - //internal/buildstamp/BUILD

@echo off

for /F %%x in ('git rev-parse --abbrev-ref HEAD') do echo BUILD_SCM_BRANCH %%x
for /F %%x in ('git rev-parse --verify HEAD') do echo BUILD_SCM_REVISION %%x

echo STABLE_BUILD_RELEASE_VERSION %BUILD_RELEASE_VERSION%

git diff-index --quiet HEAD --
if %ERRORLEVEL% == 0 (
  echo BUILD_SCM_STATUS clean
) else (
  echo BUILD_SCM_STATUS modified
)

for /F %%x in ('git remote get-url origin') do set REMOTE_URL=%%x
if %ERRORLEVEL% == 0 (
  echo BUILD_SCM_REMOTE %REMOTE_URL%
)