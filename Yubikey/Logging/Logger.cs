// Copyright 2021 Yubico AB
//
// Licensed under the Apache License, Version 2.0 (the "License").
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System;

namespace Yubico.Core.Logging
{
    /// <summary>
    /// A concrete logger implementation used by Yubico .NET-based libraries.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This class builds on top of the standard <see cref="ILogger"/> interface used by the Microsoft.Extensions logging
    /// library. This is a meta-library for interoperating with different concrete logging implementations such as NLog,
    /// Serilog, or .NET's built in EventPipe system.
    /// </para>
    /// <para>
    /// Methods for logging potentially sensitive information are present. These methods are disabled for Release builds,
    /// resulting in a no-op for anything other than a Debug build of this library.
    /// </para>
    /// <para>
    /// Extension methods can be used to add further conveniences to the logging interface. For example, if you wanted to
    /// log a platform error code in a uniform way, you could introduce a `LogPlatformError` extension that takes care of
    /// formatting the error and calling one of the existing log methods.
    /// </para>
    /// </remarks>
    public sealed class Logger { 

        internal Logger()
        {
   
        }

        internal void LogInformation(string v) {
           
        }
    }
}
