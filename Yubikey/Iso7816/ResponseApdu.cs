﻿// Copyright 2021 Yubico AB
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
using System.Globalization;
using System.Linq;

namespace Yubico.Core.Iso7816 {
    /// <summary>
    /// Represents an ISO 7816 application response.
    /// </summary>
    public class ResponseApdu
    {
        /// <summary>
        /// The status word (two byte) code which represents the overall result of a CCID interaction.
        /// The most common value is 0x9000 which represents a successful result.
        /// </summary>
        public short SW => (short)((SW1 << 8) | SW2);

        /// <summary>
        /// A convenience property accessor for the high byte of SW
        /// </summary>
        public byte SW1 { get; private set; }

        /// <summary>
        /// A convenience property accessor for the low byte of SW
        /// </summary>
        public byte SW2 { get; private set; }

        /// <summary>
        /// Gets the data part of the response.
        /// </summary>
        /// <value>
        /// The raw bytes not including the ending status word.
        /// </value>
        public ReadOnlyMemory<byte> Data { get; private set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="ResponseApdu"/> class.
        /// </summary>
        /// <param name="data">The raw data returned by the ISO 7816 smart card.</param>
        public ResponseApdu(byte[] data)
        {
            if (data is null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            if (data.Length < 2)
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, ExceptionMessages.ResponseApduNotEnoughBytes, data.Length));
            }

            SW1 = data[data.Length-2];
            SW2 = data[data.Length-1];
            Data = data.Take(data.Length - 2).ToArray();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ResponseApdu"/> class.
        /// </summary>
        /// <param name="dataWithoutSW">The raw data returned by the ISO 7816 smart card without the
        /// trailing status bytes.</param>
        /// <param name="sw">The status word, 'SW', for the APDU response.</param>
        public ResponseApdu(byte[] dataWithoutSW, short sw)
        {
            if (dataWithoutSW is null)
            {
                throw new ArgumentNullException(nameof(dataWithoutSW));
            }

            SW1 = (byte)(sw >> 8);
            SW2 = (byte)(sw & 0xFF);
            Data = dataWithoutSW.ToArray();
        }
    }
}
