// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;

// Copied from corefx/src/System.Security.Cryptography.X509Certificates/src/Internal/Cryptography/Helpers.cs
//
// This is a temporary solution until we have cleaned up the System.Security / monotouch_watch problem.
// See "Code Aquamarine": https://github.com/mono/mono/pull/9665.

namespace Internal.Cryptography.Private
{
    internal static class Helpers
    {
        public static byte[] CloneByteArray(this byte[] src)
        {
            if (src == null)
            {
                return null;
            }

            return (byte[])(src.Clone());
        }

        // Encode a byte array as an array of upper-case hex characters.
        public static char[] ToHexArrayUpper(this byte[] bytes)
        {
            char[] chars = new char[bytes.Length * 2];
            int i = 0;
            foreach (byte b in bytes)
            {
                chars[i++] = NibbleToHex((byte)(b >> 4));
                chars[i++] = NibbleToHex((byte)(b & 0xF));
            }
            return chars;
        }

        // Encode a byte array as an upper case hex string.
        public static string ToHexStringUpper(this byte[] bytes)
        {
            return new string(ToHexArrayUpper(bytes));
        }

        private static char NibbleToHex(byte b)
        {
            Debug.Assert(b >= 0 && b <= 15);
            return (char)(b >= 0 && b <= 9 ? 
                '0' + b : 
                'A' + (b - 10));
        }
    }
}
