/*
 *  Copyright 2017-2025 The Pkcs11Interop Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 *  Written for the Pkcs11Interop project by:
 *  Jaroslav IMRICH <jimrich@jimrich.sk>
 */

using System;
using System.Security.Cryptography;

namespace Net.Pkcs11Interop.X509Store
{
    internal static class HashAlgorithmUtils
    {
        /// <summary>
        /// Creates a hash algorithm instance based on the provided HashAlgorithmName,
        /// or throws an exception if the name is invalid or not supported.
        /// </summary>
        internal static HashAlgorithm CreateHashAlgorithm(HashAlgorithmName hashAlgorithm)
        {
            if (string.IsNullOrEmpty(hashAlgorithm.Name))
                throw new ArgumentException("Hash algorithm name is required", nameof(hashAlgorithm));

            var hashAlg = HashAlgorithm.Create(hashAlgorithm.Name);
            if (hashAlg == null)
                throw new NotSupportedException($"Hash algorithm '{hashAlgorithm.Name}' is not a valid hash algorithm");
            return hashAlg;
        }
    }
}