﻿/*
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
using Net.Pkcs11Interop.HighLevelAPI;

namespace Net.Pkcs11Interop.X509Store
{
    /// <summary>
    /// Detailed information about PKCS#11 based X.509 store
    /// </summary>
    public class Pkcs11X509StoreInfo
    {
        /// <summary>
        /// Name of or path to PKCS#11 library
        /// </summary>
        public string LibraryPath { get; }

        /// <summary>
        /// PKCS#11 library version
        /// </summary>
        public string LibraryVersion { get; }

        /// <summary>
        /// Manufacturer of PKCS#11 library
        /// </summary>
        public string Manufacturer { get; }

        /// <summary>
        /// Description of PKCS#11 library
        /// </summary>
        public string Description { get; }

        /// <summary>
        /// Creates new instance of Pkcs11X509StoreInfo class
        /// </summary>
        /// <param name="libraryPath">Name of or path to PKCS#11 library</param>
        /// <param name="libraryInfo">General information about PKCS#11 library (CK_INFO)</param>
        internal Pkcs11X509StoreInfo(string libraryPath, ILibraryInfo libraryInfo)
        {
            if (string.IsNullOrEmpty(libraryPath))
                throw new ArgumentNullException(nameof(libraryPath));

            if (libraryInfo == null)
                throw new ArgumentNullException(nameof(libraryInfo));

            LibraryPath = libraryPath;
            LibraryVersion = libraryInfo.LibraryVersion;
            Manufacturer = libraryInfo.ManufacturerId;
            Description = libraryInfo.LibraryDescription;
        }
    }
}
