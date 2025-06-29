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
    /// Internal context for Pkcs11Slot class
    /// </summary>
    internal class Pkcs11SlotContext
    {
        /// <summary>
        /// High level PKCS#11 slot
        /// </summary>
        internal ISlot Slot { get; }

        /// <summary>
        /// Detailed information about PKCS#11 slot
        /// </summary>
        internal Pkcs11SlotInfo SlotInfo { get; }

        /// <summary>
        /// Internal context for Pkcs11X509Store class
        /// </summary>
        internal Pkcs11X509StoreContext StoreContext { get; }

        /// <summary>
        /// Creates new instance of Pkcs11SlotContext class
        /// </summary>
        /// <param name="slot">High level PKCS#11 slot</param>
        /// <param name="slotInfo">Detailed information about PKCS#11 slot</param>
        /// <param name="storeContext">Internal context for Pkcs11X509Store class</param>
        internal Pkcs11SlotContext(ISlot slot, Pkcs11SlotInfo slotInfo, Pkcs11X509StoreContext storeContext)
        {
            Slot = slot ?? throw new ArgumentNullException(nameof(slot));
            SlotInfo = slotInfo ?? throw new ArgumentNullException(nameof(slotInfo));
            StoreContext = storeContext ?? throw new ArgumentNullException(nameof(storeContext));
        }
    }
}
