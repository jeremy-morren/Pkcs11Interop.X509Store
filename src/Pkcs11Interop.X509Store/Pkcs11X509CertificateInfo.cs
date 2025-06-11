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
using System.Security.Cryptography.X509Certificates;
using Net.Pkcs11Interop.Common;

namespace Net.Pkcs11Interop.X509Store
{
    /// <summary>
    /// Detailed information about X.509 certificate stored on PKCS#11 token
    /// </summary>
    public class Pkcs11X509CertificateInfo
    {
        /// <summary>
        /// Hex encoded identifier of PKCS#11 certificate object (value of CKA_ID attribute)
        /// </summary>
        public string Id { get; }

        /// <summary>
        /// Label of PKCS#11 certificate object (value of CKA_LABEL attribute)
        /// </summary>
        public string Label { get; }

        /// <summary>
        /// DER encoded value of X.509 certificate (value of CKA_VALUE attribute)
        /// </summary>
        public byte[] RawData { get; }

        /// <summary>
        /// X.509 certificate parsed as System.Security.Cryptography.X509Certificates.X509Certificate2 instance for convenience
        /// </summary>
        public X509Certificate2 ParsedCertificate { get; }

        /// <summary>
        /// Type of certified asymmetric key
        /// </summary>
        public AsymmetricKeyType KeyType { get; }

        /// <summary>
        /// Creates new instance of Pkcs11X509CertificateInfo class
        /// </summary>
        /// <param name="ckaId">Value of CKA_ID attribute</param>
        /// <param name="ckaLabel">Value of CKA_LABEL attribute</param>
        /// <param name="ckaValue">Value of CKA_VALUE attribute</param>
        internal Pkcs11X509CertificateInfo(byte[] ckaId, string ckaLabel, byte[] ckaValue)
        {
            Id = ConvertUtils.BytesToHexString(ckaId);
            Label = ckaLabel;
            RawData = ckaValue ?? throw new ArgumentNullException(nameof(ckaValue));
            ParsedCertificate = new X509Certificate2(RawData);

            switch (ParsedCertificate.PublicKey.Oid.Value)
            {
                case "1.2.840.113549.1.1.1":
                    KeyType = AsymmetricKeyType.RSA;
                    break;
                case "1.2.840.10045.2.1":
                    KeyType = AsymmetricKeyType.EC;
                    break;
                default:
                    KeyType = AsymmetricKeyType.Other;
                    break;
            }
        }
    }
}
