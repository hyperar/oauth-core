﻿// The MIT License
//
// Copyright (c) 2024 Hyperar.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

namespace Hyperar.OAuthCore.Consumer
{
    using System;
    using System.Diagnostics;
    using System.IO;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;

    public class LocalFileCertificateFactory : ICertificateFactory
    {
        private readonly string _filename;

        private readonly string _password;

        /// <summary>
        /// Initializes a new instance of the <see cref="LocalFileCertificateFactory"/> class.
        /// </summary>
        /// <param name="filename">The filename.</param>
        /// <param name="password">The password.</param>
        public LocalFileCertificateFactory(string filename, string password)
        {
            this._filename = filename;
            this._password = password;

            if (!File.Exists(filename))
            {
                throw new FileNotFoundException("The certificate file could not be located on disk.", filename);
            }

            if (this.CreateCertificate() == null)
            {
                throw new ApplicationException("The certificate could not be loaded from disk.");
            }
        }

        /// <summary>
        /// Creates the certificate.
        /// </summary>
        /// <returns></returns>
        public X509Certificate2? CreateCertificate()
        {
            if (!File.Exists(this._filename))
            {
                return null;
            }

            try
            {
                X509Certificate2 certificate = new X509Certificate2(this._filename, this._password);
                Debug.Assert(certificate.Subject != string.Empty);
                return certificate;
            }
            catch (CryptographicException)
            {
                return null;
            }
        }

        /// <summary>
        /// Counts the matching certificates.
        /// </summary>
        /// <returns></returns>
        public int GetMatchingCertificateCount()
        {
            return this.CreateCertificate() != null ? 1 : 0;
        }
    }
}