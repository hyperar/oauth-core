// The MIT License
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
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// Creates X509 certificates from the Local Computer certificate sture based on the certificate subject.
    /// </summary>
    public class LocalMachineCertificateFactory : ICertificateFactory
    {
        private readonly string _certificateSubject;

        private readonly X509FindType _findType;

        /// <summary>
        /// Initializes a new instance of the <see cref="LocalMachineCertificateFactory"/> class.
        /// </summary>
        /// <param name="certificateSubject">The certificate subject.</param>
        /// <param name="findType"></param>
        public LocalMachineCertificateFactory(string certificateSubject, X509FindType findType)
        {
            this._certificateSubject = certificateSubject;
            this._findType = findType;

            ServicePointManager.ServerCertificateValidationCallback = RemoteCertificateValidationCallback;
        }

        /// <summary>
        /// Creates the certificate.
        /// </summary>
        /// <returns></returns>
        public X509Certificate2? CreateCertificate()
        {
            X509Certificate2Collection certificateCollection = this.GetCertificateCollection();
            return certificateCollection.Count > 0 ? certificateCollection[0] : null;
        }

        /// <summary>
        /// Counts the matching certificates.
        /// </summary>
        /// <returns></returns>
        public int GetMatchingCertificateCount()
        {
            return this.GetCertificateCollection().Count;
        }

        /// <summary>
        /// Remotes the certificate validation callback.
        /// </summary>
        /// <param name="sender">The sender.</param>
        /// <param name="certificate">The certificate.</param>
        /// <param name="chain">The chain.</param>
        /// <param name="sslPolicyErrors">The SSL policy errors.</param>
        /// <returns></returns>
        public static bool RemoteCertificateValidationCallback(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }

        /// <summary>
        /// Gets the certificate collection.
        /// </summary>
        /// <returns></returns>
        private X509Certificate2Collection GetCertificateCollection()
        {
            X509Store certStore = new X509Store("My", StoreLocation.LocalMachine);
            certStore.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            X509Certificate2Collection certificateCollection = certStore.Certificates.Find(this._findType, this._certificateSubject, false);
            certStore.Close();

            return certificateCollection;
        }
    }
}