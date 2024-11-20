namespace Hyperar.OAuthCore.Testing
{
    #region License

    // The MIT License
    //
    // Copyright (c) 2006-2008 DevDefined Limited.
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

    #endregion License

    using System;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using Hyperar.OAuthCore.Framework;
    using Hyperar.OAuthCore.Storage;

    public class TestConsumerStore : IConsumerStore
    {
        public AsymmetricAlgorithm GetConsumerPublicKey(IConsumer consumer)
        {
            RSA? publicKey = TestCertificates.OAuthTestCertificate().GetRSAPublicKey() ?? throw new NullReferenceException("GetRSAPubclicKey");

            ArgumentNullException.ThrowIfNull(publicKey);

            return publicKey;
        }

        public string GetConsumerSecret(IOAuthContext consumer)
        {
            return "secret";
        }

        public bool IsConsumer(IConsumer consumer)
        {
            return consumer.ConsumerKey == "key" && string.IsNullOrEmpty(consumer.Realm);
        }

        public void SetConsumerCertificate(IConsumer consumer, X509Certificate2 certificate)
        {
            throw new NotImplementedException();
        }

        public void SetConsumerSecret(IConsumer consumer, string consumerSecret)
        {
            throw new NotImplementedException();
        }
    }
}