namespace Hyperar.OAuthCore.UnitTest.Provider.Inspectors
{
    using System.Security.Cryptography.X509Certificates;
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

    using Hyperar.OAuthCore.Framework;
    using Hyperar.OAuthCore.Framework.Signing;
    using Hyperar.OAuthCore.Provider.Inspectors;
    using Hyperar.OAuthCore.Storage;
    using Hyperar.OAuthCore.Testing;
    using Rhino.Mocks;

    [TestClass]
    public class SignatureValidationInspectorTests
    {
        [TestMethod]
        public void InvalidSignatureThrows()
        {
            var repository = new MockRepository();

            var consumerStore = repository.DynamicMock<IConsumerStore>();
            var signer = repository.StrictMock<IOAuthContextSigner>();

            var context = new OAuthContext { ConsumerKey = "key", SignatureMethod = SignatureMethod.PlainText };

            using (repository.Record())
            {
                _ = Expect.Call(signer.ValidateSignature(null, null)).IgnoreArguments().Return(false);
            }
            using (repository.Playback())
            {
                var inspector = new SignatureValidationInspector(consumerStore, signer);
                var ex = Assert.ThrowsException<OAuthException>(() => inspector.InspectContext(ProviderPhase.GrantRequestToken, context));
                Assert.AreEqual("Failed to validate signature", ex.Message);
            }
        }

        [TestMethod]
        public void PlainTextSignatureMethodDoesNotFetchCertificate()
        {
            var repository = new MockRepository();

            var consumerStore = repository.DynamicMock<IConsumerStore>();
            var signer = repository.StrictMock<IOAuthContextSigner>();

            var context = new OAuthContext { ConsumerKey = "key", SignatureMethod = SignatureMethod.PlainText };

            using (repository.Record())
            {
                _ = Expect.Call(signer.ValidateSignature(null, null)).IgnoreArguments().Return(true);
            }
            using (repository.Playback())
            {
                var inspector = new SignatureValidationInspector(consumerStore, signer);
                inspector.InspectContext(ProviderPhase.GrantRequestToken, context);
            }
        }

        [TestMethod]
        public void RsaSha1SignatureMethodFetchesCertificate()
        {
            var repository = new MockRepository();

            var consumerStore = repository.DynamicMock<IConsumerStore>();
            var signer = repository.StrictMock<IOAuthContextSigner>();

            var context = new OAuthContext { ConsumerKey = "key", SignatureMethod = SignatureMethod.RsaSha1 };

            using (repository.Record())
            {
                _ = Expect.Call(consumerStore.GetConsumerPublicKey(context)).Return(
                    TestCertificates.OAuthTestCertificate().GetRSAPublicKey() ?? throw new NullReferenceException("GetRSAPubclicKey"));
                _ = Expect.Call(signer.ValidateSignature(null, null)).IgnoreArguments().Return(true);
            }
            using (repository.Playback())
            {
                var inspector = new SignatureValidationInspector(consumerStore, signer);
                inspector.InspectContext(ProviderPhase.GrantRequestToken, context);
            }
        }
    }
}