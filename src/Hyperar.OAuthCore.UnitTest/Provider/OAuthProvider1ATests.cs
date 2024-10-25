namespace Hyperar.OAuthCore.UnitTest.Provider
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
    using System.Security.Cryptography.X509Certificates;
    using Hyperar.OAuthCore.Consumer;
    using Hyperar.OAuthCore.Framework;
    using Hyperar.OAuthCore.Provider;
    using Hyperar.OAuthCore.Provider.Inspectors;
    using Hyperar.OAuthCore.Testing;

    [TestClass]
    public class OAuthProvider1ATests
    {
        private readonly OAuthProvider provider;

        public OAuthProvider1ATests()
        {
            var tokenStore = new TestTokenStore();
            var consumerStore = new TestConsumerStore();
            var nonceStore = new TestNonceStore();

            this.provider = new OAuthProvider(tokenStore,
                                         new SignatureValidationInspector(consumerStore),
                                         new NonceStoreInspector(nonceStore),
                                         new TimestampRangeInspector(new TimeSpan(1, 0, 0)),
                                         new ConsumerValidationInspector(consumerStore),
                                         new OAuth10AInspector(tokenStore));
        }

        private static IOAuthSession CreateConsumer(string signatureMethod)
        {
            var consumerContext = new OAuthConsumerContext
            {
                SignatureMethod = signatureMethod,
                ConsumerKey = "key",
                ConsumerSecret = "secret",
                Key = TestCertificates.OAuthTestCertificate().GetRSAPrivateKey() ?? throw new NullReferenceException("GetRSAPrivateKey")
            };

            var session = new OAuthSession(consumerContext, "http://localhost/oauth/requesttoken.rails",
                                           "http://localhost/oauth/userauhtorize.rails",
                                           "http://localhost/oauth/accesstoken.rails");

            return session;
        }

        [TestMethod]
        public void ExchangeTokensWhenVerifierIsMatchDoesNotThrowException()
        {
            IOAuthSession session = CreateConsumer(SignatureMethod.RsaSha1);
            IOAuthContext context = session.BuildExchangeRequestTokenForAccessTokenContext(
                new TokenBase { ConsumerKey = "key", Token = "requestkey" }, "GET", "GzvVb5WjWfHKa/0JuFupaMyn").Context;
            this.provider.ExchangeRequestTokenForAccessToken(context);
        }

        [TestMethod]
        public void ExchangeTokensWhenVerifierIsMissingThrowsException()
        {
            string verifier = null;

            IOAuthSession session = CreateConsumer(SignatureMethod.RsaSha1);
            IOAuthContext context = session.BuildExchangeRequestTokenForAccessTokenContext(
                new TokenBase { ConsumerKey = "key", Token = "requestkey" }, "GET", verifier).Context;
            var ex = Assert.ThrowsException<OAuthException>(() => this.provider.ExchangeRequestTokenForAccessToken(context));
            Assert.AreEqual("Missing required parameter : oauth_verifier", ex.Message);
        }

        [TestMethod]
        public void ExchangeTokensWhenVerifierIsWrongThrowsException()
        {
            IOAuthSession session = CreateConsumer(SignatureMethod.RsaSha1);
            IOAuthContext context = session.BuildExchangeRequestTokenForAccessTokenContext(
                new TokenBase { ConsumerKey = "key", Token = "requestkey" }, "GET", "wrong").Context;
            var ex = Assert.ThrowsException<OAuthException>(() => this.provider.ExchangeRequestTokenForAccessToken(context));
            Assert.AreEqual("The parameter \"oauth_verifier\" was rejected", ex.Message);
        }

        [TestMethod]
        public void RequestTokenWithCallbackDoesNotThrowException()
        {
            IOAuthSession session = CreateConsumer(SignatureMethod.PlainText);
            IOAuthContext context = session.BuildRequestTokenContext("GET").Context;
            this.provider.GrantRequestToken(context);
        }

        [TestMethod]
        public void RequestTokenWithoutCallbackWillThrowException()
        {
            IOAuthSession session = CreateConsumer(SignatureMethod.PlainText);
            IOAuthContext context = session.BuildRequestTokenContext("GET").Context;
            context.CallbackUrl = null; // clear parameter, as it will default to "oob"
            var ex = Assert.ThrowsException<OAuthException>(() => this.provider.GrantRequestToken(context));
            Assert.AreEqual("Missing required parameter : oauth_callback", ex.Message);
        }
    }
}