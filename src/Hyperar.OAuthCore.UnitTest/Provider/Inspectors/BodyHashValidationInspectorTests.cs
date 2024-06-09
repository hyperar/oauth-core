namespace Hyperar.OAuthCore.UnitTest.Provider.Inspectors
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

    using Hyperar.OAuthCore.Framework;
    using Hyperar.OAuthCore.Provider.Inspectors;
    using Xunit;

    [TestClass]
    public class BodyHashValidationInspectorTests
    {
        private const string EmptyBodyHash = "2jmj7l5rSw0yVb/vlWAYkK/YBwk=";

        private readonly BodyHashValidationInspector inspector = new BodyHashValidationInspector();

        [TestMethod]
        public void InspectBodyForHmacSha1SignatureDoesNotThrowWhenBodyHashIsNull()
        {
            var context = new OAuthContext
            {
                UseAuthorizationHeader = true,
                BodyHash = null,
                SignatureMethod = SignatureMethod.HmacSha1
            };

            var exception = Record.Exception(() => this.inspector.InspectContext(ProviderPhase.AccessProtectedResourceRequest, context));

            Assert.IsNull(exception);
        }

        [TestMethod]
        public void InspectBodyForHmacSha1SignatureDoesNotThrowWhenHashMatches()
        {
            var context = new OAuthContext
            {
                UseAuthorizationHeader = true,
                BodyHash = EmptyBodyHash,
                SignatureMethod = SignatureMethod.HmacSha1
            };

            var exception = Record.Exception(() => this.inspector.InspectContext(ProviderPhase.AccessProtectedResourceRequest, context));

            Assert.IsNull(exception);
        }

        [TestMethod]
        public void InspectBodyForHmacSha1SignatureThrowsWhenHashDoesNotMatch()
        {
            var context = new OAuthContext
            {
                UseAuthorizationHeader = true,
                BodyHash = "wrong",
                SignatureMethod = SignatureMethod.HmacSha1
            };

            var ex = Assert.ThrowsException<OAuthException>(() => this.inspector.InspectContext(ProviderPhase.AccessProtectedResourceRequest, context));

            Assert.AreEqual("Failed to validate body hash", ex.Message);
        }

        [TestMethod]
        public void InspectBodyForPlainttextSignatureDoesNothing()
        {
            var context = new OAuthContext
            {
                UseAuthorizationHeader = true,
                BodyHash = "wrong",
                SignatureMethod = SignatureMethod.PlainText
            };

            var exception = Record.Exception(() => this.inspector.InspectContext(ProviderPhase.AccessProtectedResourceRequest, context));

            Assert.IsNull(exception);
        }

        [TestMethod]
        public void InspectWhenContextHasFormParametersThrows()
        {
            var context = new OAuthContext
            {
                UseAuthorizationHeader = false,
                BodyHash = "1234",
                SignatureMethod = SignatureMethod.HmacSha1
            };

            var ex = Assert.ThrowsException<OAuthException>(() => this.inspector.InspectContext(ProviderPhase.AccessProtectedResourceRequest, context));

            Assert.AreEqual("Encountered unexpected oauth_body_hash value in form-encoded request", ex.Message);
        }
    }
}