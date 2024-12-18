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
    using Hyperar.OAuthCore.Storage;
    using Rhino.Mocks;
    using Xunit;

    [TestClass]
    public class NonceStoreInspectorTests
    {
        [TestMethod]
        public void InspectContextForRepeatedNonceThrows()
        {
            INonceStore nonceStore = MockRepository.GenerateStub<INonceStore>();

            OAuthContext context = new OAuthContext { Nonce = "1" };

            _ = nonceStore.Stub(stub => stub.RecordNonceAndCheckIsUnique(context, "1")).Return(false);

            NonceStoreInspector inspector = new NonceStoreInspector(nonceStore);

            OAuthException ex = Assert.ThrowsException<OAuthException>(() => inspector.InspectContext(ProviderPhase.GrantRequestToken, context));

            Assert.AreEqual("The nonce value \"1\" has already been used", ex.Message);
        }

        [TestMethod]
        public void InspectContextForUniqueNoncePasses()
        {
            INonceStore nonceStore = MockRepository.GenerateStub<INonceStore>();

            OAuthContext context = new OAuthContext { Nonce = "2" };

            _ = nonceStore.Stub(stub => stub.RecordNonceAndCheckIsUnique(context, "2")).Return(true);

            NonceStoreInspector inspector = new NonceStoreInspector(nonceStore);

            Exception exception = Record.Exception(() => inspector.InspectContext(ProviderPhase.GrantRequestToken, context));

            Assert.IsNull(exception);
        }
    }
}