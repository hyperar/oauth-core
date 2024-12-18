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

    [TestClass]
    public class ConsumerValidationInspector
    {
        [TestMethod]
        public void InValidConsumerThrows()
        {
            IConsumerStore consumerStore = MockRepository.GenerateStub<IConsumerStore>();

            OAuthContext context = new OAuthContext { ConsumerKey = "key" };

            _ = consumerStore.Stub(stub => stub.IsConsumer(context)).Return(false);

            OAuthCore.Provider.Inspectors.ConsumerValidationInspector inspector = new OAuthCore.Provider.Inspectors.ConsumerValidationInspector(consumerStore);

            OAuthException ex = Assert.ThrowsException<OAuthException>(() => inspector.InspectContext(ProviderPhase.GrantRequestToken, context));

            Assert.AreEqual("Unknown Consumer (Realm: , Key: key)", ex.Message);
        }

        [TestMethod]
        public void ValidConsumerPassesThrough()
        {
            MockRepository repository = new MockRepository();

            IConsumerStore consumerStore = repository.StrictMock<IConsumerStore>();
            OAuthContext context = new OAuthContext { ConsumerKey = "key" };

            using (repository.Record())
            {
                _ = Expect.Call(consumerStore.IsConsumer(context)).Return(true);
            }

            using (repository.Playback())
            {
                OAuthCore.Provider.Inspectors.ConsumerValidationInspector inspector = new OAuthCore.Provider.Inspectors.ConsumerValidationInspector(consumerStore);
                inspector.InspectContext(ProviderPhase.GrantRequestToken, context);
            }
        }
    }
}