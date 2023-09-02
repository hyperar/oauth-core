namespace Hyperar.OAuthCore.UnitTest.Consumer
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

    #endregion

    using System;
    using Hyperar.OauthCore.Consumer;
    using Hyperar.OauthCore.Framework;
    using Hyperar.OauthCore.Storage.Basic;

    [TestClass]
    public class ConsumerRequestTests
    {
        private readonly AccessToken accessToken;
        private readonly OAuthConsumerContext consumerContext;
        private readonly OAuthContext context;

        public ConsumerRequestTests()
        {
            this.context = new OAuthContext { RequestMethod = "POST", RawUri = new Uri("http://localhost/svc") };
            this.consumerContext = new OAuthConsumerContext { ConsumerKey = "key", ConsumerSecret = "secret", SignatureMethod = SignatureMethod.PlainText };
            this.accessToken = new AccessToken();
        }

        [TestMethod]
        public void GetRequestDescriptionCopiesHeadersFromContextToDescription()
        {
            this.context.Headers["a-key"] = "a-value";
            var request = new ConsumerRequest(this.context, this.consumerContext, this.accessToken);
            RequestDescription description = request.GetRequestDescription();
            Assert.AreEqual("a-value", description.Headers["a-key"]);
        }
    }
}