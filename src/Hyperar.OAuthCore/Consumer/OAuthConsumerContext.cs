// The MIT License
//
// Copyright (c) 2022 Hyperar.
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

namespace Hyperar.OauthCore.Consumer
{
    using System;
    using System.Security.Cryptography;
    using Hyperar.OauthCore.Framework;
    using Hyperar.OauthCore.Framework.Signing;
    using Hyperar.OauthCore.Utility;

    [Serializable]
    public class OAuthConsumerContext : IOAuthConsumerContext
    {
        private INonceGenerator _nonceGenerator = new GuidNonceGenerator();

        private IOAuthContextSigner _signer = new OAuthContextSigner();

        public OAuthConsumerContext()
        {
            this.SignatureMethod = Framework.SignatureMethod.PlainText;
        }

        public string ConsumerKey { get; set; }

        public string ConsumerSecret { get; set; }

        public AsymmetricAlgorithm Key { get; set; }

        public INonceGenerator NonceGenerator
        {
            get { return this._nonceGenerator; }
            set { this._nonceGenerator = value; }
        }

        public string Realm { get; set; }

        public string SignatureMethod { get; set; }

        public IOAuthContextSigner Signer
        {
            get { return this._signer; }
            set { this._signer = value; }
        }

        public bool UseHeaderForOAuthParameters { get; set; }

        public string UserAgent { get; set; }

        public void SignContext(IOAuthContext context)
        {
            this.EnsureStateIsValid();

            context.UseAuthorizationHeader = this.UseHeaderForOAuthParameters;
            context.Nonce = this._nonceGenerator.GenerateNonce(context);
            context.ConsumerKey = this.ConsumerKey;
            context.Realm = this.Realm;
            context.SignatureMethod = this.SignatureMethod;
            context.Timestamp = Clock.EpochString;
            context.Version = "1.0";

            context.Nonce = this.NonceGenerator.GenerateNonce(context);

            string signatureBase = context.GenerateSignatureBase();

            this._signer.SignContext(context,
                                new SigningContext
                                { Algorithm = Key, SignatureBase = signatureBase, ConsumerSecret = ConsumerSecret });
        }

        public void SignContextWithToken(IOAuthContext context, IToken token)
        {
            context.Token = token.Token;
            context.TokenSecret = token.TokenSecret;

            this.SignContext(context);
        }

        private void EnsureStateIsValid()
        {
            if (string.IsNullOrEmpty(this.ConsumerKey))
            {
                throw Error.EmptyConsumerKey();
            }

            if (string.IsNullOrEmpty(this.SignatureMethod))
            {
                throw Error.UnknownSignatureMethod(this.SignatureMethod);
            }

            if ((this.SignatureMethod == Framework.SignatureMethod.RsaSha1)
                && (this.Key == null))
            {
                throw Error.ForRsaSha1SignatureMethodYouMustSupplyAssymetricKeyParameter();
            }
        }
    }
}