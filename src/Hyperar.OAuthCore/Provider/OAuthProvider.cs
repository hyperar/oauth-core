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

namespace Hyperar.OAuthCore.Provider
{
    using System;
    using System.Collections.Generic;
    using Hyperar.OAuthCore.Framework;
    using Hyperar.OAuthCore.Provider.Inspectors;
    using Hyperar.OAuthCore.Storage;

    public class OAuthProvider : IOAuthProvider
    {
        private readonly List<IContextInspector> _inspectors = new List<IContextInspector>();

        private readonly ITokenStore _tokenStore;

        public OAuthProvider(ITokenStore tokenStore, params IContextInspector[] inspectors)
        {
            this.RequiresCallbackUrlInRequest = true;

            if (tokenStore == null)
            {
                throw new ArgumentNullException("tokenStore");
            }

            this._tokenStore = tokenStore;

            if (inspectors != null)
            {
                this._inspectors.AddRange(inspectors);
            }
        }

        public bool RequiresCallbackUrlInRequest { get; set; }

        public virtual void AccessProtectedResourceRequest(IOAuthContext context)
        {
            this.InspectRequest(ProviderPhase.AccessProtectedResourceRequest, context);

            this._tokenStore.ConsumeAccessToken(context);
        }

        public void AddInspector(IContextInspector inspector)
        {
            this._inspectors.Add(inspector);
        }

        public IToken CreateAccessToken(IOAuthContext context)
        {
            this.InspectRequest(ProviderPhase.CreateAccessToken, context);

            return this._tokenStore.CreateAccessToken(context);
        }

        public virtual IToken ExchangeRequestTokenForAccessToken(IOAuthContext context)
        {
            this.InspectRequest(ProviderPhase.ExchangeRequestTokenForAccessToken, context);

            this._tokenStore.ConsumeRequestToken(context);

            switch (this._tokenStore.GetStatusOfRequestForAccess(context))
            {
                case RequestForAccessStatus.Granted:
                    break;

                case RequestForAccessStatus.Unknown:
                    throw Error.ConsumerHasNotBeenGrantedAccessYet(context);
                default:
                    throw Error.ConsumerHasBeenDeniedAccess(context);
            }

            return this._tokenStore.GetAccessTokenAssociatedWithRequestToken(context);
        }

        public virtual IToken GrantRequestToken(IOAuthContext context)
        {
            this.AssertContextDoesNotIncludeToken(context);

            this.InspectRequest(ProviderPhase.GrantRequestToken, context);

            return this._tokenStore.CreateRequestToken(context);
        }

        public IToken RenewAccessToken(IOAuthContext context)
        {
            this.InspectRequest(ProviderPhase.RenewAccessToken, context);

            return this._tokenStore.RenewAccessToken(context);
        }

        protected virtual void InspectRequest(ProviderPhase phase, IOAuthContext context)
        {
            AssertContextDoesNotIncludeTokenSecret(context);

            this.AddStoredTokenSecretToContext(context, phase);

            this.ApplyInspectors(context, phase);
        }

        private static void AssertContextDoesNotIncludeTokenSecret(IOAuthContext context)
        {
            if (!string.IsNullOrEmpty(context.TokenSecret))
            {
                throw new OAuthException(context, OAuthProblems.ParameterRejected, "The oauth_token_secret must not be transmitted to the provider.");
            }
        }

        private void AddStoredTokenSecretToContext(IOAuthContext context, ProviderPhase phase)
        {
            if (phase == ProviderPhase.ExchangeRequestTokenForAccessToken)
            {
                string secret = this._tokenStore.GetRequestTokenSecret(context);
                context.TokenSecret = secret;
            }
            else if (phase is ProviderPhase.AccessProtectedResourceRequest or ProviderPhase.RenewAccessToken)
            {
                string secret = this._tokenStore.GetAccessTokenSecret(context);

                context.TokenSecret = secret;
            }
        }

        private void ApplyInspectors(IOAuthContext context, ProviderPhase phase)
        {
            foreach (IContextInspector inspector in this._inspectors)
            {
                inspector.InspectContext(phase, context);
            }
        }

        private void AssertContextDoesNotIncludeToken(IOAuthContext context)
        {
            if (context.Token != null)
            {
                throw Error.RequestForTokenMustNotIncludeTokenInContext(context);
            }
        }
    }
}