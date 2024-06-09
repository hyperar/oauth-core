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

namespace Hyperar.OAuthCore.Provider.Inspectors
{
    using System;
    using Hyperar.OAuthCore.Framework;
    using Hyperar.OAuthCore.Storage;

    /// <summary>
    /// This inspector implements additional behavior required by the 1.0a version of OAuthCore.
    /// </summary>
    public class OAuth10AInspector : IContextInspector
    {
        private readonly ITokenStore _tokenStore;

        public OAuth10AInspector(ITokenStore tokenStore)
        {
            if (tokenStore == null)
            {
                throw new ArgumentNullException("tokenStore");
            }

            this._tokenStore = tokenStore;
        }

        public void InspectContext(ProviderPhase phase, IOAuthContext context)
        {
            if (phase == ProviderPhase.GrantRequestToken)
            {
                ValidateCallbackUrlIsPartOfRequest(context);
            }
            else if (phase == ProviderPhase.ExchangeRequestTokenForAccessToken)
            {
                this.ValidateVerifierMatchesStoredVerifier(context);
            }
        }

        private static void ValidateCallbackUrlIsPartOfRequest(IOAuthContext context)
        {
            if (string.IsNullOrEmpty(context.CallbackUrl))
            {
                throw Error.MissingRequiredOAuthParameter(context, Parameters.OAuth_Callback);
            }
        }

        private void ValidateVerifierMatchesStoredVerifier(IOAuthContext context)
        {
            string actual = context.Verifier;

            if (string.IsNullOrEmpty(actual))
            {
                throw Error.MissingRequiredOAuthParameter(context, Parameters.OAuth_Verifier);
            }

            string expected = this._tokenStore.GetVerificationCodeForRequestToken(context);

            if (expected != actual.Trim())
            {
                throw Error.RejectedRequiredOAuthParameter(context, Parameters.OAuth_Verifier);
            }
        }
    }
}