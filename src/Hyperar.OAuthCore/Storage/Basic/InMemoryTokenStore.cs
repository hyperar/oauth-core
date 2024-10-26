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

namespace Hyperar.OAuthCore.Storage.Basic
{
    using System;
    using Hyperar.OAuthCore.Framework;
    using Hyperar.OAuthCore.Utility;

    public class SimpleTokenStore : ITokenStore
    {
        private readonly ITokenRepository<AccessToken> _accessTokenRepository;

        private readonly ITokenRepository<RequestToken> _requestTokenRepository;

        public SimpleTokenStore(ITokenRepository<AccessToken> accessTokenRepository, ITokenRepository<RequestToken> requestTokenRepository)
        {
            ArgumentNullException.ThrowIfNull(accessTokenRepository);

            ArgumentNullException.ThrowIfNull(requestTokenRepository);

            this._accessTokenRepository = accessTokenRepository;
            this._requestTokenRepository = requestTokenRepository;
        }

        public void ConsumeAccessToken(IOAuthContext accessContext)
        {
            AccessToken accessToken = this.GetAccessToken(accessContext);

            if (accessToken.ExpiryDate < Clock.Now)
            {
                throw new OAuthException(accessContext, OAuthProblems.TokenExpired, "Token has expired");
            }
        }

        public void ConsumeRequestToken(IOAuthContext requestContext)
        {
            ArgumentNullException.ThrowIfNull(requestContext);

            RequestToken requestToken = this.GetRequestToken(requestContext);

            UseUpRequestToken(requestContext, requestToken);

            this._requestTokenRepository.SaveToken(requestToken);
        }

        /// <summary>
        /// Create an access token using xAuth.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <returns></returns>
        public IToken CreateAccessToken(IOAuthContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            var accessToken = new AccessToken
            {
                ConsumerKey = context.ConsumerKey,
                ExpiryDate = DateTime.UtcNow.AddDays(20),
                Realm = context.Realm,
                Token = Guid.NewGuid().ToString(),
                TokenSecret = Guid.NewGuid().ToString(),
                UserName = Guid.NewGuid().ToString(),
            };

            this._accessTokenRepository.SaveToken(accessToken);

            return accessToken;
        }

        public IToken CreateRequestToken(IOAuthContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            var token = new RequestToken
            {
                ConsumerKey = context.ConsumerKey,
                Realm = context.Realm,
                Token = Guid.NewGuid().ToString(),
                TokenSecret = Guid.NewGuid().ToString(),
                CallbackUrl = context.CallbackUrl
            };

            this._requestTokenRepository.SaveToken(token);

            return token;
        }

        public IToken? GetAccessTokenAssociatedWithRequestToken(IOAuthContext requestContext)
        {
            RequestToken requestToken = this.GetRequestToken(requestContext);

            return requestToken.AccessToken;
        }

        public string? GetAccessTokenSecret(IOAuthContext context)
        {
            AccessToken token = this.GetAccessToken(context);

            return token.TokenSecret;
        }

        public string? GetCallbackUrlForToken(IOAuthContext requestContext)
        {
            RequestToken requestToken = this.GetRequestToken(requestContext);
            return requestToken.CallbackUrl;
        }

        public string? GetRequestTokenSecret(IOAuthContext context)
        {
            RequestToken requestToken = this.GetRequestToken(context);

            return requestToken.TokenSecret;
        }

        public RequestForAccessStatus GetStatusOfRequestForAccess(IOAuthContext accessContext)
        {
            RequestToken request = this.GetRequestToken(accessContext);

            if (request.AccessDenied)
            {
                return RequestForAccessStatus.Denied;
            }

            if (request.AccessToken == null)
            {
                return RequestForAccessStatus.Unknown;
            }

            return RequestForAccessStatus.Granted;
        }

        public IToken? GetToken(IOAuthContext context)
        {
            var token = (IToken?)null;

            if (!string.IsNullOrEmpty(context.Token))
            {
                try
                {
                    token = this._accessTokenRepository.GetToken(context.Token) ??
                            (IToken)this._requestTokenRepository.GetToken(context.Token);
                }
                catch (Exception ex)
                {
                    // TODO: log exception
                    throw Error.UnknownToken(context, context.Token, ex);
                }
            }

            return token;
        }

        public string? GetVerificationCodeForRequestToken(IOAuthContext requestContext)
        {
            RequestToken requestToken = this.GetRequestToken(requestContext);

            return requestToken.Verifier;
        }

        public IToken RenewAccessToken(IOAuthContext requestContext)
        {
            throw new NotImplementedException();
        }

        private static void UseUpRequestToken(IOAuthContext requestContext, RequestToken requestToken)
        {
            if (requestToken.UsedUp)
            {
                throw new OAuthException(requestContext, OAuthProblems.TokenRejected,
                                         "The request token has already be consumed.");
            }

            requestToken.UsedUp = true;
        }

        private AccessToken GetAccessToken(IOAuthContext context)
        {
            try
            {
                return this._accessTokenRepository.GetToken(context.Token);
            }
            catch (Exception exception)
            {
                // TODO: log exception
                throw Error.UnknownToken(context, context.Token ?? string.Empty, exception);
            }
        }

        private RequestToken GetRequestToken(IOAuthContext context)
        {
            try
            {
                return this._requestTokenRepository.GetToken(context.Token);
            }
            catch (Exception exception)
            {
                // TODO: log exception
                throw Error.UnknownToken(context, context.Token ?? string.Empty, exception);
            }
        }
    }
}