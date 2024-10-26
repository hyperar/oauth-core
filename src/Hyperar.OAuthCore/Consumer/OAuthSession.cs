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

namespace Hyperar.OAuthCore.Consumer
{
    using System;
    using System.Collections;
    using System.Collections.Specialized;
    using System.Web;
    using Hyperar.OAuthCore.Framework;
    using Hyperar.OAuthCore.Utility;

    [Serializable]
    public class OAuthSession : IOAuthSession
    {
        private readonly NameValueCollection _cookies = new NameValueCollection();

        private readonly NameValueCollection _formParameters = new NameValueCollection();

        private readonly NameValueCollection _headers = new NameValueCollection();

        private readonly NameValueCollection _queryParameters = new NameValueCollection();

        private IConsumerRequestFactory _consumerRequestFactory = DefaultConsumerRequestFactory.Instance;

        public OAuthSession(IOAuthConsumerContext consumerContext) : this(
            consumerContext,
            (Uri?)null,
            null,
            null,
            null)
        {
        }

        public OAuthSession(IOAuthConsumerContext consumerContext, Uri endPointUri)
            : this(consumerContext, endPointUri, endPointUri, endPointUri, null)
        {
        }

        public OAuthSession(IOAuthConsumerContext consumerContext, Uri requestTokenUri, Uri userAuthorizeUri, Uri accessTokenUri)
            : this(consumerContext, requestTokenUri, userAuthorizeUri, accessTokenUri, null)
        {
        }

        public OAuthSession(
            IOAuthConsumerContext consumerContext,
            Uri? requestTokenUri,
            Uri? userAuthorizeUri,
            Uri? accessTokenUri,
            Uri? callBackUri)
        {
            this.ConsumerContext = consumerContext;
            this.RequestTokenUri = requestTokenUri;
            this.AccessTokenUri = accessTokenUri;
            this.UserAuthorizeUri = userAuthorizeUri;
            this.CallbackUri = callBackUri;
        }

        public OAuthSession(
            IOAuthConsumerContext consumerContext,
            string requestTokenUrl,
            string userAuthorizeUrl,
            string accessTokenUrl,
            string? callBackUrl) : this(
                consumerContext,
                new Uri(requestTokenUrl),
                new Uri(userAuthorizeUrl),
                new Uri(accessTokenUrl),
                ParseCallbackUri(callBackUrl))
        {
        }

        public OAuthSession(
            IOAuthConsumerContext consumerContext,
            string requestTokenUrl,
            string userAuthorizeUrl,
            string accessTokenUrl) : this(
                consumerContext,
                requestTokenUrl,
                userAuthorizeUrl,
                accessTokenUrl,
                null)
        {
        }

        public IToken? AccessToken { get; set; }

        public Uri? AccessTokenUri { get; set; }

        public bool AddBodyHashesToRawRequests { get; set; }

        public bool CallbackMustBeConfirmed { get; set; }

        public Uri? CallbackUri { get; set; }

        public IOAuthConsumerContext ConsumerContext { get; set; }

        public IConsumerRequestFactory ConsumerRequestFactory
        {
            get { return this._consumerRequestFactory; }

            set
            {
                if (this._consumerRequestFactory == null)
                {
                    throw new ArgumentNullException(nameof(value));
                }

                this._consumerRequestFactory = value;
            }
        }

        public Uri? ProxyServerUri { get; set; }

        public Uri? RequestTokenUri { get; set; }

        public Action<string>? ResponseBodyAction { get; set; }

        public Uri? UserAuthorizeUri { get; set; }

        public IConsumerRequest BuildAccessTokenContext(string method, string xAuthMode, string xAuthUsername, string xAuthPassword)
        {
            ArgumentNullException.ThrowIfNull(this.AccessTokenUri);

            return this.Request()
              .ForMethod(method)
              .AlterContext(context => context.XAuthUsername = xAuthUsername)
              .AlterContext(context => context.XAuthPassword = xAuthPassword)
              .AlterContext(context => context.XAuthMode = xAuthMode)
              .ForUri(this.AccessTokenUri)
              .SignWithoutToken();
        }

        public IConsumerRequest BuildExchangeRequestTokenForAccessTokenContext(IToken requestToken, string method, string? verificationCode)
        {
            ArgumentNullException.ThrowIfNull(this.AccessTokenUri);

            return this.Request()
                .ForMethod(method)
                .AlterContext(context => context.Verifier = verificationCode)
                .ForUri(this.AccessTokenUri)
                .SignWithToken(requestToken);
        }

        public IConsumerRequest BuildRenewAccessTokenContext(IToken requestToken, string method, string sessionHandle)
        {
            ArgumentNullException.ThrowIfNull(this.AccessTokenUri);

            return this.Request()
                .ForMethod(method)
                .AlterContext(context => context.SessionHandle = sessionHandle)
                .ForUri(this.AccessTokenUri)
                .SignWithToken(requestToken);
        }

        public IConsumerRequest BuildRequestTokenContext(string method)
        {
            ArgumentNullException.ThrowIfNull(this.RequestTokenUri);

            return this.Request()
                .ForMethod(method)
                .AlterContext(context => context.CallbackUrl = (this.CallbackUri == null) ? "oob" : this.CallbackUri.ToString())
                .AlterContext(context => context.Token = null)
                .ForUri(this.RequestTokenUri)
                .SignWithoutToken();
        }

        public IOAuthSession EnableOAuthRequestBodyHashes()
        {
            this.AddBodyHashesToRawRequests = true;
            return this;
        }

        public IToken ExchangeRequestTokenForAccessToken(IToken requestToken)
        {
            return this.ExchangeRequestTokenForAccessToken(requestToken, "GET", null);
        }

        public IToken ExchangeRequestTokenForAccessToken(IToken requestToken, string verificationCode)
        {
            return this.ExchangeRequestTokenForAccessToken(requestToken, "GET", verificationCode);
        }

        public IToken ExchangeRequestTokenForAccessToken(IToken requestToken, string method, string? verificationCode)
        {
            TokenBase token = this.BuildExchangeRequestTokenForAccessTokenContext(requestToken, method, verificationCode)
                .Select(collection =>
                        new TokenBase
                        {
                            ConsumerKey = requestToken.ConsumerKey,
                            Token = ParseResponseParameter(collection, Parameters.OAuth_Token),
                            TokenSecret = ParseResponseParameter(collection, Parameters.OAuth_Token_Secret),
                            SessionHandle = ParseResponseParameter(collection, Parameters.OAuth_Session_Handle)
                        });

            this.AccessToken = token;

            return token;
        }

        public IToken GetAccessTokenUsingXAuth(string authMode, string username, string password)
        {
            TokenBase token = this.BuildAccessTokenContext("GET", authMode, username, password)
                   .Select(collection =>
                           new TokenBase
                           {
                               ConsumerKey = this.ConsumerContext.ConsumerKey,
                               Token = ParseResponseParameter(collection, Parameters.OAuth_Token),
                               TokenSecret = ParseResponseParameter(collection, Parameters.OAuth_Token_Secret),
                               SessionHandle = ParseResponseParameter(collection, Parameters.OAuth_Session_Handle)
                           });

            this.AccessToken = token;
            return token;
        }

        public IToken GetRequestToken()
        {
            return this.GetRequestToken("GET");
        }

        public IToken GetRequestToken(string method)
        {
            var results = this.BuildRequestTokenContext(method)
                .Select(collection =>
                    new
                    {
                        this.ConsumerContext.ConsumerKey,
                        Token = ParseResponseParameter(collection, Parameters.OAuth_Token),
                        TokenSecret = ParseResponseParameter(collection, Parameters.OAuth_Token_Secret),
                        CallackConfirmed = WasCallbackConfimed(collection)
                    });

            if (!results.CallackConfirmed && this.CallbackMustBeConfirmed)
            {
                throw Error.CallbackWasNotConfirmed();
            }

            return new TokenBase
            {
                ConsumerKey = results.ConsumerKey,
                Token = results.Token,
                TokenSecret = results.TokenSecret
            };
        }

        public string GetUserAuthorizationUrlForToken(IToken token)
        {
            return this.GetUserAuthorizationUrlForToken(token, null);
        }

        public string GetUserAuthorizationUrlForToken(IToken token, string? callbackUrl)
        {
            ArgumentNullException.ThrowIfNull(this.UserAuthorizeUri);

            var builder = new UriBuilder(this.UserAuthorizeUri);

            var collection = new NameValueCollection();

            if (builder.Query != null)
            {
                collection.Add(HttpUtility.ParseQueryString(builder.Query));
            }

            if (this._queryParameters != null)
            {
                collection.Add(this._queryParameters);
            }

            collection[Parameters.OAuth_Token] = token.Token;

            if (!string.IsNullOrEmpty(callbackUrl))
            {
                collection[Parameters.OAuth_Callback] = callbackUrl;
            }

            builder.Query = "";

            return builder.Uri + "?" + UriUtility.FormatQueryString(collection);
        }

        public IToken RenewAccessToken(IToken accessToken, string sessionHandle)
        {
            return this.RenewAccessToken(accessToken, "GET", sessionHandle);
        }

        public IToken RenewAccessToken(IToken accessToken, string method, string sessionHandle)
        {
            TokenBase token = this.BuildRenewAccessTokenContext(accessToken, method, sessionHandle)
                .Select(collection =>
                        new TokenBase
                        {
                            ConsumerKey = accessToken.ConsumerKey,
                            Token = ParseResponseParameter(collection, Parameters.OAuth_Token),
                            TokenSecret = ParseResponseParameter(collection, Parameters.OAuth_Token_Secret),
                            SessionHandle = ParseResponseParameter(collection, Parameters.OAuth_Session_Handle)
                        });

            this.AccessToken = token;

            return token;
        }

        public IConsumerRequest Request(IToken accessToken)
        {
            var context = new OAuthContext
            {
                UseAuthorizationHeader = this.ConsumerContext.UseHeaderForOAuthParameters,
                IncludeOAuthRequestBodyHashInSignature = this.AddBodyHashesToRawRequests
            };

            context.Cookies.Add(this._cookies);
            context.FormEncodedParameters.Add(this._formParameters);
            context.Headers.Add(this._headers);
            context.QueryParameters.Add(this._queryParameters);

            IConsumerRequest consumerRequest = this._consumerRequestFactory.CreateConsumerRequest(context, this.ConsumerContext, accessToken);

            consumerRequest.ProxyServerUri = this.ProxyServerUri;
            consumerRequest.ResponseBodyAction = this.ResponseBodyAction;

            return consumerRequest;
        }

        public IConsumerRequest Request()
        {
            var context = new OAuthContext
            {
                UseAuthorizationHeader = this.ConsumerContext.UseHeaderForOAuthParameters,
                IncludeOAuthRequestBodyHashInSignature = this.AddBodyHashesToRawRequests
            };

            context.Cookies.Add(this._cookies);
            context.FormEncodedParameters.Add(this._formParameters);
            context.Headers.Add(this._headers);
            context.QueryParameters.Add(this._queryParameters);

            IConsumerRequest consumerRequest = this._consumerRequestFactory.CreateConsumerRequest(context, this.ConsumerContext, this.AccessToken);

            consumerRequest.ProxyServerUri = this.ProxyServerUri;
            consumerRequest.ResponseBodyAction = this.ResponseBodyAction;

            return consumerRequest;
        }

        public IOAuthSession RequiresCallbackConfirmation()
        {
            this.CallbackMustBeConfirmed = true;
            return this;
        }

        public IOAuthSession WithCookies(IDictionary dictionary)
        {
            return this.AddItems(this._cookies, dictionary);
        }

        public IOAuthSession WithCookies(object anonymousClass)
        {
            return this.AddItems(this._cookies, anonymousClass);
        }

        public IOAuthSession WithFormParameters(IDictionary dictionary)
        {
            return this.AddItems(this._formParameters, dictionary);
        }

        public IOAuthSession WithFormParameters(object anonymousClass)
        {
            return this.AddItems(this._formParameters, anonymousClass);
        }

        public IOAuthSession WithHeaders(IDictionary dictionary)
        {
            return this.AddItems(this._headers, dictionary);
        }

        public IOAuthSession WithHeaders(object anonymousClass)
        {
            return this.AddItems(this._headers, anonymousClass);
        }

        public IOAuthSession WithQueryParameters(IDictionary dictionary)
        {
            return this.AddItems(this._queryParameters, dictionary);
        }

        public IOAuthSession WithQueryParameters(object anonymousClass)
        {
            return this.AddItems(this._queryParameters, anonymousClass);
        }

        private static Uri? ParseCallbackUri(string? callBackUrl)
        {
            if (string.IsNullOrEmpty(callBackUrl))
            {
                return null;
            }

            if (callBackUrl.Equals("oob", StringComparison.InvariantCultureIgnoreCase))
            {
                return null;
            }

            return new Uri(callBackUrl);
        }

        private static string? ParseResponseParameter(NameValueCollection collection, string parameter)
        {
            string value = (collection[parameter] ?? "").Trim();
            return (value.Length > 0) ? value : null;
        }

        private static bool WasCallbackConfimed(NameValueCollection parameters)
        {
            string? value = ParseResponseParameter(parameters, Parameters.OAuth_Callback_Confirmed);

            return value == "true";
        }

        private OAuthSession AddItems(NameValueCollection destination, object anonymousClass)
        {
            return this.AddItems(destination, new ReflectionBasedDictionaryAdapter(anonymousClass));
        }

        private OAuthSession AddItems(NameValueCollection destination, IDictionary additions)
        {
            foreach (string parameter in additions.Keys)
            {
                destination[parameter] = Convert.ToString(additions[parameter]);
            }

            return this;
        }
    }
}