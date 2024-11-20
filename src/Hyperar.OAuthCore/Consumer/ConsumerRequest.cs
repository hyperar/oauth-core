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
    using System.Collections.Specialized;
    using System.Net;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Web;
    using System.Xml.Linq;
    using Hyperar.OAuthCore.Framework;
    using Hyperar.OAuthCore.Utility;

    public class ConsumerRequest : IConsumerRequest
    {
        private readonly IToken? _token;

        public ConsumerRequest(IOAuthContext context, IOAuthConsumerContext consumerContext, IToken? token)
        {
            ArgumentNullException.ThrowIfNull(context);

            ArgumentNullException.ThrowIfNull(consumerContext);

            this.Context = context;
            this.ConsumerContext = consumerContext;
            this._token = token;
        }

        public string? AcceptsType { get; set; }

        public IOAuthConsumerContext ConsumerContext { get; }

        public IOAuthContext Context { get; }

        public Uri? ProxyServerUri { get; set; }

        public string? RequestBody { get; set; }

        public Action<string>? ResponseBodyAction { get; set; }

        /// <summary>
        /// Override the default request timeout in milliseconds.
        /// Sets the <see cref="System.Net.HttpWebRequest.Timeout"/> property.
        /// </summary>
        public int? Timeout { get; set; }

        private string? ResponseBody { get; set; }

        public RequestDescription GetRequestDescription()
        {
            if (string.IsNullOrEmpty(this.Context.Signature))
            {
                if (this._token != null)
                {
                    this.ConsumerContext.SignContextWithToken(this.Context, this._token);
                }
                else
                {
                    this.ConsumerContext.SignContext(this.Context);
                }
            }

            Uri uri = this.Context.GenerateUri();

            RequestDescription description = new RequestDescription
            {
                Url = uri,
                Method = this.Context.RequestMethod,
            };

            if ((this.Context.FormEncodedParameters != null) && (this.Context.FormEncodedParameters.Count > 0))
            {
                description.ContentType = Parameters.HttpFormEncoded;
                description.Body = UriUtility.FormatQueryString(this.Context.FormEncodedParameters.ToQueryParametersExcludingTokenSecret());
            }
            else if (!string.IsNullOrEmpty(this.RequestBody))
            {
                description.Body = UriUtility.UrlEncode(this.RequestBody);
            }
            else if (this.Context.RawContent != null)
            {
                description.ContentType = this.Context.RawContentType;
                description.RawBody = this.Context.RawContent;
            }

            if (this.Context.Headers != null)
            {
                description.Headers.Add(this.Context.Headers);
            }

            if (this.ConsumerContext.UseHeaderForOAuthParameters)
            {
                description.Headers[Parameters.OAuth_Authorization_Header] = this.Context.GenerateOAuthParametersForHeader();
            }

            return description;
        }

        public IConsumerRequest SignWithoutToken()
        {
            this.EnsureRequestHasNotBeenSignedYet();
            this.ConsumerContext.SignContext(this.Context);
            return this;
        }

        public IConsumerRequest SignWithToken()
        {
            return this.SignWithToken(this._token);
        }

        public IConsumerRequest SignWithToken(IToken? token)
        {
            ArgumentNullException.ThrowIfNull(token);

            this.EnsureRequestHasNotBeenSignedYet();
            this.ConsumerContext.SignContextWithToken(this.Context, token);
            return this;
        }

        public async Task<NameValueCollection> ToBodyParametersAsync()
        {
            try
            {
                string encodedFormParameters = await this.ToStringAsync();

                this.ResponseBodyAction?.Invoke(encodedFormParameters);

                try
                {
                    return HttpUtility.ParseQueryString(encodedFormParameters);
                }
                catch (ArgumentNullException)
                {
                    throw Error.FailedToParseResponse(encodedFormParameters);
                }
            }
            catch (WebException webEx)
            {
                throw Error.RequestFailed(webEx);
            }
        }

        public async Task<byte[]> ToBytesAsync()
        {
            return Convert.FromBase64String(await this.ToStringAsync());
        }

        public async Task<XDocument> ToXDocumentAsync()
        {
            return XDocument.Parse(await this.ToStringAsync());
        }

        public async Task<string> ToStringAsync()
        {
            if (string.IsNullOrEmpty(this.ResponseBody))
            {
                HttpResponseMessage responseMessage = await this.ToResponseMessageAsync();

                this.ResponseBody = await responseMessage.Content
                    .ReadAsStringAsync();
            }

            return this.ResponseBody;
        }

        public HttpRequestMessage ToRequestMessage()
        {
            RequestDescription description = this.GetRequestDescription();

            ArgumentNullException.ThrowIfNull(description.Url);
            ArgumentException.ThrowIfNullOrWhiteSpace(description.Method);

            HttpRequestMessage requestMessage = new HttpRequestMessage(
                description.Method.ToHttpMethod(),
                description.Url);

            if (!string.IsNullOrEmpty(this.AcceptsType))
            {
                requestMessage.Headers.Accept.Add(
                    MediaTypeWithQualityHeaderValue.Parse(
                        this.AcceptsType));
            }

            try
            {
                string? modifiedDateString = this.Context.Headers["If-Modified-Since"];

                if (modifiedDateString != null)
                {
                    requestMessage.Headers.IfModifiedSince = DateTime.Parse(modifiedDateString);
                }
            }
            catch (Exception ex)
            {
                throw new ApplicationException("If-Modified-Since header could not be parsed as a datetime", ex);
            }

            if (description.Headers.Count > 0)
            {
                foreach (string key in description.Headers)
                {
                    requestMessage.Headers.Add(key, description.Headers[key]);
                }
            }

            if (!string.IsNullOrEmpty(description.Body))
            {
                requestMessage.Content = new StringContent(description.Body);
            }
            else if (description.RawBody != null && description.RawBody.Length > 0)
            {
                requestMessage.Content = new ByteArrayContent(description.RawBody);
            }

            return requestMessage;
        }

        protected virtual HttpClientHandler GetHttpClientHandler()
        {
            HttpClientHandler httpClientHandler = new HttpClientHandler();

            if (this.ProxyServerUri != null)
            {
                httpClientHandler.Proxy = new WebProxy(this.ProxyServerUri, false);
            }

            return httpClientHandler;
        }

        private HttpClient GetHttpClient()
        {
            HttpClient httpClient = new HttpClient(
                this.GetHttpClientHandler());

            if (this.Timeout.HasValue)
            {
                httpClient.Timeout = new TimeSpan(0, 0, 0, 0, this.Timeout.Value);
            }

            return httpClient;
        }

        public async Task<HttpResponseMessage> ToResponseMessageAsync()
        {
            try
            {
                using (HttpClient httpClient = this.GetHttpClient())
                {
                    HttpRequestMessage requestMessage = this.ToRequestMessage();

                    return await httpClient.SendAsync(requestMessage);
                }
            }
            catch (WebException webEx)
            {
                if (WebExceptionHelper.TryWrapException(this.Context, webEx, out OAuthException authException, this.ResponseBodyAction))
                {
                    throw authException;
                }

                throw;
            }
        }

        private void EnsureRequestHasNotBeenSignedYet()
        {
            if (!string.IsNullOrEmpty(this.Context.Signature))
            {
                throw Error.ThisConsumerRequestHasAlreadyBeenSigned();
            }
        }
    }
}