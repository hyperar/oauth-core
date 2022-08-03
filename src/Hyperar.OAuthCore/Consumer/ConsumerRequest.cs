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
    using System.Collections.Specialized;
    using System.IO;
    using System.Net;
    using System.Web;
    using System.Xml.Linq;
    using Hyperar.OauthCore.Framework;
    using Hyperar.OauthCore.Utility;

    public class ConsumerRequest : IConsumerRequest
    {
        private readonly IOAuthConsumerContext _consumerContext;

        private readonly IOAuthContext _context;

        private readonly IToken _token;

        public ConsumerRequest(IOAuthContext context, IOAuthConsumerContext consumerContext, IToken token)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }

            if (consumerContext == null)
            {
                throw new ArgumentNullException("consumerContext");
            }

            this._context = context;
            this._consumerContext = consumerContext;
            this._token = token;
        }

        public string AcceptsType { get; set; }

        public IOAuthConsumerContext ConsumerContext
        {
            get { return this._consumerContext; }
        }

        public IOAuthContext Context
        {
            get { return this._context; }
        }

        public Uri ProxyServerUri { get; set; }

        public string RequestBody { get; set; }

        public Action<string> ResponseBodyAction { get; set; }

        /// <summary>
        /// Override the default request timeout in milliseconds.
        /// Sets the <see cref="System.Net.HttpWebRequest.Timeout"/> property.
        /// </summary>
        public int? Timeout { get; set; }

        private string ResponseBody { get; set; }

        public RequestDescription GetRequestDescription()
        {
            if (string.IsNullOrEmpty(this._context.Signature))
            {
                if (this._token != null)
                {
                    this._consumerContext.SignContextWithToken(this._context, this._token);
                }
                else
                {
                    this._consumerContext.SignContext(this._context);
                }
            }

            Uri uri = this._context.GenerateUri();

            var description = new RequestDescription
            {
                Url = uri,
                Method = this._context.RequestMethod,
            };

            if ((this._context.FormEncodedParameters != null) && (this._context.FormEncodedParameters.Count > 0))
            {
                description.ContentType = Parameters.HttpFormEncoded;
                description.Body = UriUtility.FormatQueryString(this._context.FormEncodedParameters.ToQueryParametersExcludingTokenSecret());
            }
            else if (!string.IsNullOrEmpty(this.RequestBody))
            {
                description.Body = UriUtility.UrlEncode(this.RequestBody);
            }
            else if (this._context.RawContent != null)
            {
                description.ContentType = this._context.RawContentType;
                description.RawBody = this._context.RawContent;
            }

            if (this._context.Headers != null)
            {
                description.Headers.Add(this._context.Headers);
            }

            if (this._consumerContext.UseHeaderForOAuthParameters)
            {
                description.Headers[Parameters.OAuth_Authorization_Header] = this._context.GenerateOAuthParametersForHeader();
            }

            return description;
        }

        public IConsumerRequest SignWithoutToken()
        {
            this.EnsureRequestHasNotBeenSignedYet();
            this._consumerContext.SignContext(this._context);
            return this;
        }

        public IConsumerRequest SignWithToken()
        {
            return this.SignWithToken(this._token);
        }

        public IConsumerRequest SignWithToken(IToken token)
        {
            this.EnsureRequestHasNotBeenSignedYet();
            this.ConsumerContext.SignContextWithToken(this._context, token);
            return this;
        }

        public NameValueCollection ToBodyParameters()
        {
            try
            {
                string encodedFormParameters = this.ToString();

                if (this.ResponseBodyAction != null)
                {
                    this.ResponseBodyAction(encodedFormParameters);
                }

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

        public byte[] ToBytes()
        {
            return Convert.FromBase64String(this.ToString());
        }

        public XDocument ToDocument()
        {
            return XDocument.Parse(this.ToString());
        }

        public override string ToString()
        {
            if (string.IsNullOrEmpty(this.ResponseBody))
            {
                this.ResponseBody = this.ToWebResponse().ReadToEnd();
            }

            return this.ResponseBody;
        }

        public virtual HttpWebRequest ToWebRequest()
        {
            RequestDescription description = this.GetRequestDescription();

            var request = (HttpWebRequest)WebRequest.Create(description.Url);
            request.Method = description.Method;
            request.UserAgent = this._consumerContext.UserAgent;

            if (this.Timeout.HasValue)
            {
                request.Timeout = this.Timeout.Value;
            }

            if (!string.IsNullOrEmpty(this.AcceptsType))
            {
                request.Accept = this.AcceptsType;
            }

            try
            {
                if (this.Context.Headers["If-Modified-Since"] != null)
                {
                    string modifiedDateString = this.Context.Headers["If-Modified-Since"];
                    request.IfModifiedSince = DateTime.Parse(modifiedDateString);
                }
            }
            catch (Exception ex)
            {
                throw new ApplicationException("If-Modified-Since header could not be parsed as a datetime", ex);
            }

            if (this.ProxyServerUri != null)
            {
                request.Proxy = new WebProxy(this.ProxyServerUri, false);
            }

            if (description.Headers.Count > 0)
            {
                foreach (string key in description.Headers.AllKeys)
                {
                    request.Headers[key] = description.Headers[key];
                }
            }

            if (!string.IsNullOrEmpty(description.Body))
            {
                request.ContentType = description.ContentType;

                using (var writer = new StreamWriter(request.GetRequestStream()))
                {
                    writer.Write(description.Body);
                }
            }
            else if (description.RawBody != null && description.RawBody.Length > 0)
            {
                request.ContentType = description.ContentType;

                using (var writer = new BinaryWriter(request.GetRequestStream()))
                {
                    writer.Write(description.RawBody);
                }
            }

            return request;
        }

        public HttpWebResponse ToWebResponse()
        {
            try
            {
                HttpWebRequest request = this.ToWebRequest();
                return (HttpWebResponse)request.GetResponse();
            }
            catch (WebException webEx)
            {
                OAuthException authException;

                if (WebExceptionHelper.TryWrapException(this.Context, webEx, out authException, this.ResponseBodyAction))
                {
                    throw authException;
                }

                throw;
            }
        }

        private void EnsureRequestHasNotBeenSignedYet()
        {
            if (!string.IsNullOrEmpty(this._context.Signature))
            {
                throw Error.ThisConsumerRequestHasAlreadyBeenSigned();
            }
        }
    }
}