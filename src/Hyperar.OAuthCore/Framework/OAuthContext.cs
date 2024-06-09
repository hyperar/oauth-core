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

namespace Hyperar.OAuthCore.Framework
{
    using System;
    using System.Collections.Generic;
    using System.Collections.Specialized;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using System.Web;
    using QueryParameter = System.Collections.Generic.KeyValuePair<string, string>;

    [Serializable]
    public class OAuthContext : IOAuthContext
    {
        private readonly BoundParameter _bodyHash;

        private readonly BoundParameter _callbackUrl;

        private readonly BoundParameter _consumerKey;

        private readonly BoundParameter _nonce;

        private readonly BoundParameter _sessionHandle;

        private readonly BoundParameter _signature;

        private readonly BoundParameter _signatureMethod;

        private readonly BoundParameter _timestamp;

        private readonly BoundParameter _token;

        private readonly BoundParameter _tokenSecret;

        private readonly BoundParameter _verifier;

        private readonly BoundParameter _version;

        private readonly BoundParameter _xAuthMode;

        private readonly BoundParameter _xAuthPassword;

        private readonly BoundParameter _xAuthUsername;

        private NameValueCollection _authorizationHeaderParameters;

        private NameValueCollection _cookies;

        private NameValueCollection _formEncodedParameters;

        private NameValueCollection _headers;

        private string _normalizedRequestUrl;

        private NameValueCollection _queryParameters;

        private Uri _rawUri;

        public OAuthContext()
        {
            this._verifier = new BoundParameter(Parameters.OAuth_Verifier, this);
            this._consumerKey = new BoundParameter(Parameters.OAuth_Consumer_Key, this);
            this._callbackUrl = new BoundParameter(Parameters.OAuth_Callback, this);
            this._nonce = new BoundParameter(Parameters.OAuth_Nonce, this);
            this._signature = new BoundParameter(Parameters.OAuth_Signature, this);
            this._signatureMethod = new BoundParameter(Parameters.OAuth_Signature_Method, this);
            this._timestamp = new BoundParameter(Parameters.OAuth_Timestamp, this);
            this._token = new BoundParameter(Parameters.OAuth_Token, this);
            this._tokenSecret = new BoundParameter(Parameters.OAuth_Token_Secret, this);
            this._version = new BoundParameter(Parameters.OAuth_Version, this);
            this._sessionHandle = new BoundParameter(Parameters.OAuth_Session_Handle, this);
            this._bodyHash = new BoundParameter(Parameters.OAuth_Body_Hash, this);

            this._xAuthUsername = new BoundParameter(Parameters.XAuthUsername, this);
            this._xAuthPassword = new BoundParameter(Parameters.XAuthPassword, this);
            this._xAuthMode = new BoundParameter(Parameters.XAuthMode, this);

            this.FormEncodedParameters = new NameValueCollection();
            this.Cookies = new NameValueCollection();
            this.Headers = new NameValueCollection();
            this.AuthorizationHeaderParameters = new NameValueCollection();
        }

        public NameValueCollection AuthorizationHeaderParameters
        {
            get
            {
                if (this._authorizationHeaderParameters == null)
                {
                    this._authorizationHeaderParameters = new NameValueCollection();
                }

                return this._authorizationHeaderParameters;
            }

            set { this._authorizationHeaderParameters = value; }
        }

        public string BodyHash
        {
            get { return this._bodyHash.Value; }
            set { this._bodyHash.Value = value; }
        }

        public string CallbackUrl
        {
            get { return this._callbackUrl.Value; }
            set { this._callbackUrl.Value = value; }
        }

        public string ConsumerKey
        {
            get { return this._consumerKey.Value; }
            set { this._consumerKey.Value = value; }
        }

        public NameValueCollection Cookies
        {
            get
            {
                if (this._cookies == null)
                {
                    this._cookies = new NameValueCollection();
                }

                return this._cookies;
            }

            set { this._cookies = value; }
        }

        public NameValueCollection FormEncodedParameters
        {
            get
            {
                if (this._formEncodedParameters == null)
                {
                    this._formEncodedParameters = new NameValueCollection();
                }

                return this._formEncodedParameters;
            }

            set { this._formEncodedParameters = value; }
        }

        public NameValueCollection Headers
        {
            get
            {
                if (this._headers == null)
                {
                    this._headers = new NameValueCollection();
                }

                return this._headers;
            }

            set { this._headers = value; }
        }

        public bool IncludeOAuthRequestBodyHashInSignature { get; set; }

        public string Nonce
        {
            get { return this._nonce.Value; }
            set { this._nonce.Value = value; }
        }

        public string NormalizedRequestUrl
        {
            get { return this._normalizedRequestUrl; }
        }

        public NameValueCollection QueryParameters
        {
            get
            {
                if (this._queryParameters == null)
                {
                    this._queryParameters = new NameValueCollection();
                }

                return this._queryParameters;
            }

            set { this._queryParameters = value; }
        }

        public byte[] RawContent { get; set; }

        public string RawContentType { get; set; }

        public Uri RawUri
        {
            get { return this._rawUri; }

            set
            {
                this._rawUri = value;

                NameValueCollection newParameters = HttpUtility.ParseQueryString(this._rawUri.Query);

                // TODO: tidy this up, bit clunky

                foreach (string parameter in newParameters)
                {
                    this.QueryParameters[parameter] = newParameters[parameter];
                }

                this._normalizedRequestUrl = UriUtility.NormalizeUri(this._rawUri);
            }
        }

        public string Realm
        {
            get { return this.AuthorizationHeaderParameters[Parameters.Realm]; }
            set { this.AuthorizationHeaderParameters[Parameters.Realm] = value; }
        }

        public string RequestMethod { get; set; }

        public string SessionHandle
        {
            get { return this._sessionHandle.Value; }
            set { this._sessionHandle.Value = value; }
        }

        public string Signature
        {
            get { return this._signature.Value; }
            set { this._signature.Value = value; }
        }

        public string SignatureMethod
        {
            get { return this._signatureMethod.Value; }
            set { this._signatureMethod.Value = value; }
        }

        public string Timestamp
        {
            get { return this._timestamp.Value; }
            set { this._timestamp.Value = value; }
        }

        public string Token
        {
            get { return this._token.Value; }
            set { this._token.Value = value; }
        }

        public string TokenSecret
        {
            get { return this._tokenSecret.Value; }
            set { this._tokenSecret.Value = value; }
        }

        public bool UseAuthorizationHeader { get; set; }

        public string Verifier
        {
            get { return this._verifier.Value; }
            set { this._verifier.Value = value; }
        }

        public string Version
        {
            get { return this._version.Value; }
            set { this._version.Value = value; }
        }

        public string XAuthMode
        {
            get { return this._xAuthMode.Value; }
            set { this._xAuthMode.Value = value; }
        }

        public string XAuthPassword
        {
            get { return this._xAuthPassword.Value; }
            set { this._xAuthPassword.Value = value; }
        }

        public string XAuthUsername
        {
            get { return this._xAuthUsername.Value; }
            set { this._xAuthUsername.Value = value; }
        }

        public void GenerateAndSetBodyHash()
        {
            this.BodyHash = this.GenerateBodyHash();
        }

        public string GenerateBodyHash()
        {
            byte[] hash = SHA1.Create().ComputeHash((this.RawContent ?? new byte[0]));
            return Convert.ToBase64String(hash);
        }

        public string GenerateOAuthParametersForHeader()
        {
            var builder = new StringBuilder();

            if (this.Realm != null)
            {
                builder.Append("realm=\"").Append(this.Realm).Append("\"");
            }

            IEnumerable<QueryParameter> parameters = this.AuthorizationHeaderParameters.ToQueryParametersExcludingTokenSecret();

            foreach (
                var parameter in parameters.Where(p => p.Key != Parameters.Realm)
                )
            {
                if (builder.Length > 0)
                {
                    builder.Append(",");
                }

                builder.Append(UriUtility.UrlEncode(parameter.Key)).Append("=\"").Append(
                    UriUtility.UrlEncode(parameter.Value)).Append("\"");
            }

            builder.Insert(0, "OAuth ");

            return builder.ToString();
        }

        public string GenerateSignatureBase()
        {
            if (string.IsNullOrEmpty(this.ConsumerKey))
            {
                throw Error.MissingRequiredOAuthParameter(this, Parameters.OAuth_Consumer_Key);
            }

            if (string.IsNullOrEmpty(this.SignatureMethod))
            {
                throw Error.MissingRequiredOAuthParameter(this, Parameters.OAuth_Signature_Method);
            }

            if (string.IsNullOrEmpty(this.RequestMethod))
            {
                throw Error.RequestMethodHasNotBeenAssigned("RequestMethod");
            }

            if (this.IncludeOAuthRequestBodyHashInSignature)
            {
                this.GenerateAndSetBodyHash();
            }

            var allParameters = new List<QueryParameter>();

            //fix for issue: http://groups.google.com/group/oauth/browse_thread/thread/42ef5fecc54a7e9a/a54e92b13888056c?hl=en&lnk=gst&q=Signing+PUT+Request#a54e92b13888056c
            if (this.FormEncodedParameters != null && this.RequestMethod == "POST")
            {
                allParameters.AddRange(this.FormEncodedParameters.ToQueryParametersExcludingTokenSecret());
            }

            if (this.QueryParameters != null)
            {
                allParameters.AddRange(this.QueryParameters.ToQueryParametersExcludingTokenSecret());
            }

            if (this.Cookies != null)
            {
                allParameters.AddRange(this.Cookies.ToQueryParametersExcludingTokenSecret());
            }

            if (this.AuthorizationHeaderParameters != null)
            {
                allParameters.AddRange(this.AuthorizationHeaderParameters.ToQueryParametersExcludingTokenSecret().Where(q => q.Key != Parameters.Realm));
            }

            allParameters.RemoveAll(param => param.Key == Parameters.OAuth_Signature);

            string signatureBase = UriUtility.FormatParameters(this.RequestMethod, new Uri(this.NormalizedRequestUrl), allParameters);

            return signatureBase;
        }

        public Uri GenerateUri()
        {
            var builder = new UriBuilder(this.NormalizedRequestUrl);

            IEnumerable<QueryParameter> parameters = this.QueryParameters.ToQueryParametersExcludingTokenSecret();

            builder.Query = UriUtility.FormatQueryString(parameters);

            return builder.Uri;
        }

        public Uri GenerateUriWithoutOAuthParameters()
        {
            var builder = new UriBuilder(this.NormalizedRequestUrl);

            IEnumerable<QueryParameter> parameters = this.QueryParameters.ToQueryParameters()
                .Where(q => !q.Key.StartsWith(Parameters.OAuthParameterPrefix) && !q.Key.StartsWith(Parameters.XAuthParameterPrefix));

            builder.Query = UriUtility.FormatQueryString(parameters);

            return builder.Uri;
        }

        public string GenerateUrl()
        {
            var builder = new UriBuilder(this.NormalizedRequestUrl);

            builder.Query = "";

            return builder.Uri + "?" + UriUtility.FormatQueryString(this.QueryParameters);
        }
    }
}