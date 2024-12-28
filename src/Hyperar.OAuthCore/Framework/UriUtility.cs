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
    using System.Text;
    using System.Web;
    using QueryParameter = System.Collections.Generic.KeyValuePair<string, string>;

    public static class UriUtility
    {
        private const string OAuthAuthorizationHeaderStart = "OAuth";

        private static readonly string[] HexEscapedUriRfc3986CharsToEscape;

        private static readonly string[] QuoteCharacters = new[] { "\"", "'" };

        private static readonly char[] separator = new[] { ',' };

        private static readonly string[] UriRfc3986CharsToEscape = new[] { "!", "*", "'", "(", ")" };

        static UriUtility()
        {
            HexEscapedUriRfc3986CharsToEscape = UriRfc3986CharsToEscape.Select(c => Uri.HexEscape(c[0])).ToArray();
        }

        /// <summary>
        /// Takes an http method, url and a set of parameters and formats them as a signature base as per the OAuth core spec.
        /// </summary>
        /// <param name="httpMethod"></param>
        /// <param name="url"></param>
        /// <param name="parameters"></param>
        /// <returns></returns>
        public static string FormatParameters(string httpMethod, Uri? url, List<QueryParameter> parameters)
        {
            ArgumentNullException.ThrowIfNull(url);

            string normalizedRequestParameters = NormalizeRequestParameters(parameters);

            StringBuilder signatureBase = new StringBuilder();
            _ = signatureBase.AppendFormat("{0}&", httpMethod.ToUpper());

            _ = signatureBase.AppendFormat("{0}&", UrlEncode(NormalizeUri(url)));
            _ = signatureBase.AppendFormat("{0}", UrlEncode(normalizedRequestParameters));

            return signatureBase.ToString();
        }

        /// <summary>
        /// Formats a set of query parameters, as per query string encoding.
        /// </summary>
        /// <param name="parameters"></param>
        /// <returns></returns>
        public static string FormatQueryString(IEnumerable<KeyValuePair<string, string>> parameters)
        {
            StringBuilder builder = new StringBuilder();

            if (parameters != null)
            {
                foreach (QueryParameter pair in parameters)
                {
                    if (builder.Length > 0)
                    {
                        _ = builder.Append('&');
                    }

                    _ = builder.Append(pair.Key).Append('=');
                    _ = builder.Append(UrlEncode(pair.Value));
                }
            }

            return builder.ToString();
        }

        /// <summary>
        /// Formats a set of query parameters, as per query string encoding.
        /// </summary>
        /// <param name="parameters"></param>
        /// <returns></returns>
        public static string FormatQueryString(NameValueCollection parameters)
        {
            StringBuilder builder = new StringBuilder();

            if (parameters != null)
            {
                foreach (string key in parameters.Keys)
                {
                    if (builder.Length > 0)
                    {
                        _ = builder.Append('&');
                    }

                    _ = builder.Append(key).Append('=');
                    _ = builder.Append(UrlEncode(parameters[key]));
                }
            }

            return builder.ToString();
        }

        public static string FormatTokenForResponse(IToken token)
        {
            StringBuilder builder = new StringBuilder();

            _ = builder.Append(Parameters.OAuth_Token).Append('=').Append(UrlEncode(token.Token))
                .Append('&').Append(Parameters.OAuth_Token_Secret).Append('=').Append(UrlEncode(token.TokenSecret));

            return builder.ToString();
        }

        /// <summary>
        /// Extracts all the parameters from the supplied encoded parameters.
        /// </summary>
        /// <param name="parameters"></param>
        /// <returns></returns>
        public static List<QueryParameter>? GetHeaderParameters(string? parameters)
        {
            if (parameters == null)
            {
                return null;
            }

            parameters = parameters.Trim();

            List<QueryParameter> result = new List<QueryParameter>();

            if (!parameters.StartsWith(OAuthAuthorizationHeaderStart, StringComparison.InvariantCultureIgnoreCase))
            {
                return result;
            }

            parameters = parameters.Substring(OAuthAuthorizationHeaderStart.Length).Trim();

            if (!string.IsNullOrEmpty(parameters))
            {
                string[] p = parameters.Split(separator, StringSplitOptions.RemoveEmptyEntries);

                foreach (string s in p)
                {
                    if (string.IsNullOrEmpty(s))
                    {
                        continue;
                    }

                    QueryParameter parameter = ParseAuthorizationHeaderKeyValuePair(s);
                    result.Add(parameter);
                }
            }

            return result;
        }

        /// <summary>
        /// Extracts all the parameters from the supplied encoded parameters.
        /// </summary>
        /// <param name="parameters"></param>
        /// <returns></returns>
        public static List<QueryParameter> GetQueryParameters(string parameters)
        {
            if (parameters.StartsWith('?'))
            {
                parameters = parameters.Remove(0, 1);
            }

            List<QueryParameter> result = new List<QueryParameter>();

            if (!string.IsNullOrEmpty(parameters))
            {
                string[] p = parameters.Split('&');
                foreach (string s in p)
                {
                    if (!string.IsNullOrEmpty(s) && !s.StartsWith(Parameters.OAuthParameterPrefix) && !s.StartsWith(Parameters.XAuthParameterPrefix))
                    {
                        if (s.IndexOf('=') > -1)
                        {
                            string[] temp = s.Split('=');
                            result.Add(new QueryParameter(temp[0], temp[1]));
                        }
                        else
                        {
                            result.Add(new QueryParameter(s, string.Empty));
                        }
                    }
                }
            }

            return result;
        }

        /// <summary>
        /// Normalizes a sequence of key/value pair parameters as per the OAuth core specification.
        /// </summary>
        /// <param name="parameters"></param>
        /// <returns></returns>
        public static string NormalizeRequestParameters(IEnumerable<QueryParameter> parameters)
        {
            IEnumerable<QueryParameter> orderedParameters = parameters
                .OrderBy(x => x.Key, StringComparer.Ordinal)
                .ThenBy(x => x.Value)
                .Select(
                    x => new QueryParameter(x.Key, UrlEncode(x.Value)));

            StringBuilder builder = new StringBuilder();

            foreach (QueryParameter parameter in orderedParameters)
            {
                if (builder.Length > 0)
                {
                    _ = builder.Append('&');
                }

                _ = builder.Append(parameter.Key).Append('=').Append(parameter.Value);
            }

            return builder.ToString();
        }

        /// <summary>
        /// Normalizes a Url according to the OAuth specification (this ensures http or https on a default port is not displayed
        /// with the :XXX following the host in the url).
        /// </summary>
        /// <param name="uri"></param>
        /// <returns></returns>
        public static string NormalizeUri(Uri uri)
        {
            string normalizedUrl = string.Format("{0}://{1}", uri.Scheme, uri.Host);

            if (!((uri.Scheme == "http" && uri.Port == 80) ||
                  (uri.Scheme == "https" && uri.Port == 443)))
            {
                normalizedUrl += ":" + uri.Port;
            }

            return normalizedUrl + ((uri.AbsolutePath == "/") ? "" : uri.AbsolutePath);
        }

        public static QueryParameter ParseAuthorizationHeaderKeyValuePair(string keyEqualValuePair)
        {
            int indexOfEqualSign = keyEqualValuePair.IndexOf('=');

            if (indexOfEqualSign > 0)
            {
                string key = keyEqualValuePair.Substring(0, indexOfEqualSign).Trim();

                string quotedValue = keyEqualValuePair.Substring(indexOfEqualSign + 1);

                string itemValue = StripQuotes(quotedValue);

                itemValue = HttpUtility.UrlDecode(itemValue);

                return new QueryParameter(key, itemValue);
            }

            return new QueryParameter(keyEqualValuePair.Trim(), string.Empty);
        }

        public static NameValueCollection ToNameValueCollection(this IEnumerable<QueryParameter> source)
        {
            NameValueCollection collection = new NameValueCollection();

            foreach (QueryParameter parameter in source)
            {
                collection[parameter.Key] = parameter.Value;
            }

            return collection;
        }

        public static IEnumerable<QueryParameter> ToQueryParameters(this NameValueCollection source)
        {
            foreach (string key in source)
            {
                yield return new QueryParameter(key, source[key] ?? string.Empty);
            }
        }

        public static IEnumerable<QueryParameter> ToQueryParametersExcludingTokenSecret(this NameValueCollection source)
        {
            foreach (string key in source)
            {
                if (key != Parameters.OAuth_Token_Secret)
                {
                    yield return new QueryParameter(key, source[key] ?? string.Empty);
                }
            }
        }

        public static string UrlEncode(string? value)
        {
            return EscapeUriDataStringRfc3986(value);
        }

        // see http://stackoverflow.com/questions/846487/how-to-get-uri-escapedatastring-to-comply-with-rfc-3986 for details
        private static string EscapeUriDataStringRfc3986(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return string.Empty;
            }

            // Fix for the exception Uri.EscapeDataString throws when the string is longer than 32766
            // Microsoft documentation http://msdn.microsoft.com/en-us/library/system.uri.escapedatastring.aspx
            StringBuilder escaped = new StringBuilder();

            const int maxChunkSize = 32766;

            for (int i = 0; i <= value.Length; i += maxChunkSize)
            {
                string substring = value.Substring(i, Math.Min(value.Length - i, maxChunkSize));
                _ = escaped.Append(Uri.EscapeDataString(substring));
            }

            for (int i = 0; i < UriRfc3986CharsToEscape.Length; i++)
            {
                _ = escaped.Replace(UriRfc3986CharsToEscape[i], HexEscapedUriRfc3986CharsToEscape[i]);
            }

            return escaped.ToString();
        }

        private static string StripQuotes(string quotedValue)
        {
            foreach (string quoteCharacter in QuoteCharacters)
            {
                if (quotedValue.StartsWith(quoteCharacter) && quotedValue.EndsWith(quoteCharacter) && quotedValue.Length > 1)
                {
                    return quotedValue.Substring(1, quotedValue.Length - 2);
                }
            }

            return quotedValue;
        }
    }
}