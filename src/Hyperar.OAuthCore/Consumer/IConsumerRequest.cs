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
    using System.Xml.Linq;
    using Hyperar.OAuthCore.Framework;

    public interface IConsumerRequest
    {
        string? AcceptsType { get; set; }

        IOAuthConsumerContext ConsumerContext { get; }

        IOAuthContext Context { get; }

        Uri? ProxyServerUri { get; set; }

        string? RequestBody { get; set; }

        Action<string>? ResponseBodyAction { get; set; }

        int? Timeout { get; set; }

        RequestDescription GetRequestDescription();

        IConsumerRequest SignWithoutToken();

        IConsumerRequest SignWithToken();

        IConsumerRequest SignWithToken(IToken token);

        Task<NameValueCollection> ToBodyParametersAsync();

        Task<byte[]> ToBytesAsync();

        HttpRequestMessage ToRequestMessage();

        Task<HttpResponseMessage> ToResponseMessageAsync();

        Task<string> ToStringAsync();

        Task<XDocument> ToXDocumentAsync();
    }
}