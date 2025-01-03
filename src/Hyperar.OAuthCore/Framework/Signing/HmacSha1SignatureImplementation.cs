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

namespace Hyperar.OAuthCore.Framework.Signing
{
    using System;
    using System.Security.Cryptography;
    using System.Text;
    using Hyperar.OAuthCore.Utility;

    public class HmacSha1SignatureImplementation : IContextSignatureImplementation
    {
        public string MethodName
        {
            get { return SignatureMethod.HmacSha1; }
        }

        public void SignContext(IOAuthContext authContext, SigningContext signingContext)
        {
            authContext.Signature = GenerateSignature(authContext, signingContext);
        }

        public bool ValidateSignature(IOAuthContext? authContext, SigningContext? signingContext)
        {
            ArgumentNullException.ThrowIfNull(authContext);
            ArgumentNullException.ThrowIfNull(signingContext);
            ArgumentException.ThrowIfNullOrWhiteSpace(authContext.Signature);
            ArgumentException.ThrowIfNullOrWhiteSpace(signingContext.SignatureBase);

            return authContext.Signature.EqualsInConstantTime(GenerateSignature(authContext, signingContext));
        }

        private static string ComputeHash(HashAlgorithm hashAlgorithm, string? data)
        {
            ArgumentNullException.ThrowIfNull(hashAlgorithm);
            ArgumentException.ThrowIfNullOrWhiteSpace(data);

            byte[] dataBuffer = Encoding.ASCII.GetBytes(data);
            byte[] hashBytes = hashAlgorithm.ComputeHash(dataBuffer);

            return Convert.ToBase64String(hashBytes);
        }

        private static string GenerateSignature(IToken authContext, SigningContext signingContext)
        {
            string consumerSecret = (signingContext.ConsumerSecret != null)
                                        ? UriUtility.UrlEncode(signingContext.ConsumerSecret)
                                        : "";
            string? tokenSecret = (authContext.TokenSecret != null)
                                ? UriUtility.UrlEncode(authContext.TokenSecret)
                                : null;

            string hashSource = string.Format("{0}&{1}", consumerSecret, tokenSecret);

            HMACSHA1 hashAlgorithm = new HMACSHA1 { Key = Encoding.ASCII.GetBytes(hashSource) };

            return ComputeHash(hashAlgorithm, signingContext.SignatureBase);
        }
    }
}