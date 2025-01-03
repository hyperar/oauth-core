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
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;

    public class RsaSha1SignatureImplementation : IContextSignatureImplementation
    {
        public string MethodName
        {
            get { return SignatureMethod.RsaSha1; }
        }

        public void SignContext(IOAuthContext authContext, SigningContext signingContext)
        {
            authContext.Signature = GenerateSignature(signingContext);
        }

        public bool ValidateSignature(IOAuthContext? authContext, SigningContext? signingContext)
        {
            ArgumentNullException.ThrowIfNull(authContext);
            ArgumentNullException.ThrowIfNull(signingContext);
            ArgumentException.ThrowIfNullOrWhiteSpace(authContext.Signature);
            ArgumentException.ThrowIfNullOrWhiteSpace(signingContext.SignatureBase);

            if (signingContext.Algorithm == null)
            {
                throw Error.AlgorithmPropertyNotSetOnSigningContext();
            }

            SHA1 sha1 = GenerateHash(signingContext);

            RSAPKCS1SignatureDeformatter deformatter = new RSAPKCS1SignatureDeformatter(signingContext.Algorithm);
            deformatter.SetHashAlgorithm("MD5");

            byte[] signature = Convert.FromBase64String(authContext.Signature);

            return deformatter.VerifySignature(sha1, signature);
        }

        private static SHA1 GenerateHash(SigningContext signingContext)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(signingContext.SignatureBase);

            SHA1 sha1 = SHA1.Create();

            byte[] dataBuffer = Encoding.ASCII.GetBytes(signingContext.SignatureBase);

            CryptoStream cs = new CryptoStream(Stream.Null, sha1, CryptoStreamMode.Write);
            cs.Write(dataBuffer, 0, dataBuffer.Length);
            cs.Close();

            return sha1;
        }

        private static string GenerateSignature(SigningContext signingContext)
        {
            if (signingContext.Algorithm == null)
            {
                throw Error.AlgorithmPropertyNotSetOnSigningContext();
            }

            SHA1 sha1 = GenerateHash(signingContext);

            RSAPKCS1SignatureFormatter formatter = new RSAPKCS1SignatureFormatter(signingContext.Algorithm);
            formatter.SetHashAlgorithm("MD5");

            byte[] signature = formatter.CreateSignature(sha1);

            return Convert.ToBase64String(signature);
        }
    }
}