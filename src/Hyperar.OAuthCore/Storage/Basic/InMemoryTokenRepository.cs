﻿// The MIT License
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
    using System.Collections.Generic;
    using Hyperar.OAuthCore.Framework;

    /// <summary>
    /// In-Memory implementation of a token repository
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public class InMemoryTokenRepository<T> : ITokenRepository<T>
        where T : TokenBase
    {
        private readonly Dictionary<string, T> _tokens = new Dictionary<string, T>();

        public T GetToken(string? token)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(token);

            return this._tokens[token];
        }

        public void SaveToken(T token)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(token.Token);

            this._tokens[token.Token] = token;
        }
    }
}