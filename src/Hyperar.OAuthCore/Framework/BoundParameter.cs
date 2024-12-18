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

namespace Hyperar.OAuthCore.Framework
{
    using System.Collections.Specialized;

    internal class BoundParameter
    {
        private readonly OAuthContext _context;

        private readonly string _name;

        /// <summary>
        /// Initializes a new instance of the <see cref="BoundParameter"/> class.
        /// </summary>
        /// <param name="name">The name.</param>
        /// <param name="context">The context.</param>
        public BoundParameter(string name, OAuthContext context)
        {
            this._name = name;
            this._context = context;
        }

        /// <summary>
        /// Gets or sets the value.
        /// </summary>
        /// <value>The value.</value>
        public string? Value
        {
            get
            {
                if (this._context.AuthorizationHeaderParameters?[this._name] != null)
                {
                    return this._context.AuthorizationHeaderParameters[this._name];
                }

                if (this._context.QueryParameters[this._name] != null)
                {
                    return this._context.QueryParameters[this._name];
                }

                if (this._context.FormEncodedParameters[this._name] != null)
                {
                    return this._context.FormEncodedParameters[this._name];
                }

                return null;
            }

            set
            {
                if (value == null)
                {
                    this.Collection.Remove(this._name);
                }
                else
                {
                    this.Collection[this._name] = value;
                }
            }
        }

        /// <summary>
        /// Gets the collection.
        /// </summary>
        /// <value>The collection.</value>
        private NameValueCollection Collection
        {
            get
            {
                if (this._context.UseAuthorizationHeader)
                {
                    return this._context.AuthorizationHeaderParameters ?? new NameValueCollection();
                }

                if (this._context.RequestMethod == "GET")
                {
                    return this._context.QueryParameters;
                }

                return this._context.FormEncodedParameters;
            }
        }
    }
}