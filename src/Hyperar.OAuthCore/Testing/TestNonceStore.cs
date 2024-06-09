namespace Hyperar.OAuthCore.Testing
{
    #region License

    // The MIT License
    //
    // Copyright (c) 2006-2008 DevDefined Limited.
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

    #endregion License

    using System.Collections.Generic;
    using Hyperar.OAuthCore.Framework;
    using Hyperar.OAuthCore.Storage;

    /// <summary>
    /// A simple nonce store that just tracks all nonces by consumer key in memory.
    /// </summary>
    public class TestNonceStore : INonceStore
    {
        private readonly Dictionary<string, List<string>> _nonces = new Dictionary<string, List<string>>();

        public bool RecordNonceAndCheckIsUnique(IConsumer consumer, string nonce)
        {
            List<string> list = this.GetNonceListForConsumer(consumer.ConsumerKey);
            lock (list)
            {
                if (list.Contains(nonce))
                {
                    return false;
                }

                list.Add(nonce);
                return true;
            }
        }

        private List<string> GetNonceListForConsumer(string consumerKey)
        {
            var list = new List<string>();

            if (!this._nonces.TryGetValue(consumerKey, out list))
            {
                lock (this._nonces)
                {
                    if (!this._nonces.TryGetValue(consumerKey, out list))
                    {
                        list = new List<string>();
                        this._nonces[consumerKey] = list;
                    }
                }
            }

            return list;
        }
    }
}