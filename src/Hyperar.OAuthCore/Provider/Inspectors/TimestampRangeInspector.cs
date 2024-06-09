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

namespace Hyperar.OAuthCore.Provider.Inspectors
{
    using System;
    using Hyperar.OAuthCore.Framework;
    using Hyperar.OAuthCore.Utility;

    public class TimestampRangeInspector : IContextInspector
    {
        private readonly TimeSpan _maxAfterNow;

        private readonly TimeSpan _maxBeforeNow;

        private readonly Func<DateTime> _nowFunc;

        public TimestampRangeInspector(TimeSpan window)
            : this(new TimeSpan(window.Ticks / 2), new TimeSpan(window.Ticks / 2))
        {
        }

        public TimestampRangeInspector(TimeSpan maxBeforeNow, TimeSpan maxAfterNow)
            : this(maxBeforeNow, maxAfterNow, () => Clock.Now)
        {
        }

        public TimestampRangeInspector(TimeSpan maxBeforeNow, TimeSpan maxAfterNow, Func<DateTime> nowFunc)
        {
            this._maxBeforeNow = maxBeforeNow;
            this._maxAfterNow = maxAfterNow;
            this._nowFunc = nowFunc;
        }

        public void InspectContext(ProviderPhase phase, IOAuthContext context)
        {
            DateTime timestamp = DateTimeUtility.FromEpoch(Convert.ToInt32(context.Timestamp));
            DateTime now = this._nowFunc();

            if (now.Subtract(this._maxBeforeNow) > timestamp)
            {
                throw new OAuthException(context, OAuthProblems.TimestampRefused,
                                         string.Format(
                                             "The timestamp is to old, it must be at most {0} seconds before the servers current date and time",
                                             this._maxBeforeNow.TotalSeconds));
            }
            if (now.Add(this._maxAfterNow) < timestamp)
            {
                throw new OAuthException(context, OAuthProblems.TimestampRefused,
                                         string.Format(
                                             "The timestamp is to far in the future, if must be at most {0} seconds after the server current date and time",
                                             this._maxAfterNow.TotalSeconds));
            }
        }
    }
}