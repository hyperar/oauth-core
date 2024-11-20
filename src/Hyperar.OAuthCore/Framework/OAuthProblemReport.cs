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
    using System.Collections.Specialized;
    using System.Text;
    using System.Web;

    [Serializable]
    public class OAuthProblemReport
    {
        public OAuthProblemReport()
        {
            this.ParametersRejected = new List<string>();
            this.ParametersAbsent = new List<string>();
        }

        public OAuthProblemReport(NameValueCollection parameters)
        {
            this.Problem = parameters[Parameters.OAuth_Problem];

            this.ProblemAdvice = parameters[Parameters.OAuth_Problem_Advice];

            this.ParametersAbsent = parameters.AllKeys.Any(key => key == Parameters.OAuth_Parameters_Absent)
                                   ? ParseFormattedParameters(parameters[Parameters.OAuth_Parameters_Absent])
                                   : new List<string>();

            this.ParametersRejected = parameters.AllKeys.Any(key => key == Parameters.OAuth_Parameters_Rejected)
                                     ? ParseFormattedParameters(parameters[Parameters.OAuth_Parameters_Rejected])
                                     : new List<string>();

            if (parameters.AllKeys.Any(key => key == Parameters.OAuth_Acceptable_Timestamps))
            {
                string[]? timeStamps = parameters[Parameters.OAuth_Acceptable_Timestamps]?.Split(separatorHyphen);

                this.AcceptableTimeStampsFrom = DateTimeUtility.FromEpoch(Convert.ToInt64(timeStamps?.ElementAtOrDefault(0)));
                this.AcceptableTimeStampsTo = DateTimeUtility.FromEpoch(Convert.ToInt64(timeStamps?.ElementAtOrDefault(1)));
            }

            if (parameters.AllKeys.Any(key => key == Parameters.OAuth_Acceptable_Versions))
            {
                string[]? versions = parameters[Parameters.OAuth_Acceptable_Versions]?.Split(separatorHyphen);

                this.AcceptableVersionFrom = versions?.ElementAtOrDefault(0);
                this.AcceptableVersionTo = versions?.ElementAtOrDefault(1);
            }
        }

        public OAuthProblemReport(string formattedReport)
            : this(HttpUtility.ParseQueryString(formattedReport))
        {
        }

        public DateTime? AcceptableTimeStampsFrom { get; set; }

        public DateTime? AcceptableTimeStampsTo { get; set; }

        public string? AcceptableVersionFrom { get; set; }

        public string? AcceptableVersionTo { get; set; }

        public List<string>? ParametersAbsent { get; set; }

        public List<string>? ParametersRejected { get; set; }

        public string? Problem { get; set; }

        public string? ProblemAdvice { get; set; }

        private static readonly char[] separatorHyphen = new[] { '-' };
        private static readonly char[] separatorAmpersand = new[] { '&' };

        public override string ToString()
        {
            if (string.IsNullOrEmpty(this.Problem))
            {
                throw Error.CantBuildProblemReportWhenProblemEmpty();
            }

            NameValueCollection response = new NameValueCollection
            {
                [Parameters.OAuth_Problem] = this.Problem
            };

            if (!string.IsNullOrEmpty(this.ProblemAdvice))
            {
                response[Parameters.OAuth_Problem_Advice] = this.ProblemAdvice.Replace("\r\n", "\n").Replace("\r", "\n");
            }

            if (this.ParametersAbsent?.Count > 0)
            {
                response[Parameters.OAuth_Parameters_Absent] = FormatParameterNames(this.ParametersAbsent);
            }

            if (this.ParametersRejected?.Count > 0)
            {
                response[Parameters.OAuth_Parameters_Rejected] = FormatParameterNames(this.ParametersRejected);
            }

            if (this.AcceptableTimeStampsFrom.HasValue && this.AcceptableTimeStampsTo.HasValue)
            {
                response[Parameters.OAuth_Acceptable_Timestamps] = string.Format("{0}-{1}",
                                                                                 this.AcceptableTimeStampsFrom.Value.Epoch(),
                                                                                 this.AcceptableTimeStampsTo.Value.Epoch());
            }

            if (!(string.IsNullOrEmpty(this.AcceptableVersionFrom) || string.IsNullOrEmpty(this.AcceptableVersionTo)))
            {
                response[Parameters.OAuth_Acceptable_Versions] = string.Format("{0}-{1}", this.AcceptableVersionFrom,
                                                                               this.AcceptableVersionTo);
            }

            return UriUtility.FormatQueryString(response);
        }

        private static string FormatParameterNames(IEnumerable<string> names)
        {
            StringBuilder builder = new StringBuilder();

            foreach (string name in names)
            {
                if (builder.Length > 0)
                {
                    _ = builder.Append('&');
                }

                _ = builder.Append(UriUtility.UrlEncode(name));
            }

            return builder.ToString();
        }

        private static List<string>? ParseFormattedParameters(string? formattedList)
        {
            return formattedList?.Split(separatorAmpersand, StringSplitOptions.RemoveEmptyEntries).ToList();
        }
    }
}