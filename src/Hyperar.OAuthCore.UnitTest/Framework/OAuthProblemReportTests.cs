namespace Hyperar.OAuthCore.UnitTest.Framework
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

    #endregion

    using System;
    using Hyperar.OauthCore.Framework;

    [TestClass]
    public class OAuthProblemReportTests
    {
        [TestMethod]
        public void FormatMissingParameterReport()
        {
            var report = new OAuthProblemReport
            {
                Problem = OAuthProblems.ParameterAbsent,
                ParametersAbsent = { Parameters.OAuth_Nonce }
            };

            Assert.AreEqual("oauth_problem=parameter_absent&oauth_parameters_absent=oauth_nonce", report.ToString());
        }

        [TestMethod]
        public void FormatRejectedParameterReport()
        {
            var report = new OAuthProblemReport
            {
                Problem = OAuthProblems.ParameterRejected,
                ParametersRejected = { Parameters.OAuth_Timestamp }
            };

            Assert.AreEqual("oauth_problem=parameter_rejected&oauth_parameters_rejected=oauth_timestamp",
                         report.ToString());
        }

        [TestMethod]
        public void FormatReportWithAdvice()
        {
            var report = new OAuthProblemReport
            {
                Problem = OAuthProblems.ConsumerKeyRefused,
                ProblemAdvice = "The supplied consumer key has been black-listed due to complaints."
            };

            Assert.AreEqual(
                "oauth_problem=consumer_key_refused&oauth_problem_advice=The%20supplied%20consumer%20key%20has%20been%20black-listed%20due%20to%20complaints.",
                report.ToString());
        }

        [TestMethod]
        public void FormatTimestampRangeReport()
        {
            var report = new OAuthProblemReport
            {
                Problem = OAuthProblems.TimestampRefused,
                AcceptableTimeStampsFrom = new DateTime(2008, 1, 1),
                AcceptableTimeStampsTo = new DateTime(2009, 1, 1)
            };

            Assert.AreEqual("oauth_problem=timestamp_refused&oauth_acceptable_timestamps=1199142000-1230764400",
                         report.ToString());
        }

        [TestMethod]
        public void FormatVersionRangeReport()
        {
            var report = new OAuthProblemReport
            {
                Problem = OAuthProblems.VersionRejected,
                AcceptableVersionFrom = "1.0",
                AcceptableVersionTo = "2.0"
            };

            Assert.AreEqual("oauth_problem=version_rejected&oauth_acceptable_versions=1.0-2.0", report.ToString());
        }

        [TestMethod]
        public void PopulateFromFormattedMissingParameterReport()
        {
            string formatted = "oauth_problem=parameter_absent&oauth_parameters_absent=oauth_nonce";

            var report = new OAuthProblemReport(formatted);

            Assert.AreEqual(OAuthProblems.ParameterAbsent, report.Problem);
            Assert.IsTrue(report.ParametersAbsent.Contains(Parameters.OAuth_Nonce));
        }

        [TestMethod]
        public void PopulateFromFormattedRejectedParameterReport()
        {
            string formatted = "oauth_problem=parameter_rejected&oauth_parameters_rejected=oauth_timestamp";

            var report = new OAuthProblemReport(formatted);

            Assert.AreEqual(OAuthProblems.ParameterRejected, report.Problem);
            Assert.IsTrue(report.ParametersRejected.Contains(Parameters.OAuth_Timestamp));
        }

        [TestMethod]
        public void PopulateFromFormattedReportWithAdvice()
        {
            string formatted =
                "oauth_problem=consumer_key_refused&oauth_problem_advice=The%20supplied%20consumer%20key%20has%20been%20black-listed%20due%20to%20complaints.";

            var report = new OAuthProblemReport(formatted);

            Assert.AreEqual(report.Problem, OAuthProblems.ConsumerKeyRefused);
            Assert.AreEqual("The supplied consumer key has been black-listed due to complaints.", report.ProblemAdvice);
        }

        [TestMethod]
        public void PopulateFromFormattedTimestampRangeReport()
        {
            string formatted = "oauth_problem=timestamp_refused&oauth_acceptable_timestamps=1199142000-1230764400";

            var report = new OAuthProblemReport(formatted);

            Assert.AreEqual(OAuthProblems.TimestampRefused, report.Problem);
            Assert.AreEqual(new DateTime(2008, 1, 1), report.AcceptableTimeStampsFrom);
            Assert.AreEqual(new DateTime(2009, 1, 1), report.AcceptableTimeStampsTo);
        }

        [TestMethod]
        public void PopulateFromFormattedVersionRangeReport()
        {
            string formatted = "oauth_problem=version_rejected&oauth_acceptable_versions=1.0-2.0";

            var report = new OAuthProblemReport(formatted);

            Assert.AreEqual(OAuthProblems.VersionRejected, report.Problem);
            Assert.AreEqual("1.0", report.AcceptableVersionFrom);
            Assert.AreEqual("2.0", report.AcceptableVersionTo);
        }
    }
}