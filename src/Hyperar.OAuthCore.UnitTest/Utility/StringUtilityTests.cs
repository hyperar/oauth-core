﻿namespace Hyperar.OAuthCore.UnitTest.Utility
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

    using System.Diagnostics;
    using System.Linq;
    using Hyperar.OAuthCore.Utility;

    [TestClass]
    public class StringUtilityTests
    {
        public static long TimeCompareValuesOverIterationsConstantTime(string value, string other, int iterations)
        {
            Stopwatch stopWatch = Stopwatch.StartNew();

            for (int i = 0; i < iterations; i++)
            {
                _ = value.EqualsInConstantTime(other);
            }

            return stopWatch.ElapsedTicks;
        }

        public static long TimeCompareValuesOverIterationsStringEquals(string value, string other, int iterations)
        {
            Stopwatch stopWatch = Stopwatch.StartNew();

            for (int i = 0; i < iterations; i++)
            {
                _ = value.Equals(other);
            }

            return stopWatch.ElapsedTicks;
        }

        [TestMethod]
        public void EqualsInConstantTimeComparesInConstantTimeRegardlessOfPercentMatchToWithinMarginOfError()
        {
            const int length = 10 * 1024; // 10K characters - big enough to avoid wild fluctuations in timing

            const int numberOfTimestoCompare = 10000;

            string value = GenerateTestString(1.0, length);

            long[] rangesOfTime = Enumerable.Range(0, 100)
                .Select(range => GenerateTestString(range / 100.0, length)).ToArray()
                .Select(other => TimeCompareValuesOverIterationsConstantTime(value, other, numberOfTimestoCompare))
                .ToArray();

            long[] stringEqualsRangesOfTime = Enumerable.Range(0, 100)
                .Select(range => GenerateTestString(range / 100.0, length)).ToArray()
                .Select(other => TimeCompareValuesOverIterationsStringEquals(value, other, numberOfTimestoCompare))
                .ToArray();

            decimal percentDifference = CalculatePercentageDifference(rangesOfTime);

            decimal percentDifferenceStringEquals = CalculatePercentageDifference(stringEqualsRangesOfTime);

            Assert.IsTrue(percentDifference < 0.50m, string.Format("Difference in time when calculating is never greater then 50%, but was: {0:0.00%}", percentDifference));

            // if you break here and check values, you should see that percentDifferenceStringEquals is dramatically wider i.e. maximum time to compare may be 100 times greater
            // then minimum time to compare.

            Assert.IsTrue(percentDifferenceStringEquals > percentDifference);
        }

        [DataTestMethod]
        [DataRow("XY", "XY")]
        [DataRow("42", "42")]
        [DataRow("YX", "XY")]
        [DataRow("Y", "Y")]
        [DataRow("Y", "X")]
        [DataRow("X", "Y")]
        [DataRow("Xy", "XY")]
        [DataRow("yX", "yX")]
        [DataRow("XY", "Y")]
        [DataRow("X", "XY")]
        [DataRow("X", "")]
        [DataRow("", "X")]
        [DataRow(null, "XY")]
        [DataRow("XY", null)]
        [DataRow(null, null)]
        [DataRow("", null)]
        [DataRow(null, "")]
        [DataRow("", "")]
        public void EqualsInConstantTimeReturnsSameResultsAsStringEquals(string value, string other)
        {
            bool expected = string.Equals(value, other);
            Assert.AreEqual(expected, value.EqualsInConstantTime(other));
        }

        private static decimal CalculatePercentageDifference(long[] rangesOfTime)
        {
            long maxTime = rangesOfTime.Max();

            long minTime = rangesOfTime.Min();

            return 1.0m - (1.0m / maxTime * minTime);
        }

        private static string GenerateTestString(double percentMatch, int length)
        {
            int matchLength = (int)(percentMatch * length);
            int nonMatchLength = length - matchLength;

            if (nonMatchLength == 0)
            {
                return new string('X', length);
            }

            return new string('X', matchLength) + new string('Y', nonMatchLength);
        }
    }
}