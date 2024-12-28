namespace Hyperar.OAuthCore.KeyInterop
{
    using System;

    internal static class Constants
    {
        internal const string ErrorParsingKeyMessage = "Error Parsing Key";

        internal const string IncorrectAlgorithmIdentifierSizeMessage = "Incorrect AlgorithmIdentifier Size. ";

        internal const string IncorrectSequenceSizeMessage = "Incorrect Sequence Size. ";

        internal const string SpecifiedIdentifierMessageMask = "Specified Identifier: {0}";

        internal const string SpecifiedRemainingMessageMask = "Specified: {0}, Remaining: {1}";

        internal static readonly byte[] EMPTY = Array.Empty<byte>();

        internal static readonly char[] SeparatorSpaceAndDot = new char[] { ' ', '.' };

        internal static readonly byte[] ZERO = new byte[] { 0 };
    }
}