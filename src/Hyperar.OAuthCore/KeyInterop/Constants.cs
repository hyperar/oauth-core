namespace Hyperar.OAuthCore.KeyInterop
{
    using System;

    internal static class Constants
    {
        internal static readonly byte[] EMPTY = Array.Empty<byte>();

        internal static readonly byte[] ZERO = new byte[] { 0 };

        internal static readonly char[] SeparatorSpaceAndDot = new char[] { ' ', '.' };

        internal const string IncorrectSequenceSizeMessage = "Incorrect Sequence Size. ";

        internal const string SpecifiedRemainingMessageMask = "Specified: {0}, Remaining: {1}";

        internal const string IncorrectAlgorithmIdentifierSizeMessage = "Incorrect AlgorithmIdentifier Size. ";

        internal const string SpecifiedIdentifierMessageMask = "Specified Identifier: {0}";

        internal const string ErrorParsingKeyMessage = "Error Parsing Key";
    }
}
