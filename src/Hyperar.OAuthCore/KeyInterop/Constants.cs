namespace Hyperar.OAuthCore.KeyInterop
{
    using System;

    internal static class Constants
    {
        internal static byte[] EMPTY = Array.Empty<byte>();

        internal static byte[] ZERO = new byte[] { 0 };

        internal static char[] SeparatorSpaceAndDot = new char[] { ' ', '.' };

        internal const string IncorrectSequenceSizeMessage = "Incorrect Sequence Size. ";

        internal const string SpecifiedRemainingMessageMask = "Specified: {0}, Remaining: {1}";

        internal const string IncorrectAlgorithmIdentifierSizeMessage = "Incorrect AlgorithmIdentifier Size. ";

        internal const string SpecifiedIdentifierMessageMask = "Specified Identifier: {0}";
    }
}
