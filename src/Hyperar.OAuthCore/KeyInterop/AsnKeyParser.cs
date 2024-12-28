namespace Hyperar.OAuthCore.KeyInterop
{
    #region License

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

    #endregion License

    using System;
    using System.Diagnostics;
    using System.Globalization;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;

    public class AsnKeyParser
    {
        private readonly AsnParser parser;

        public AsnKeyParser(string pathname)
        {
            using (BinaryReader reader = new BinaryReader(
                new FileStream(pathname, FileMode.Open, FileAccess.Read)))
            {
                FileInfo info = new FileInfo(pathname);

                this.parser = new AsnParser(reader.ReadBytes((int)info.Length));
            }
        }

        public AsnKeyParser(byte[] contents)
        {
            this.parser = new AsnParser(contents);
        }

        public static bool EqualOid(byte[] first, byte[] second)
        {
            if (first.Length != second.Length)
            {
                return false;
            }

            for (int i = 0; i < first.Length; i++)
            {
                if (first[i] != second[i])
                {
                    return false;
                }
            }

            return true;
        }

        public static byte[] TrimLeadingZero(byte[] values)
        {
            byte[] r;
            if ((0x00 == values[0]) && (values.Length > 1))
            {
                r = new byte[values.Length - 1];
                Array.Copy(values, 1, r, 0, values.Length - 1);
            }
            else
            {
                r = new byte[values.Length];
                Array.Copy(values, r, values.Length);
            }

            return r;
        }

        public DSAParameters ParseDSAPrivateKey()
        {
            DSAParameters parameters = new DSAParameters();

            this.ValidateSequenceSize();

            // Checkpoint
            int position = this.parser.CurrentPosition();

            // Current value
            // Version
            byte[] value = this.parser.NextInteger();

            if (0x00 != value[0])
            {
                throw new BerDecodeException("Incorrect PrivateKeyInfo Version", position);
            }

            this.ValidateAlgorithmIdentifierSize();

            this.ValidateDsaKeyOid();

            this.ValidateDdsParametersSize();

            // Next three are curve parameters
            parameters.P = TrimLeadingZero(this.parser.NextInteger());
            parameters.Q = TrimLeadingZero(this.parser.NextInteger());
            parameters.G = TrimLeadingZero(this.parser.NextInteger());

            // Ignore OctetString - PrivateKey
            _ = this.parser.NextOctetString();

            // Private Key
            parameters.X = TrimLeadingZero(this.parser.NextInteger());

            Debug.Assert(0 == this.parser.RemainingBytes());

            return parameters;
        }

        public DSAParameters ParseDSAPublicKey()
        {
            DSAParameters parameters = new DSAParameters();

            this.ValidateSequenceSize();

            this.ValidateAlgorithmIdentifierSize();

            this.ValidateDsaKeyOid();

            this.ValidateDdsParametersSize();

            // Next three are curve parameters
            parameters.P = TrimLeadingZero(this.parser.NextInteger());
            parameters.Q = TrimLeadingZero(this.parser.NextInteger());
            parameters.G = TrimLeadingZero(this.parser.NextInteger());

            // Ignore BitString - PrivateKey
            _ = this.parser.NextBitString();

            // Public Key
            parameters.Y = TrimLeadingZero(this.parser.NextInteger());

            Debug.Assert(0 == this.parser.RemainingBytes());

            return parameters;
        }

        public RSAParameters ParseRSAPrivateKey()
        {
            RSAParameters parameters = new RSAParameters();

            this.ValidateSequenceSize();

            // Checkpoint
            int position = this.parser.CurrentPosition();

            // Current value
            // Version
            byte[] value = this.parser.NextInteger();

            if (0x00 != value[0])
            {
                StringBuilder sb = new StringBuilder("Incorrect PrivateKeyInfo Version. ");

                BigInteger v = new BigInteger(value);

                _ = sb.AppendFormat("Expected: 0, Specified: {0}", v.ToString(10));

                throw new BerDecodeException(sb.ToString(), position);
            }

            this.ValidateAlgorithmIdentifierSize();

            this.ValidateRsaKeyOid();

            // Optional Parameters
            if (this.parser.IsNextNull())
            {
                _ = this.parser.NextNull();

                // Also OK: value = parser.Next();
            }
            else
            {
                // Gracefully skip the optional data
                _ = this.parser.Next();
            }

            // Checkpoint
            position = this.parser.CurrentPosition();

            // Ignore OctetString - PrivateKey
            int length = this.parser.NextOctetString();

            if (length > this.parser.RemainingBytes())
            {
                StringBuilder sb = new StringBuilder("Incorrect PrivateKey Size. ");

                _ = sb.AppendFormat(
                    Constants.SpecifiedRemainingMessageMask,
                    length.ToString(CultureInfo.InvariantCulture),
                    this.parser.RemainingBytes()
                               .ToString(CultureInfo.InvariantCulture));

                throw new BerDecodeException(sb.ToString(), position);
            }

            // Checkpoint
            position = this.parser.CurrentPosition();

            // Ignore Sequence - RSAPrivateKey
            length = this.parser.NextSequence();

            if (length < this.parser.RemainingBytes())
            {
                StringBuilder sb = new StringBuilder("Incorrect RSAPrivateKey Size. ");

                _ = sb.AppendFormat(
                    Constants.SpecifiedRemainingMessageMask,
                    length.ToString(CultureInfo.InvariantCulture),
                    this.parser.RemainingBytes()
                               .ToString(CultureInfo.InvariantCulture));

                throw new BerDecodeException(sb.ToString(), position);
            }

            // Checkpoint
            position = this.parser.CurrentPosition();

            // Version
            value = this.parser.NextInteger();
            if (0x00 != value[0])
            {
                StringBuilder sb = new StringBuilder("Incorrect RSAPrivateKey Version. ");

                BigInteger v = new BigInteger(value);

                _ = sb.AppendFormat("Expected: 0, Specified: {0}", v.ToString(10));

                throw new BerDecodeException(sb.ToString(), position);
            }

            parameters.Modulus = TrimLeadingZero(this.parser.NextInteger());
            parameters.Exponent = TrimLeadingZero(this.parser.NextInteger());
            parameters.D = TrimLeadingZero(this.parser.NextInteger());
            parameters.P = TrimLeadingZero(this.parser.NextInteger());
            parameters.Q = TrimLeadingZero(this.parser.NextInteger());
            parameters.DP = TrimLeadingZero(this.parser.NextInteger());
            parameters.DQ = TrimLeadingZero(this.parser.NextInteger());
            parameters.InverseQ = TrimLeadingZero(this.parser.NextInteger());

            Debug.Assert(0 == this.parser.RemainingBytes());

            return parameters;
        }

        public RSAParameters ParseRSAPublicKey()
        {
            RSAParameters parameters = new RSAParameters();

            this.ValidateSequenceSize();

            this.ValidateAlgorithmIdentifierSize();

            this.ValidateRsaKeyOid();

            // Optional Parameters
            if (this.parser.IsNextNull())
            {
                _ = this.parser.NextNull();

                // Also OK: value = parser.Next();
            }
            else
            {
                // Gracefully skip the optional data
                _ = this.parser.Next();
            }

            // Checkpoint
            int position = this.parser.CurrentPosition();

            // Ignore BitString - PublicKey
            int length = this.parser.NextBitString();

            if (length > this.parser.RemainingBytes())
            {
                StringBuilder sb = new StringBuilder("Incorrect PublicKey Size. ");

                _ = sb.AppendFormat(
                    Constants.SpecifiedRemainingMessageMask,
                    length.ToString(CultureInfo.InvariantCulture),
                    this.parser.RemainingBytes()
                               .ToString(CultureInfo.InvariantCulture));

                throw new BerDecodeException(sb.ToString(), position);
            }

            // Checkpoint
            position = this.parser.CurrentPosition();

            // Ignore Sequence - RSAPublicKey
            length = this.parser.NextSequence();

            if (length < this.parser.RemainingBytes())
            {
                StringBuilder sb = new StringBuilder("Incorrect RSAPublicKey Size. ");

                _ = sb.AppendFormat(
                    Constants.SpecifiedRemainingMessageMask,
                    length.ToString(CultureInfo.InvariantCulture),
                    this.parser.RemainingBytes()
                               .ToString(CultureInfo.InvariantCulture));

                throw new BerDecodeException(sb.ToString(), position);
            }

            parameters.Modulus = TrimLeadingZero(this.parser.NextInteger());
            parameters.Exponent = TrimLeadingZero(this.parser.NextInteger());

            Debug.Assert(0 == this.parser.RemainingBytes());

            return parameters;
        }

        private void ValidateAlgorithmIdentifierSize()
        {
            // Checkpoint
            int position = this.parser.CurrentPosition();

            // Ignore Sequence - AlgorithmIdentifier
            int length = this.parser.NextSequence();

            if (length > this.parser.RemainingBytes())
            {
                StringBuilder sb = new StringBuilder(Constants.IncorrectAlgorithmIdentifierSizeMessage);

                _ = sb.AppendFormat(
                    Constants.SpecifiedRemainingMessageMask,
                    length.ToString(CultureInfo.InvariantCulture),
                    this.parser.RemainingBytes()
                               .ToString(CultureInfo.InvariantCulture));

                throw new BerDecodeException(sb.ToString(), position);
            }
        }

        private void ValidateDdsParametersSize()
        {
            // Checkpoint
            int position = this.parser.CurrentPosition();

            // Ignore Sequence - DSS-Params
            int length = this.parser.NextSequence();

            if (length > this.parser.RemainingBytes())
            {
                StringBuilder sb = new StringBuilder("Incorrect DSS-Params Size. ");

                _ = sb.AppendFormat(
                    Constants.SpecifiedRemainingMessageMask,
                    length.ToString(CultureInfo.InvariantCulture),
                    this.parser.RemainingBytes()
                               .ToString(CultureInfo.InvariantCulture));

                throw new BerDecodeException(sb.ToString(), position);
            }
        }

        private void ValidateDsaKeyOid()
        {
            // Checkpoint
            int position = this.parser.CurrentPosition();

            // Grab the OID
            byte[] value = this.parser.NextOID();

            byte[] oid = { 0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01 };

            if (!EqualOid(value, oid))
            {
                throw new BerDecodeException("Expected OID 1.2.840.10040.4.1", position);
            }
        }

        private void ValidateRsaKeyOid()
        {
            // Checkpoint
            int position = this.parser.CurrentPosition();

            // Grab the OID
            byte[] value = this.parser.NextOID();

            byte[] oid = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };

            if (!EqualOid(value, oid))
            {
                throw new BerDecodeException("Expected OID 1.2.840.113549.1.1.1", position);
            }
        }

        private void ValidateSequenceSize()
        {
            // Current Position
            int position = this.parser.CurrentPosition();

            // Ignore Sequence - PrivateKeyInfo
            int length = this.parser.NextSequence();

            if (length != this.parser.RemainingBytes())
            {
                StringBuilder sb = new StringBuilder(Constants.IncorrectSequenceSizeMessage);

                _ = sb.AppendFormat(
                    Constants.SpecifiedRemainingMessageMask,
                    length.ToString(CultureInfo.InvariantCulture),
                    this.parser.RemainingBytes()
                               .ToString(CultureInfo.InvariantCulture));

                throw new BerDecodeException(sb.ToString(), position);
            }
        }
    }
}