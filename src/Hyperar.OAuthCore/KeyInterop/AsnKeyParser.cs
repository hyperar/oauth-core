namespace Hyperar.OauthCore.KeyInterop
{
    #region License

    // The MIT License
    //
    // Copyright (c) 2022 Hyperar.
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
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Globalization;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;

    public class AsnKeyParser
    {
        private readonly AsnParser parser;

        public AsnKeyParser(String pathname)
        {
            using (var reader = new BinaryReader(
                new FileStream(pathname, FileMode.Open, FileAccess.Read)))
            {
                var info = new FileInfo(pathname);

                this.parser = new AsnParser(reader.ReadBytes((int)info.Length));
            }
        }

        public AsnKeyParser(byte[] contents)
        {
            this.parser = new AsnParser(contents);
        }

        public static byte[] TrimLeadingZero(byte[] values)
        {
            byte[] r = null;
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

        public RSAParameters ParseRSAPublicKey()
        {
            var parameters = new RSAParameters();

            // Current value
            byte[] value = null;

            // Sanity Check
            int length = 0;

            // Checkpoint
            int position = this.parser.CurrentPosition();

            // Ignore Sequence - PublicKeyInfo
            length = this.parser.NextSequence();
            if (length != this.parser.RemainingBytes())
            {
                var sb = new StringBuilder("Incorrect Sequence Size. ");
                sb.AppendFormat("Specified: {0}, Remaining: {1}",
                                length.ToString(CultureInfo.InvariantCulture),
                                this.parser.RemainingBytes().ToString(CultureInfo.InvariantCulture));
                throw new BerDecodeException(sb.ToString(), position);
            }

            // Checkpoint
            position = this.parser.CurrentPosition();

            // Ignore Sequence - AlgorithmIdentifier
            length = this.parser.NextSequence();
            if (length > this.parser.RemainingBytes())
            {
                var sb = new StringBuilder("Incorrect AlgorithmIdentifier Size. ");
                sb.AppendFormat("Specified: {0}, Remaining: {1}",
                                length.ToString(CultureInfo.InvariantCulture),
                                this.parser.RemainingBytes().ToString(CultureInfo.InvariantCulture));
                throw new BerDecodeException(sb.ToString(), position);
            }

            // Checkpoint
            position = this.parser.CurrentPosition();

            // Grab the OID
            value = this.parser.NextOID();
            byte[] oid = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
            if (!EqualOid(value, oid))
            {
                throw new BerDecodeException("Expected OID 1.2.840.113549.1.1.1", position);
            }

            // Optional Parameters
            if (this.parser.IsNextNull())
            {
                this.parser.NextNull();

                // Also OK: value = parser.Next();
            }
            else
            {
                // Gracefully skip the optional data
                value = this.parser.Next();
            }

            // Checkpoint
            position = this.parser.CurrentPosition();

            // Ignore BitString - PublicKey
            length = this.parser.NextBitString();
            if (length > this.parser.RemainingBytes())
            {
                var sb = new StringBuilder("Incorrect PublicKey Size. ");
                sb.AppendFormat("Specified: {0}, Remaining: {1}",
                                length.ToString(CultureInfo.InvariantCulture),
                                (this.parser.RemainingBytes()).ToString(CultureInfo.InvariantCulture));
                throw new BerDecodeException(sb.ToString(), position);
            }

            // Checkpoint
            position = this.parser.CurrentPosition();

            // Ignore Sequence - RSAPublicKey
            length = this.parser.NextSequence();
            if (length < this.parser.RemainingBytes())
            {
                var sb = new StringBuilder("Incorrect RSAPublicKey Size. ");
                sb.AppendFormat("Specified: {0}, Remaining: {1}",
                                length.ToString(CultureInfo.InvariantCulture),
                                this.parser.RemainingBytes().ToString(CultureInfo.InvariantCulture));
                throw new BerDecodeException(sb.ToString(), position);
            }

            parameters.Modulus = TrimLeadingZero(this.parser.NextInteger());
            parameters.Exponent = TrimLeadingZero(this.parser.NextInteger());

            Debug.Assert(0 == this.parser.RemainingBytes());

            return parameters;
        }

        public RSAParameters ParseRSAPrivateKey()
        {
            var parameters = new RSAParameters();

            // Current value
            byte[] value = null;

            // Checkpoint
            int position = this.parser.CurrentPosition();

            // Sanity Check
            int length = 0;

            // Ignore Sequence - PrivateKeyInfo
            length = this.parser.NextSequence();
            if (length != this.parser.RemainingBytes())
            {
                var sb = new StringBuilder("Incorrect Sequence Size. ");
                sb.AppendFormat("Specified: {0}, Remaining: {1}",
                                length.ToString(CultureInfo.InvariantCulture),
                                this.parser.RemainingBytes().ToString(CultureInfo.InvariantCulture));
                throw new BerDecodeException(sb.ToString(), position);
            }

            // Checkpoint
            position = this.parser.CurrentPosition();

            // Version
            value = this.parser.NextInteger();
            if (0x00 != value[0])
            {
                var sb = new StringBuilder("Incorrect PrivateKeyInfo Version. ");
                var v = new BigInteger(value);
                sb.AppendFormat("Expected: 0, Specified: {0}", v.ToString(10));
                throw new BerDecodeException(sb.ToString(), position);
            }

            // Checkpoint
            position = this.parser.CurrentPosition();

            // Ignore Sequence - AlgorithmIdentifier
            length = this.parser.NextSequence();
            if (length > this.parser.RemainingBytes())
            {
                var sb = new StringBuilder("Incorrect AlgorithmIdentifier Size. ");
                sb.AppendFormat("Specified: {0}, Remaining: {1}",
                                length.ToString(CultureInfo.InvariantCulture),
                                this.parser.RemainingBytes().ToString(CultureInfo.InvariantCulture));
                throw new BerDecodeException(sb.ToString(), position);
            }

            // Checkpoint
            position = this.parser.CurrentPosition();

            // Grab the OID
            value = this.parser.NextOID();
            byte[] oid = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
            if (!EqualOid(value, oid))
            {
                throw new BerDecodeException("Expected OID 1.2.840.113549.1.1.1", position);
            }

            // Optional Parameters
            if (this.parser.IsNextNull())
            {
                this.parser.NextNull();

                // Also OK: value = parser.Next();
            }
            else
            {
                // Gracefully skip the optional data
                value = this.parser.Next();
            }

            // Checkpoint
            position = this.parser.CurrentPosition();

            // Ignore OctetString - PrivateKey
            length = this.parser.NextOctetString();
            if (length > this.parser.RemainingBytes())
            {
                var sb = new StringBuilder("Incorrect PrivateKey Size. ");
                sb.AppendFormat("Specified: {0}, Remaining: {1}",
                                length.ToString(CultureInfo.InvariantCulture),
                                this.parser.RemainingBytes().ToString(CultureInfo.InvariantCulture));
                throw new BerDecodeException(sb.ToString(), position);
            }

            // Checkpoint
            position = this.parser.CurrentPosition();

            // Ignore Sequence - RSAPrivateKey
            length = this.parser.NextSequence();
            if (length < this.parser.RemainingBytes())
            {
                var sb = new StringBuilder("Incorrect RSAPrivateKey Size. ");
                sb.AppendFormat("Specified: {0}, Remaining: {1}",
                                length.ToString(CultureInfo.InvariantCulture),
                                this.parser.RemainingBytes().ToString(CultureInfo.InvariantCulture));
                throw new BerDecodeException(sb.ToString(), position);
            }

            // Checkpoint
            position = this.parser.CurrentPosition();

            // Version
            value = this.parser.NextInteger();
            if (0x00 != value[0])
            {
                var sb = new StringBuilder("Incorrect RSAPrivateKey Version. ");
                var v = new BigInteger(value);
                sb.AppendFormat("Expected: 0, Specified: {0}", v.ToString(10));
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

        public DSAParameters ParseDSAPublicKey()
        {
            var parameters = new DSAParameters();

            // Current value
            byte[] value = null;

            // Current Position
            int position = this.parser.CurrentPosition();

            // Sanity Checks
            int length = 0;

            // Ignore Sequence - PublicKeyInfo
            length = this.parser.NextSequence();
            if (length != this.parser.RemainingBytes())
            {
                var sb = new StringBuilder("Incorrect Sequence Size. ");
                sb.AppendFormat("Specified: {0}, Remaining: {1}",
                                length.ToString(CultureInfo.InvariantCulture),
                                this.parser.RemainingBytes().ToString(CultureInfo.InvariantCulture));
                throw new BerDecodeException(sb.ToString(), position);
            }

            // Checkpoint
            position = this.parser.CurrentPosition();

            // Ignore Sequence - AlgorithmIdentifier
            length = this.parser.NextSequence();
            if (length > this.parser.RemainingBytes())
            {
                var sb = new StringBuilder("Incorrect AlgorithmIdentifier Size. ");
                sb.AppendFormat("Specified: {0}, Remaining: {1}",
                                length.ToString(CultureInfo.InvariantCulture),
                                this.parser.RemainingBytes().ToString(CultureInfo.InvariantCulture));
                throw new BerDecodeException(sb.ToString(), position);
            }

            // Checkpoint
            position = this.parser.CurrentPosition();

            // Grab the OID
            value = this.parser.NextOID();
            byte[] oid = { 0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01 };
            if (!EqualOid(value, oid))
            {
                throw new BerDecodeException("Expected OID 1.2.840.10040.4.1", position);
            }

            // Checkpoint
            position = this.parser.CurrentPosition();

            // Ignore Sequence - DSS-Params
            length = this.parser.NextSequence();
            if (length > this.parser.RemainingBytes())
            {
                var sb = new StringBuilder("Incorrect DSS-Params Size. ");
                sb.AppendFormat("Specified: {0}, Remaining: {1}",
                                length.ToString(CultureInfo.InvariantCulture),
                                this.parser.RemainingBytes().ToString(CultureInfo.InvariantCulture));
                throw new BerDecodeException(sb.ToString(), position);
            }

            // Next three are curve parameters
            parameters.P = TrimLeadingZero(this.parser.NextInteger());
            parameters.Q = TrimLeadingZero(this.parser.NextInteger());
            parameters.G = TrimLeadingZero(this.parser.NextInteger());

            // Ignore BitString - PrivateKey
            this.parser.NextBitString();

            // Public Key
            parameters.Y = TrimLeadingZero(this.parser.NextInteger());

            Debug.Assert(0 == this.parser.RemainingBytes());

            return parameters;
        }

        public DSAParameters ParseDSAPrivateKey()
        {
            var parameters = new DSAParameters();

            // Current value
            byte[] value = null;

            // Current Position
            int position = this.parser.CurrentPosition();

            // Sanity Checks
            int length = 0;

            // Ignore Sequence - PrivateKeyInfo
            length = this.parser.NextSequence();
            if (length != this.parser.RemainingBytes())
            {
                var sb = new StringBuilder("Incorrect Sequence Size. ");
                sb.AppendFormat("Specified: {0}, Remaining: {1}",
                                length.ToString(CultureInfo.InvariantCulture),
                                this.parser.RemainingBytes().ToString(CultureInfo.InvariantCulture));
                throw new BerDecodeException(sb.ToString(), position);
            }

            // Checkpoint
            position = this.parser.CurrentPosition();

            // Version
            value = this.parser.NextInteger();
            if (0x00 != value[0])
            {
                throw new BerDecodeException("Incorrect PrivateKeyInfo Version", position);
            }

            // Checkpoint
            position = this.parser.CurrentPosition();

            // Ignore Sequence - AlgorithmIdentifier
            length = this.parser.NextSequence();
            if (length > this.parser.RemainingBytes())
            {
                var sb = new StringBuilder("Incorrect AlgorithmIdentifier Size. ");
                sb.AppendFormat("Specified: {0}, Remaining: {1}",
                                length.ToString(CultureInfo.InvariantCulture),
                                this.parser.RemainingBytes().ToString(CultureInfo.InvariantCulture));
                throw new BerDecodeException(sb.ToString(), position);
            }

            // Checkpoint
            position = this.parser.CurrentPosition();

            // Grab the OID
            value = this.parser.NextOID();
            byte[] oid = { 0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01 };
            if (!EqualOid(value, oid))
            {
                throw new BerDecodeException("Expected OID 1.2.840.10040.4.1", position);
            }

            // Checkpoint
            position = this.parser.CurrentPosition();

            // Ignore Sequence - DSS-Params
            length = this.parser.NextSequence();
            if (length > this.parser.RemainingBytes())
            {
                var sb = new StringBuilder("Incorrect DSS-Params Size. ");
                sb.AppendFormat("Specified: {0}, Remaining: {1}",
                                length.ToString(CultureInfo.InvariantCulture),
                                this.parser.RemainingBytes().ToString(CultureInfo.InvariantCulture));
                throw new BerDecodeException(sb.ToString(), position);
            }

            // Next three are curve parameters
            parameters.P = TrimLeadingZero(this.parser.NextInteger());
            parameters.Q = TrimLeadingZero(this.parser.NextInteger());
            parameters.G = TrimLeadingZero(this.parser.NextInteger());

            // Ignore OctetString - PrivateKey
            this.parser.NextOctetString();

            // Private Key
            parameters.X = TrimLeadingZero(this.parser.NextInteger());

            Debug.Assert(0 == this.parser.RemainingBytes());

            return parameters;
        }
    }

    internal class AsnParser
    {
        private readonly int initialCount;

        private readonly List<byte> octets;

        public AsnParser(byte[] values)
        {
            this.octets = new List<byte>(values.Length);
            this.octets.AddRange(values);

            this.initialCount = this.octets.Count;
        }

        public int CurrentPosition()
        {
            return this.initialCount - this.octets.Count;
        }

        public int RemainingBytes()
        {
            return this.octets.Count;
        }

        private int GetLength()
        {
            int length = 0;

            // Checkpoint
            int position = this.CurrentPosition();

            try
            {
                byte b = this.GetNextOctet();

                if (b == (b & 0x7f))
                {
                    return b;
                }
                int i = b & 0x7f;

                if (i > 4)
                {
                    var sb = new StringBuilder("Invalid Length Encoding. ");
                    sb.AppendFormat("Length uses {0} octets",
                                    i.ToString(CultureInfo.InvariantCulture));
                    throw new BerDecodeException(sb.ToString(), position);
                }

                while (0 != i--)
                {
                    // shift left
                    length <<= 8;

                    length |= this.GetNextOctet();
                }
            }
            catch (ArgumentOutOfRangeException ex)
            {
                throw new BerDecodeException("Error Parsing Key", position, ex);
            }

            return length;
        }

        public byte[] Next()
        {
            int position = this.CurrentPosition();

            try
            {
#pragma warning disable 0219
                byte b = this.GetNextOctet();
#pragma warning restore 0219

                int length = this.GetLength();
                if (length > this.RemainingBytes())
                {
                    var sb = new StringBuilder("Incorrect Size. ");
                    sb.AppendFormat("Specified: {0}, Remaining: {1}",
                                    length.ToString(CultureInfo.InvariantCulture),
                                    this.RemainingBytes().ToString(CultureInfo.InvariantCulture));
                    throw new BerDecodeException(sb.ToString(), position);
                }

                return this.GetOctets(length);
            }
            catch (ArgumentOutOfRangeException ex)
            {
                throw new BerDecodeException("Error Parsing Key", position, ex);
            }
        }

        public byte GetNextOctet()
        {
            int position = this.CurrentPosition();

            if (0 == this.RemainingBytes())
            {
                var sb = new StringBuilder("Incorrect Size. ");
                sb.AppendFormat("Specified: {0}, Remaining: {1}",
                                1.ToString(CultureInfo.InvariantCulture),
                                this.RemainingBytes().ToString(CultureInfo.InvariantCulture));
                throw new BerDecodeException(sb.ToString(), position);
            }

            byte b = this.GetOctets(1)[0];

            return b;
        }

        public byte[] GetOctets(int octetCount)
        {
            int position = this.CurrentPosition();

            if (octetCount > this.RemainingBytes())
            {
                var sb = new StringBuilder("Incorrect Size. ");
                sb.AppendFormat("Specified: {0}, Remaining: {1}",
                                octetCount.ToString(CultureInfo.InvariantCulture),
                                this.RemainingBytes().ToString(CultureInfo.InvariantCulture));
                throw new BerDecodeException(sb.ToString(), position);
            }

            var values = new byte[octetCount];

            try
            {
                this.octets.CopyTo(0, values, 0, octetCount);
                this.octets.RemoveRange(0, octetCount);
            }
            catch (ArgumentOutOfRangeException ex)
            {
                throw new BerDecodeException("Error Parsing Key", position, ex);
            }

            return values;
        }

        public bool IsNextNull()
        {
            return 0x05 == this.octets[0];
        }

        public int NextNull()
        {
            int position = this.CurrentPosition();

            try
            {
                byte b = this.GetNextOctet();
                if (0x05 != b)
                {
                    var sb = new StringBuilder("Expected Null. ");
                    sb.AppendFormat("Specified Identifier: {0}", b.ToString(CultureInfo.InvariantCulture));
                    throw new BerDecodeException(sb.ToString(), position);
                }

                // Next octet must be 0
                b = this.GetNextOctet();
                if (0x00 != b)
                {
                    var sb = new StringBuilder("Null has non-zero size. ");
                    sb.AppendFormat("Size: {0}", b.ToString(CultureInfo.InvariantCulture));
                    throw new BerDecodeException(sb.ToString(), position);
                }

                return 0;
            }
            catch (ArgumentOutOfRangeException ex)
            {
                throw new BerDecodeException("Error Parsing Key", position, ex);
            }
        }

        public bool IsNextSequence()
        {
            return 0x30 == this.octets[0];
        }

        public int NextSequence()
        {
            int position = this.CurrentPosition();

            try
            {
                byte b = this.GetNextOctet();
                if (0x30 != b)
                {
                    var sb = new StringBuilder("Expected Sequence. ");
                    sb.AppendFormat("Specified Identifier: {0}",
                                    b.ToString(CultureInfo.InvariantCulture));
                    throw new BerDecodeException(sb.ToString(), position);
                }

                int length = this.GetLength();
                if (length > this.RemainingBytes())
                {
                    var sb = new StringBuilder("Incorrect Sequence Size. ");
                    sb.AppendFormat("Specified: {0}, Remaining: {1}",
                                    length.ToString(CultureInfo.InvariantCulture),
                                    this.RemainingBytes().ToString(CultureInfo.InvariantCulture));
                    throw new BerDecodeException(sb.ToString(), position);
                }

                return length;
            }
            catch (ArgumentOutOfRangeException ex)
            {
                throw new BerDecodeException("Error Parsing Key", position, ex);
            }
        }

        public bool IsNextOctetString()
        {
            return 0x04 == this.octets[0];
        }

        public int NextOctetString()
        {
            int position = this.CurrentPosition();

            try
            {
                byte b = this.GetNextOctet();
                if (0x04 != b)
                {
                    var sb = new StringBuilder("Expected Octet String. ");
                    sb.AppendFormat("Specified Identifier: {0}", b.ToString(CultureInfo.InvariantCulture));
                    throw new BerDecodeException(sb.ToString(), position);
                }

                int length = this.GetLength();
                if (length > this.RemainingBytes())
                {
                    var sb = new StringBuilder("Incorrect Octet String Size. ");
                    sb.AppendFormat("Specified: {0}, Remaining: {1}",
                                    length.ToString(CultureInfo.InvariantCulture),
                                    this.RemainingBytes().ToString(CultureInfo.InvariantCulture));
                    throw new BerDecodeException(sb.ToString(), position);
                }

                return length;
            }
            catch (ArgumentOutOfRangeException ex)
            {
                throw new BerDecodeException("Error Parsing Key", position, ex);
            }
        }

        public bool IsNextBitString()
        {
            return 0x03 == this.octets[0];
        }

        public int NextBitString()
        {
            int position = this.CurrentPosition();

            try
            {
                byte b = this.GetNextOctet();
                if (0x03 != b)
                {
                    var sb = new StringBuilder("Expected Bit String. ");
                    sb.AppendFormat("Specified Identifier: {0}", b.ToString(CultureInfo.InvariantCulture));
                    throw new BerDecodeException(sb.ToString(), position);
                }

                int length = this.GetLength();

                // We need to consume unused bits, which is the first
                //   octet of the remaing values
                b = this.octets[0];
                this.octets.RemoveAt(0);
                length--;

                if (0x00 != b)
                {
                    throw new BerDecodeException("The first octet of BitString must be 0", position);
                }

                return length;
            }
            catch (ArgumentOutOfRangeException ex)
            {
                throw new BerDecodeException("Error Parsing Key", position, ex);
            }
        }

        public bool IsNextInteger()
        {
            return 0x02 == this.octets[0];
        }

        public byte[] NextInteger()
        {
            int position = this.CurrentPosition();

            try
            {
                byte b = this.GetNextOctet();
                if (0x02 != b)
                {
                    var sb = new StringBuilder("Expected Integer. ");
                    sb.AppendFormat("Specified Identifier: {0}", b.ToString(CultureInfo.InvariantCulture));
                    throw new BerDecodeException(sb.ToString(), position);
                }

                int length = this.GetLength();
                if (length > this.RemainingBytes())
                {
                    var sb = new StringBuilder("Incorrect Integer Size. ");
                    sb.AppendFormat("Specified: {0}, Remaining: {1}",
                                    length.ToString(CultureInfo.InvariantCulture),
                                    this.RemainingBytes().ToString(CultureInfo.InvariantCulture));
                    throw new BerDecodeException(sb.ToString(), position);
                }

                return this.GetOctets(length);
            }
            catch (ArgumentOutOfRangeException ex)
            {
                throw new BerDecodeException("Error Parsing Key", position, ex);
            }
        }

        public byte[] NextOID()
        {
            int position = this.CurrentPosition();

            try
            {
                byte b = this.GetNextOctet();
                if (0x06 != b)
                {
                    var sb = new StringBuilder("Expected Object Identifier. ");
                    sb.AppendFormat("Specified Identifier: {0}",
                                    b.ToString(CultureInfo.InvariantCulture));
                    throw new BerDecodeException(sb.ToString(), position);
                }

                int length = this.GetLength();
                if (length > this.RemainingBytes())
                {
                    var sb = new StringBuilder("Incorrect Object Identifier Size. ");
                    sb.AppendFormat("Specified: {0}, Remaining: {1}",
                                    length.ToString(CultureInfo.InvariantCulture),
                                    this.RemainingBytes().ToString(CultureInfo.InvariantCulture));
                    throw new BerDecodeException(sb.ToString(), position);
                }

                var values = new byte[length];

                for (int i = 0; i < length; i++)
                {
                    values[i] = this.octets[0];
                    this.octets.RemoveAt(0);
                }

                return values;
            }
            catch (ArgumentOutOfRangeException ex)
            {
                throw new BerDecodeException("Error Parsing Key", position, ex);
            }
        }
    }
}