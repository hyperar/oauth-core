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

namespace Hyperar.OAuthCore.KeyInterop
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Globalization;
    using System.Security.Cryptography;

    internal static class AsnKeyBuilder
    {

        /// <summary>
        /// <para>An ordered sequence of zero, one or more bits. Returns
        /// the AsnType representing an ASN.1 encoded bit string.</para>
        /// <para>If octets is null or length is 0, an empty (0 length)
        /// bit string is returned.</para>
        /// </summary>
        /// <param name="octets">A MSB (big endian) byte[] representing the
        /// bit string to be encoded.</param>
        /// <returns>Returns the AsnType representing an ASN.1
        /// encoded bit string.</returns>
        /// <seealso cref="CreateBitString(byte[], uint)"/>
        /// <seealso cref="CreateBitString(AsnType)"/>
        /// <seealso cref="CreateBitString(AsnType[])"/>
        /// <seealso cref="CreateBitString(string)"/>
        /// <seealso cref="CreateOctetString(byte[])"/>
        /// <seealso cref="CreateOctetString(AsnType)"/>
        /// <seealso cref="CreateOctetString(AsnType[])"/>
        /// <seealso cref="CreateOctetString(string)"/>
        public static AsnType CreateBitString(byte[] octets)
        {
            // BitString: Tag 0x03 (3, Universal, Primitive)
            return CreateBitString(octets, 0);
        }

        /// <summary>
        /// <para>An ordered sequence of zero, one or more bits. Returns
        /// the AsnType representing an ASN.1 encoded bit string.</para>
        /// <para>unusedBits is applied to the end of the bit string,
        /// not the start of the bit string. unusedBits must be less than 8
        /// (the size of an octet). Refer to ITU X.680, Section 32.</para>
        /// <para>If octets is null or length is 0, an empty (0 length)
        /// bit string is returned.</para>
        /// </summary>
        /// <param name="octets">A MSB (big endian) byte[] representing the
        /// bit string to be encoded.</param>
        /// <param name="unusedBits">The number of unused trailing binary
        /// digits in the bit string to be encoded.</param>
        /// <returns>Returns the AsnType representing an ASN.1
        /// encoded bit string.</returns>
        /// <seealso cref="CreateBitString(byte[])"/>
        /// <seealso cref="CreateBitString(AsnType)"/>
        /// <seealso cref="CreateBitString(AsnType[])"/>
        /// <seealso cref="CreateBitString(string)"/>
        /// <seealso cref="CreateOctetString(byte[])"/>
        /// <seealso cref="CreateOctetString(AsnType)"/>
        /// <seealso cref="CreateOctetString(AsnType[])"/>
        /// <seealso cref="CreateOctetString(string)"/>
        public static AsnType CreateBitString(byte[] octets, uint unusedBits)
        {
            if (IsEmpty(octets))
            {
                // Empty octet string
                return new AsnType(0x03, Constants.EMPTY);
            }

            if (!(unusedBits < 8))
            {
                throw new ArgumentException("Unused bits must be less than 8.");
            }

            byte[] b = Concatenate(new byte[] { (byte)unusedBits }, octets);

            // BitString: Tag 0x03 (3, Universal, Primitive)
            return new AsnType(0x03, b);
        }

        /// <summary>
        /// An ordered sequence of zero, one or more bits. Returns
        /// the AsnType representing an ASN.1 encoded bit string.
        /// If value is null, an empty (0 length) bit string is
        /// returned.
        /// </summary>
        /// <param name="value">An AsnType object to be encoded.</param>
        /// <returns>Returns the AsnType representing an ASN.1
        /// encoded bit string.</returns>
        /// <seealso cref="CreateBitString(byte[])"/>
        /// <seealso cref="CreateBitString(byte[], uint)"/>
        /// <seealso cref="CreateBitString(AsnType[])"/>
        /// <seealso cref="CreateBitString(string)"/>
        /// <seealso cref="CreateOctetString(byte[])"/>
        /// <seealso cref="CreateOctetString(AsnType)"/>
        /// <seealso cref="CreateOctetString(AsnType[])"/>
        /// <seealso cref="CreateOctetString(string)"/>
        public static AsnType CreateBitString(AsnType value)
        {
            if (IsEmpty(value))
            {
                return new AsnType(0x03, Constants.EMPTY);
            }

            // BitString: Tag 0x03 (3, Universal, Primitive)
            return CreateBitString(value.GetBytes(), 0x00);
        }

        /// <summary>
        /// An ordered sequence of zero, one or more bits. Returns
        /// the AsnType representing an ASN.1 encoded bit string.
        /// If value is null, an empty (0 length) bit string is
        /// returned.
        /// </summary>
        /// <param name="values">An AsnType object to be encoded.</param>
        /// <returns>Returns the AsnType representing an ASN.1
        /// encoded bit string.</returns>
        /// <seealso cref="CreateBitString(byte[])"/>
        /// <seealso cref="CreateBitString(byte[], uint)"/>
        /// <seealso cref="CreateBitString(AsnType)"/>
        /// <seealso cref="CreateBitString(string)"/>
        /// <seealso cref="CreateOctetString(byte[])"/>
        /// <seealso cref="CreateOctetString(AsnType)"/>
        /// <seealso cref="CreateOctetString(AsnType[])"/>
        /// <seealso cref="CreateOctetString(string)"/>
        public static AsnType CreateBitString(AsnType[] values)
        {
            if (IsEmpty(values))
            {
                return new AsnType(0x03, Constants.EMPTY);
            }

            // BitString: Tag 0x03 (3, Universal, Primitive)
            return CreateBitString(Concatenate(values), 0x00);
        }

        /// <summary>
        /// <para>An ordered sequence of zero, one or more bits. Returns
        /// the AsnType representing an ASN.1 encoded bit string.</para>
        /// <para>If octets is null or length is 0, an empty (0 length)
        /// bit string is returned.</para>
        /// <para>If conversion fails, the bit string returned is a partial
        /// bit string. The partial bit string ends at the octet before the
        /// point of failure (it does not include the octet which could
        /// not be parsed, or subsequent octets).</para>
        /// </summary>
        /// <param name="value">A MSB (big endian) byte[] representing the
        /// bit string to be encoded.</param>
        /// <returns>Returns the AsnType representing an ASN.1
        /// encoded bit string.</returns>
        /// <seealso cref="CreateBitString(byte[])"/>
        /// <seealso cref="CreateBitString(byte[], uint)"/>
        /// <seealso cref="CreateBitString(AsnType)"/>
        /// <seealso cref="CreateOctetString(byte[])"/>
        /// <seealso cref="CreateOctetString(AsnType)"/>
        /// <seealso cref="CreateOctetString(AsnType[])"/>
        /// <seealso cref="CreateOctetString(string)"/>
        public static AsnType CreateBitString(string value)
        {
            if (IsEmpty(value))
            {
                return CreateBitString(Constants.EMPTY);
            }

            // Any unused bits?
            int lstrlen = value.Length;
            int unusedBits = 8 - (lstrlen % 8);
            if (8 == unusedBits)
            {
                unusedBits = 0;
            }

            for (int i = 0; i < unusedBits; i++)
            {
                value += "0";
            }

            // Determine number of octets
            int loctlen = (lstrlen + 7) / 8;

            List<byte> octets = new List<byte>();
            for (int i = 0; i < loctlen; i++)
            {
                string s = value.Substring(i * 8, 8);
                byte b;
                try
                {
                    b = Convert.ToByte(s, 2);
                }
                catch (FormatException /*e*/)
                {
                    unusedBits = 0;
                    break;
                }
                catch (OverflowException /*e*/)
                {
                    unusedBits = 0;
                    break;
                }

                octets.Add(b);
            }

            // BitString: Tag 0x03 (3, Universal, Primitive)
            return CreateBitString(octets.ToArray(), (uint)unusedBits);
        }

        /// <summary>
        /// <para>Returns the AsnType representing a ASN.1 encoded
        /// integer. The octets pass through this method are not modified.</para>
        /// <para>If octets is null or zero length, the method returns an
        /// AsnType equivalent to CreateInteger(byte[]{0})..</para>
        /// </summary>
        /// <param name="value">A MSB (big endian) byte[] representing the
        /// integer to be encoded.</param>
        /// <returns>Returns the AsnType representing an ASN.1
        /// encoded integer.</returns>
        /// <example>
        /// ASN.1 encoded 0:
        /// <code>CreateInteger(null)</code>
        /// <code>CreateInteger(new byte[]{0x00})</code>
        /// <code>CreateInteger(new byte[]{0x00, 0x00})</code>
        /// </example>
        /// <example>
        /// ASN.1 encoded 1:
        /// <code>CreateInteger(new byte[]{0x01})</code>
        /// </example>
        /// <seealso cref="CreateIntegerPos"/>
        /// <seealso cref="CreateIntegerNeg"/>
        public static AsnType CreateInteger(byte[] value)
        {
            // Is it better to add a '0', or silently
            //   drop the Integer? Dropping integers
            //   is probably not te best choice...
            if (IsEmpty(value))
            {
                return CreateInteger(Constants.ZERO);
            }

            return new AsnType(0x02, value);
        }

        /// <summary>
        /// <para>Returns the negative ASN.1 encoded integer. If the high
        /// bit of most significant byte is set, the integer is already
        /// considered negative.</para>
        /// <para>If the high bit of most significant byte
        /// is <bold>not</bold> set, the integer will be 2's complimented
        /// to form a negative integer.</para>
        /// <para>If octets is null or zero length, the method returns an
        /// AsnType equivalent to CreateInteger(byte[]{0})..</para>
        /// </summary>
        /// <param name="value">A MSB (big endian) byte[] representing the
        /// integer to be encoded.</param>
        /// <returns>Returns the negative ASN.1 encoded integer.</returns>
        /// <example>
        /// ASN.1 encoded 0:
        /// <code>CreateIntegerNeg(null)</code>
        /// <code>CreateIntegerNeg(new byte[]{0x00})</code>
        /// <code>CreateIntegerNeg(new byte[]{0x00, 0x00})</code>
        /// </example>
        /// <example>
        /// ASN.1 encoded -1 (2's compliment 0xFF):
        /// <code>CreateIntegerNeg(new byte[]{0x01})</code>
        /// </example>
        /// <example>
        /// ASN.1 encoded -2 (2's compliment 0xFE):
        /// <code>CreateIntegerNeg(new byte[]{0x02})</code>
        /// </example>
        /// <example>
        /// ASN.1 encoded -1:
        /// <code>CreateIntegerNeg(new byte[]{0xFF})</code>
        /// <code>CreateIntegerNeg(new byte[]{0xFF,0xFF})</code>
        /// Note: already negative since the high bit is set.</example>
        /// <example>
        /// ASN.1 encoded -255 (2's compliment 0xFF, 0x01):
        /// <code>CreateIntegerNeg(new byte[]{0x00,0xFF})</code>
        /// </example>
        /// <example>
        /// ASN.1 encoded -255 (2's compliment 0xFF, 0xFF, 0x01):
        /// <code>CreateIntegerNeg(new byte[]{0x00,0x00,0xFF})</code>
        /// </example>
        /// <seealso cref="CreateInteger"/>
        /// <seealso cref="CreateIntegerPos"/>
        public static AsnType CreateIntegerNeg(byte[] value)
        {
            // Is it better to add a '0', or silently
            //   drop the Integer? Dropping integers
            //   is probably not te best choice...
            if (IsEmpty(value))
            {
                return CreateInteger(Constants.ZERO);
            }

            // No Trimming
            // The byte[] may be that way for a reason
            if (IsZero(value))
            {
                return CreateInteger(value);
            }

            //
            // At this point, we know we have at least 1 octet
            //

            // Is this integer already negative?
            if (value[0] >= 0x80)

            // Pass through with no modifications
            {
                return CreateInteger(value);
            }

            // No need to Duplicate - Compliment2s
            // performs the action
            byte[] c = Compliment2s(value);

            return CreateInteger(c);
        }

        /// <summary>
        /// <para>Returns the AsnType representing a positive ASN.1 encoded
        /// integer. If the high bit of most significant byte is set,
        /// the method prepends a 0x00 to octets before assigning the
        /// value to ensure the resulting integer is interpreted as
        /// positive in the application.</para>
        /// <para>If octets is null or zero length, the method returns an
        /// AsnType equivalent to CreateInteger(byte[]{0})..</para>
        /// </summary>
        /// <param name="value">A MSB (big endian) byte[] representing the
        /// integer to be encoded.</param>
        /// <returns>Returns the AsnType representing an ASN.1
        /// encoded positive integer.</returns>
        /// <example>
        /// ASN.1 encoded 0:
        /// <code>CreateIntegerPos(null)</code>
        /// <code>CreateIntegerPos(new byte[]{0x00})</code>
        /// <code>CreateIntegerPos(new byte[]{0x00, 0x00})</code>
        /// </example>
        /// <example>
        /// ASN.1 encoded 1:
        /// <code>CreateInteger(new byte[]{0x01})</code>
        /// </example>
        /// <seealso cref="CreateInteger"/>
        /// <seealso cref="CreateIntegerNeg"/>
        public static AsnType CreateIntegerPos(byte[] value)
        {
            byte[] d = Duplicate(value);

            if (IsEmpty(d))
            {
                d = Constants.ZERO;
            }

            byte[] i;
            // Mediate the 2's compliment representation.
            // If the first byte has its high bit set, we will
            // add the additional byte of 0x00
            if (d.Length > 0 && d[0] > 0x7F)
            {
                i = new byte[d.Length + 1];
                i[0] = 0x00;
                Array.Copy(d, 0, i, 1, value.Length);
            }
            else
            {
                i = d;
            }

            // Integer: Tag 0x02 (2, Universal, Primitive)
            return CreateInteger(i);
        }

        /// <summary>
        /// Returns the AsnType representing an ASN.1 encoded null.
        /// </summary>
        /// <returns>Returns the AsnType representing an ASN.1
        /// encoded null.</returns>
        public static AsnType CreateNull()
        {
            return new AsnType(0x05, new byte[] { 0x00 });
        }

        /// <summary>
        /// An ordered sequence of zero, one or more octets. Returns
        /// the ASN.1 encoded octet string. If octets is null or length
        /// is 0, an empty (0 length) octet string is returned.
        /// </summary>
        /// <param name="value">A MSB (big endian) byte[] representing the
        /// octet string to be encoded.</param>
        /// <returns>Returns the AsnType representing an ASN.1
        /// encoded octet string.</returns>
        /// <seealso cref="CreateBitString(byte[])"/>
        /// <seealso cref="CreateBitString(byte[], uint)"/>
        /// <seealso cref="CreateBitString(AsnType)"/>
        /// <seealso cref="CreateBitString(string)"/>
        /// <seealso cref="CreateOctetString(AsnType)"/>
        /// <seealso cref="CreateOctetString(AsnType[])"/>
        /// <seealso cref="CreateOctetString(string)"/>
        public static AsnType CreateOctetString(byte[] value)
        {
            if (IsEmpty(value))
            {
                // Empty octet string
                return new AsnType(0x04, Constants.EMPTY);
            }

            // OctetString: Tag 0x04 (4, Universal, Primitive)
            return new AsnType(0x04, value);
        }

        /// <summary>
        /// An ordered sequence of zero, one or more octets. Returns
        /// the byte[] representing an ASN.1 encoded octet string.
        /// If octets is null or length is 0, an empty (0 length)
        /// o ctet string is returned.
        /// </summary>
        /// <param name="value">An AsnType object to be encoded.</param>
        /// <returns>Returns the AsnType representing an ASN.1
        /// encoded octet string.</returns>
        /// <seealso cref="CreateBitString(byte[])"/>
        /// <seealso cref="CreateBitString(byte[], uint)"/>
        /// <seealso cref="CreateBitString(AsnType)"/>
        /// <seealso cref="CreateBitString(string)"/>
        /// <seealso cref="CreateOctetString(byte[])"/>
        /// <seealso cref="CreateOctetString(string)"/>
        public static AsnType CreateOctetString(AsnType value)
        {
            if (IsEmpty(value))
            {
                // Empty octet string
                return new AsnType(0x04, 0x00);
            }

            // OctetString: Tag 0x04 (4, Universal, Primitive)
            return new AsnType(0x04, value.GetBytes());
        }

        /// <summary>
        /// An ordered sequence of zero, one or more octets. Returns
        /// the byte[] representing an ASN.1 encoded octet string.
        /// If octets is null or length is 0, an empty (0 length)
        /// o ctet string is returned.
        /// </summary>
        /// <param name="values">An AsnType object to be encoded.</param>
        /// <returns>Returns the AsnType representing an ASN.1
        /// encoded octet string.</returns>
        /// <seealso cref="CreateBitString(byte[])"/>
        /// <seealso cref="CreateBitString(byte[], uint)"/>
        /// <seealso cref="CreateBitString(AsnType)"/>
        /// <seealso cref="CreateBitString(string)"/>
        /// <seealso cref="CreateOctetString(byte[])"/>
        /// <seealso cref="CreateOctetString(AsnType)"/>
        /// <seealso cref="CreateOctetString(string)"/>
        public static AsnType CreateOctetString(AsnType[] values)
        {
            if (IsEmpty(values))
            {
                // Empty octet string
                return new AsnType(0x04, 0x00);
            }

            // OctetString: Tag 0x04 (4, Universal, Primitive)
            return new AsnType(0x04, Concatenate(values));
        }

        /// <summary>
        /// <para>An ordered sequence of zero, one or more bits. Returns
        /// the AsnType representing an ASN.1 encoded octet string.</para>
        /// <para>If octets is null or length is 0, an empty (0 length)
        /// octet string is returned.</para>
        /// <para>If conversion fails, the bit string returned is a partial
        /// bit string. The partial octet string ends at the octet before the
        /// point of failure (it does not include the octet which could
        /// not be parsed, or subsequent octets).</para>
        /// </summary>
        /// <param name="value">A string representing the
        /// octet string to be encoded.</param>
        /// <returns>Returns the AsnType representing an ASN.1
        /// encoded octet string.</returns>
        /// <seealso cref="CreateBitString(byte[])"/>
        /// <seealso cref="CreateBitString(byte[], uint)"/>
        /// <seealso cref="CreateBitString(string)"/>
        /// <seealso cref="CreateBitString(AsnType)"/>
        /// <seealso cref="CreateOctetString(byte[])"/>
        /// <seealso cref="CreateOctetString(AsnType)"/>
        /// <seealso cref="CreateOctetString(AsnType[])"/>
        public static AsnType CreateOctetString(string value)
        {
            if (IsEmpty(value))
            {
                return CreateOctetString(Constants.EMPTY);
            }

            // Determine number of octets
            int len = (value.Length + 255) / 256;

            List<byte> octets = new List<byte>();
            for (int i = 0; i < len; i++)
            {
                string s = value.Substring(i * 2, 2);
                byte b;
                try
                {
                    b = Convert.ToByte(s, 16);
                }
                catch (FormatException /*e*/)
                {
                    break;
                }
                catch (OverflowException /*e*/)
                {
                    break;
                }

                octets.Add(b);
            }

            // OctetString: Tag 0x04 (4, Universal, Primitive)
            return CreateOctetString(octets.ToArray());
        }

        private static bool ValidateOidValue(string value, ref ulong a, ref List<ulong> arcs)
        {
            // Punt?
            if (IsEmpty(value))
            {
                return false;
            }

            string[] tokens = value.Split(Constants.SeparatorSpaceAndDot);

            // Punt?
            if (IsEmpty(tokens))
            {
                return false;
            }

            // Parsing/Manipulation of the arc value
            a = 0;

            // One or more strings are available
            arcs = new List<ulong>();

            foreach (string t in tokens)
            {
                // No empty or ill-formed strings...
                if (t.Length == 0)
                {
                    break;
                }

                try
                {
                    a = Convert.ToUInt64(t, CultureInfo.InvariantCulture);
                }
                catch (FormatException /*e*/)
                {
                    break;
                }
                catch (OverflowException /*e*/)
                {
                    break;
                }

                arcs.Add(a);
            }

            // Punt?
            if (0 == arcs.Count)
            {
                return false;
            }

            return true;
        }

        /// <summary>
        /// Returns the AsnType representing an ASN.1 encoded OID.
        /// If conversion fails, the result is a partial conversion
        /// up to the point of failure. If the oid string is null or
        /// not well formed, an empty byte[] is returned.
        /// </summary>
        /// <param name="value">The string representing the object
        /// identifier to be encoded.</param>
        /// <returns>Returns the AsnType representing an ASN.1
        /// encoded object identifier.</returns>
        /// <example>The following assigns the encoded AsnType
        /// for a RSA key to oid:
        /// <code>AsnType oid = CreateOid("1.2.840.113549.1.1.1")</code>
        /// </example>
        /// <seealso cref="CreateOid(byte[])"/>
        public static AsnType? CreateOid(string value)
        {
            List<ulong> arcs = new List<ulong>();
            ulong a = 0;

            if (!ValidateOidValue(value, ref a, ref arcs))
            {
                return null;
            }

            // Octets to be returned to caller
            List<byte> octets = new List<byte>();

            // Guard the case of a small list
            // The list has at least 1 item...
            if (arcs.Count >= 1)
            {
                a = arcs[0] * 40;
            }

            if (arcs.Count >= 2)
            {
                a += arcs[1];
            }

            octets.Add((byte)a);

            // Add remaining arcs (subidentifiers)
            for (int i = 2; i < arcs.Count; i++)
            {
                // Scratch list builder for this arc
                List<byte> temp = new List<byte>();

                // The current arc (subidentifier)
                ulong arc = arcs[i];

                // Build the arc (subidentifier) byte array
                // The array is built in reverse (LSB to MSB).
                do
                {
                    // Each entry is formed from the low 7 bits (0x7F).
                    // Set high bit of all entries (0x80) per X.680. We
                    // will unset the high bit of the final byte later.
                    temp.Add((byte)(0x80 | (arc & 0x7F)));
                    arc >>= 7;
                } while (0 != arc);

                // Grab resulting array. Because of the do/while,
                // there is at least one value in the array.
                byte[] t = temp.ToArray();

                // Unset high bit of byte t[0]
                // t[0] will be LSB after the array is reversed.
                t[0] = (byte)(0x7F & t[0]);

                // MSB first...
                Array.Reverse(t);

                // Add to the resulting array
                foreach (byte b in t)
                {
                    octets.Add(b);
                }
            }

            return CreateOid(octets.ToArray());
        }

        /// <summary>
        /// Returns the AsnType representing an ASN.1 encoded OID.
        /// If conversion fails, the result is a partial conversion
        /// (up to the point of failure). If octets is null, an
        /// empty byte[] is returned.
        /// </summary>
        /// <param name="value">The packed byte[] representing the object
        /// identifier to be encoded.</param>
        /// <returns>Returns the AsnType representing an ASN.1
        /// encoded object identifier.</returns>
        /// <example>The following assigns the encoded AsnType for a RSA
        /// key to oid:
        /// <code>// Packed 1.2.840.113549.1.1.1
        /// byte[] rsa = new byte[] { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
        /// AsnType = CreateOid(rsa)</code>
        /// </example>
        /// <seealso cref="CreateOid(string)"/>
        public static AsnType? CreateOid(byte[] value)
        {
            // Punt...
            if (IsEmpty(value))
            {
                return null;
            }

            // OID: Tag 0x06 (6, Universal, Primitive)
            return new AsnType(0x06, value);
        }

        /// <summary>
        /// <para>An ordered collection of one or more types.
        /// Returns the AsnType representing an ASN.1 encoded sequence.</para>
        /// <para>If the AsnType is null, an empty sequence (length 0)
        /// is returned.</para>
        /// </summary>
        /// <param name="value">An AsnType consisting of
        /// a single value to be encoded.</param>
        /// <returns>Returns the AsnType representing an ASN.1
        /// encoded sequence.</returns>
        /// <seealso cref="CreateSet(AsnType)"/>
        /// <seealso cref="CreateSet(AsnType[])"/>
        /// <seealso cref="CreateSetOf(AsnType)"/>
        /// <seealso cref="CreateSetOf(AsnType[])"/>
        /// <seealso cref="CreateSequence(AsnType)"/>
        /// <seealso cref="CreateSequence(AsnType[])"/>
        /// <seealso cref="CreateSequenceOf(AsnType)"/>
        /// <seealso cref="CreateSequenceOf(AsnType[])"/>
        public static AsnType CreateSequence(AsnType value)
        {
            // Should be at least 1...
            Debug.Assert(!IsEmpty(value));

            // One or more required
            if (IsEmpty(value))
            {
                throw new ArgumentException("A sequence requires at least one value.");
            }

            // Sequence: Tag 0x30 (16, Universal, Constructed)
            return new AsnType(0x30, value.GetBytes());
        }

        /// <summary>
        /// <para>An ordered collection of one or more types.
        /// Returns the AsnType representing an ASN.1 encoded sequence.</para>
        /// <para>If the AsnType is null, an
        /// empty sequence (length 0) is returned.</para>
        /// </summary>
        /// <param name="values">An array of AsnType consisting of
        /// the values in the collection to be encoded.</param>
        /// <returns>Returns the AsnType representing an ASN.1
        /// encoded Set.</returns>
        /// <seealso cref="CreateSet(AsnType)"/>
        /// <seealso cref="CreateSet(AsnType[])"/>
        /// <seealso cref="CreateSetOf(AsnType)"/>
        /// <seealso cref="CreateSetOf(AsnType[])"/>
        /// <seealso cref="CreateSequence(AsnType)"/>
        /// <seealso cref="CreateSequence(AsnType[])"/>
        /// <seealso cref="CreateSequenceOf(AsnType)"/>
        /// <seealso cref="CreateSequenceOf(AsnType[])"/>
        public static AsnType CreateSequence(AsnType[] values)
        {
            // Should be at least 1...
            Debug.Assert(!IsEmpty(values));

            // One or more required
            if (IsEmpty(values))
            {
                throw new ArgumentException("A sequence requires at least one value.");
            }

            // Sequence: Tag 0x30 (16, Universal, Constructed)
            return new AsnType(0x10 | 0x20, Concatenate(values));
        }

        /// <summary>
        /// <para>An ordered collection zero, one or more types.
        /// Returns the AsnType representing an ASN.1 encoded sequence.</para>
        /// <para>If the AsnType value is null,an
        /// empty sequence (length 0) is returned.</para>
        /// </summary>
        /// <param name="value">An AsnType consisting of
        /// a single value to be encoded.</param>
        /// <returns>Returns the AsnType representing an ASN.1
        /// encoded sequence.</returns>
        /// <seealso cref="CreateSet(AsnType)"/>
        /// <seealso cref="CreateSet(AsnType[])"/>
        /// <seealso cref="CreateSetOf(AsnType)"/>
        /// <seealso cref="CreateSetOf(AsnType[])"/>
        /// <seealso cref="CreateSequence(AsnType)"/>
        /// <seealso cref="CreateSequence(AsnType[])"/>
        /// <seealso cref="CreateSequenceOf(AsnType)"/>
        /// <seealso cref="CreateSequenceOf(AsnType[])"/>
        public static AsnType CreateSequenceOf(AsnType value)
        {
            // From the ASN.1 Mailing List
            if (IsEmpty(value))
            {
                return new AsnType(0x30, Constants.EMPTY);
            }

            // Sequence: Tag 0x30 (16, Universal, Constructed)
            return new AsnType(0x30, value.GetBytes());
        }

        /// <summary>
        /// <para>An ordered collection zero, one or more types.
        /// Returns the AsnType representing an ASN.1 encoded sequence.</para>
        /// <para>If the AsnType array is null or the array is 0 length,
        /// an empty sequence (length 0) is returned.</para>
        /// </summary>
        /// <param name="values">An AsnType consisting of
        /// the values in the collection to be encoded.</param>
        /// <returns>Returns the AsnType representing an ASN.1
        /// encoded sequence.</returns>
        /// <seealso cref="CreateSet(AsnType)"/>
        /// <seealso cref="CreateSet(AsnType[])"/>
        /// <seealso cref="CreateSetOf(AsnType)"/>
        /// <seealso cref="CreateSetOf(AsnType[])"/>
        /// <seealso cref="CreateSequence(AsnType)"/>
        /// <seealso cref="CreateSequence(AsnType[])"/>
        /// <seealso cref="CreateSequenceOf(AsnType)"/>
        /// <seealso cref="CreateSequenceOf(AsnType[])"/>
        public static AsnType CreateSequenceOf(AsnType[] values)
        {
            // From the ASN.1 Mailing List
            if (IsEmpty(values))
            {
                return new AsnType(0x30, Constants.EMPTY);
            }

            // Sequence: Tag 0x30 (16, Universal, Constructed)
            return new AsnType(0x30, Concatenate(values));
        }

        // PKCS #8, Section 6 (PrivateKeyInfo) message
        // !!!!!!!!!!!!!!! Unencrypted !!!!!!!!!!!!!!!
        /// <summary>
        /// Returns AsnMessage representing the unencrypted
        /// PKCS #8 PrivateKeyInfo.
        /// </summary>
        /// <param name="privateKey">The DSA key to be encoded.</param>
        /// <returns>Returns the AsnType representing the unencrypted
        /// PKCS #8 PrivateKeyInfo.</returns>
        /// <seealso cref="PrivateKeyToPKCS8(RSAParameters)"/>
        /// <seealso cref="PublicKeyToX509(DSAParameters)"/>
        /// <seealso cref="PublicKeyToX509(RSAParameters)"/>
        public static AsnMessage PrivateKeyToPKCS8(DSAParameters privateKey)
        {
            // Value Type cannot be null
            // Debug.Assert(null != privateKey);

            /* *
            * SEQUENCE              // PrivateKeyInfo
            * +- INTEGER(0)         // Version (v1998)
            * +- SEQUENCE           // AlgorithmIdentifier
            * |  +- OID             // 1.2.840.10040.4.1
            * |  +- SEQUENCE        // DSS-Params (Optional Parameters)
            * |    +- INTEGER (P)
            * |    +- INTEGER (Q)
            * |    +- INTEGER (G)
            * +- OCTETSTRING        // PrivateKey
            *    +- INTEGER(X)   // DSAPrivateKey X
            * */

            // Version - 0 (v1998)
            AsnType version = CreateInteger(Constants.ZERO);

            ArgumentNullException.ThrowIfNull(privateKey.P);
            ArgumentNullException.ThrowIfNull(privateKey.Q);
            ArgumentNullException.ThrowIfNull(privateKey.G);

            // Domain Parameters
            AsnType p = CreateIntegerPos(privateKey.P);
            AsnType q = CreateIntegerPos(privateKey.Q);
            AsnType g = CreateIntegerPos(privateKey.G);

            AsnType dssParams = CreateSequence(new AsnType[] { p, q, g });

            // OID - packed 1.2.840.10040.4.1
            //   { 0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x01 }
            AsnType? oid = CreateOid("1.2.840.10040.4.1");

            ArgumentNullException.ThrowIfNull(oid);

            // AlgorithmIdentifier
            AsnType algorithmID = CreateSequence(
                new AsnType[]
                {
                    oid,
                    dssParams
                });

            ArgumentNullException.ThrowIfNull(privateKey.X);

            // Private Key X
            AsnType x = CreateIntegerPos(privateKey.X);
            AsnType key = CreateOctetString(x);

            // Sequence
            AsnType privateKeyInfo =
                CreateSequence(new AsnType[] { version, algorithmID, key });

            return new AsnMessage(privateKeyInfo.GetBytes(), "PKCS#8");
        }

        // PKCS #8, Section 6 (PrivateKeyInfo) message
        // !!!!!!!!!!!!!!! Unencrypted !!!!!!!!!!!!!!!
        /// <summary>
        /// Returns AsnMessage representing the unencrypted
        /// PKCS #8 PrivateKeyInfo.
        /// </summary>
        /// <param name="privateKey">The RSA key to be encoded.</param>
        /// <returns>Returns the AsnType representing the unencrypted
        /// PKCS #8 PrivateKeyInfo.</returns>
        /// <seealso cref="PrivateKeyToPKCS8(DSAParameters)"/>
        /// <seealso cref="PublicKeyToX509(DSAParameters)"/>
        /// <seealso cref="PublicKeyToX509(RSAParameters)"/>
        public static AsnMessage PrivateKeyToPKCS8(RSAParameters privateKey)
        {
            // Value Type cannot be null
            // Debug.Assert(null != privateKey);

            /* *
            * SEQUENCE                  // PublicKeyInfo
            * +- INTEGER(0)             // Version - 0 (v1998)
            * +- SEQUENCE               // AlgorithmIdentifier
            *    +- OID                 // 1.2.840.113549.1.1.1
            *    +- NULL                // Optional Parameters
            * +- OCTETSTRING            // PrivateKey
            *    +- SEQUENCE            // RSAPrivateKey
            *       +- INTEGER(0)       // Version - 0 (v1998)
            *       +- INTEGER(N)
            *       +- INTEGER(E)
            *       +- INTEGER(D)
            *       +- INTEGER(P)
            *       +- INTEGER(Q)
            *       +- INTEGER(DP)
            *       +- INTEGER(DQ)
            *       +- INTEGER(Inv Q)
            * */

            ArgumentNullException.ThrowIfNull(privateKey.Modulus);
            ArgumentNullException.ThrowIfNull(privateKey.Exponent);
            ArgumentNullException.ThrowIfNull(privateKey.D);
            ArgumentNullException.ThrowIfNull(privateKey.P);
            ArgumentNullException.ThrowIfNull(privateKey.Q);
            ArgumentNullException.ThrowIfNull(privateKey.DP);
            ArgumentNullException.ThrowIfNull(privateKey.DQ);
            ArgumentNullException.ThrowIfNull(privateKey.InverseQ);

            AsnType n = CreateIntegerPos(privateKey.Modulus);
            AsnType e = CreateIntegerPos(privateKey.Exponent);
            AsnType d = CreateIntegerPos(privateKey.D);
            AsnType p = CreateIntegerPos(privateKey.P);
            AsnType q = CreateIntegerPos(privateKey.Q);
            AsnType dp = CreateIntegerPos(privateKey.DP);
            AsnType dq = CreateIntegerPos(privateKey.DQ);
            AsnType iq = CreateIntegerPos(privateKey.InverseQ);

            // Version - 0 (v1998)
            AsnType version = CreateInteger(new byte[] { 0 });

            // octstring = OCTETSTRING(SEQUENCE(INTEGER(0)INTEGER(N)...))
            AsnType key = CreateOctetString(
                CreateSequence(
                    new AsnType[]
                    {
                        version,
                        n,
                        e,
                        d,
                        p,
                        q,
                        dp,
                        dq,
                        iq
                    }));

            // OID - packed 1.2.840.113549.1.1.1
            //   { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 }

            AsnType? value = CreateOid("1.2.840.113549.1.1.1");

            ArgumentNullException.ThrowIfNull(value);

            AsnType algorithmID = CreateSequence(
                new AsnType[]
                {
                    value,
                    CreateNull()
                });

            // PrivateKeyInfo
            AsnType privateKeyInfo =
                CreateSequence(new AsnType[] { version, algorithmID, key });

            return new AsnMessage(privateKeyInfo.GetBytes(), "PKCS#8");
        }

        // PublicKeyInfo (X.509 compatible) message
        /// <summary>
        /// Returns the AsnMessage representing the X.509 PublicKeyInfo.
        /// </summary>
        /// <param name="publicKey">The DSA key to be encoded.</param>
        /// <returns>Returns the AsnType representing the
        /// X.509 PublicKeyInfo.</returns>
        /// <seealso cref="PrivateKeyToPKCS8(DSAParameters)"/>
        /// <seealso cref="PrivateKeyToPKCS8(RSAParameters)"/>
        /// <seealso cref="PublicKeyToX509(RSAParameters)"/>
        public static AsnMessage PublicKeyToX509(DSAParameters publicKey)
        {
            // Value Type cannot be null
            // Debug.Assert(null != publicKey);

            /* *
            * SEQUENCE              // PrivateKeyInfo
            * +- SEQUENCE           // AlgorithmIdentifier
            * |  +- OID             // 1.2.840.10040.4.1
            * |  +- SEQUENCE        // DSS-Params (Optional Parameters)
            * |    +- INTEGER (P)
            * |    +- INTEGER (Q)
            * |    +- INTEGER (G)
            * +- BITSTRING          // PublicKey
            *    +- INTEGER(Y)      // DSAPublicKey Y
            * */

            ArgumentNullException.ThrowIfNull(publicKey.P);
            ArgumentNullException.ThrowIfNull(publicKey.Q);
            ArgumentNullException.ThrowIfNull(publicKey.G);

            // DSA Parameters
            AsnType p = CreateIntegerPos(publicKey.P);
            AsnType q = CreateIntegerPos(publicKey.Q);
            AsnType g = CreateIntegerPos(publicKey.G);

            // Sequence - DSA-Params
            AsnType dssParams = CreateSequence(new AsnType[] { p, q, g });

            // OID - packed 1.2.840.10040.4.1
            //   { 0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x01 }
            AsnType? oid = CreateOid("1.2.840.10040.4.1");

            ArgumentNullException.ThrowIfNull(oid);

            // Sequence
            AsnType algorithmID = CreateSequence(new AsnType[] { oid, dssParams });

            ArgumentNullException.ThrowIfNull(publicKey.Y);

            // Public Key Y
            AsnType y = CreateIntegerPos(publicKey.Y);
            AsnType key = CreateBitString(y);

            // Sequence 'A'
            AsnType publicKeyInfo =
                CreateSequence(new AsnType[] { algorithmID, key });

            return new AsnMessage(publicKeyInfo.GetBytes(), "X.509");
        }

        // PublicKeyInfo (X.509 compatible) message
        /// <summary>
        /// Returns the AsnMessage representing the X.509 PublicKeyInfo.
        /// </summary>
        /// <param name="publicKey">The RSA key to be encoded.</param>
        /// <returns>Returns the AsnType representing the
        /// X.509 PublicKeyInfo.</returns>
        /// <seealso cref="PrivateKeyToPKCS8(DSAParameters)"/>
        /// <seealso cref="PrivateKeyToPKCS8(RSAParameters)"/>
        /// <seealso cref="PublicKeyToX509(DSAParameters)"/>
        public static AsnMessage PublicKeyToX509(RSAParameters publicKey)
        {
            // Value Type cannot be null
            // Debug.Assert(null != publicKey);

            /* *
            * SEQUENCE              // PrivateKeyInfo
            * +- SEQUENCE           // AlgorithmIdentifier
            *    +- OID             // 1.2.840.113549.1.1.1
            *    +- Null            // Optional Parameters
            * +- BITSTRING          // PrivateKey
            *    +- SEQUENCE        // RSAPrivateKey
            *       +- INTEGER(N)   // N
            *       +- INTEGER(E)   // E
            * */

            // OID - packed 1.2.840.113549.1.1.1
            //   { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 }
            AsnType? oid = CreateOid("1.2.840.113549.1.1.1");

            ArgumentNullException.ThrowIfNull(oid);

            AsnType algorithmID = CreateSequence(new AsnType[] { oid, CreateNull() });

            ArgumentNullException.ThrowIfNull(publicKey.Modulus);
            ArgumentNullException.ThrowIfNull(publicKey.Exponent);

            AsnType n = CreateIntegerPos(publicKey.Modulus);
            AsnType e = CreateIntegerPos(publicKey.Exponent);
            AsnType key = CreateBitString(CreateSequence(new AsnType[] { n, e }));

            AsnType publicKeyInfo = CreateSequence(new AsnType[] { algorithmID, key });

            return new AsnMessage(publicKeyInfo.GetBytes(), "X.509");
        }

        /// <summary>
        /// Removes trailing 0x00 octets from the byte[] octets. This
        /// method may return an empty byte array (0 length).
        /// </summary>
        /// <param name="octets">An array of octets to trim.</param>
        /// <returns>A byte[] with trailing 0x00 octets removed.</returns>
        public static byte[] TrimEnd(byte[] octets)
        {
            if (IsEmpty(octets) || IsZero(octets))
            {
                return Constants.EMPTY;
            }

            byte[] d = Duplicate(octets);

            Array.Reverse(d);

            d = TrimStart(d);

            Array.Reverse(d);

            return d;
        }

        /// <summary>
        /// Removes leading 0x00 octets from the byte[] octets. This
        /// method may return an empty byte array (0 length).
        /// </summary>
        /// <param name="octets">An array of octets to trim.</param>
        /// <returns>A byte[] with leading 0x00 octets removed.</returns>
        public static byte[] TrimStart(byte[] octets)
        {
            if (IsEmpty(octets) || IsZero(octets))
            {
                return Array.Empty<byte>();
            }

            byte[] d = Duplicate(octets);

            // Position of the first non-zero value
            int pos = 0;
            foreach (byte b in d)
            {
                if (0 != b)
                {
                    break;
                }

                pos++;
            }

            // Nothing to trim
            if (pos == d.Length)
            {
                return octets;
            }

            // Allocate trimmed array
            byte[] t = new byte[d.Length - pos];

            // Copy
            Array.Copy(d, pos, t, 0, t.Length);

            return t;
        }

        internal static byte[] Compliment2s(byte[] value)
        {
            if (IsEmpty(value))
            {
                return Constants.EMPTY;
            }

            // 2s Compliment of 0 is 0
            if (IsZero(value))
            {
                return Duplicate(value);
            }

            // Make a copy of octet array
            byte[] d = Duplicate(value);

            int carry = 1;
            for (int i = d.Length - 1; i >= 0; i--)
            {
                // Compliment
                d[i] = (byte)~d[i];

                // Add
                int j = d[i] + carry;

                // Write Back
                d[i] = (byte)(j & 0xFF);

                // Determine Next Carry
                carry = 0x100 == (j & 0x100) ? 1 : 0;
            }

            // Carry Array (we may need to carry out of 'd'
            byte[] c;
            if (1 == carry)
            {
                c = new byte[d.Length + 1];

                // Sign Extend....
                c[0] = 0xFF;

                Array.Copy(d, 0, c, 1, d.Length);
            }
            else
            {
                c = d;
            }

            return c;
        }

        internal static byte[] Concatenate(AsnType[] values)
        {
            // Nothing in, nothing out
            if (IsEmpty(values))
            {
                return Array.Empty<byte>();
            }

            int length = 0;
            foreach (AsnType t in values)
            {
                if (null != t)
                {
                    length += t.GetBytes().Length;
                }
            }

            byte[] cated = new byte[length];

            int current = 0;
            foreach (AsnType t in values)
            {
                if (null != t)
                {
                    byte[] b = t.GetBytes();

                    Array.Copy(b, 0, cated, current, b.Length);
                    current += b.Length;
                }
            }

            return cated;
        }

        internal static byte[] Concatenate(byte[] first, byte[] second)
        {
            return Concatenate(new byte[][] { first, second });
        }

        internal static byte[] Concatenate(byte[][] values)
        {
            // Nothing in, nothing out
            if (IsEmpty(values))
            {
                return Array.Empty<byte>();
            }

            int length = 0;
            foreach (byte[] b in values)
            {
                if (null != b)
                {
                    length += b.Length;
                }
            }

            byte[] cated = new byte[length];

            int current = 0;
            foreach (byte[] b in values)
            {
                if (null != b)
                {
                    Array.Copy(b, 0, cated, current, b.Length);
                    current += b.Length;
                }
            }

            return cated;
        }

        internal static byte[] Duplicate(byte[] b)
        {
            if (IsEmpty(b))
            {
                return Constants.EMPTY;
            }

            byte[] d = new byte[b.Length];
            Array.Copy(b, d, b.Length);

            return d;
        }

        internal static bool IsEmpty(byte[] octets)
        {
            if (null == octets || 0 == octets.Length)
            {
                return true;
            }

            return false;
        }

        internal static bool IsEmpty(string s)
        {
            if (null == s || 0 == s.Length)
            {
                return true;
            }

            return false;
        }

        internal static bool IsEmpty(string[] strings)
        {
            if (null == strings || 0 == strings.Length)
            {
                return true;
            }

            return false;
        }

        internal static bool IsEmpty(AsnType value)
        {
            if (null == value)
            {
                return true;
            }

            return false;
        }

        internal static bool IsEmpty(AsnType[] values)
        {
            if (null == values || 0 == values.Length)
            {
                return true;
            }

            return false;
        }

        internal static bool IsEmpty(byte[][] arrays)
        {
            if (null == arrays || 0 == arrays.Length)
            {
                return true;
            }

            return false;
        }

        internal static bool IsZero(byte[] octets)
        {
            if (IsEmpty(octets))
            {
                return false;
            }

            bool allZeros = true;
            for (int i = 0; i < octets.Length; i++)
            {
                if (0 != octets[i])
                {
                    allZeros = false;
                    break;
                }
            }

            return allZeros;
        }
    }
}