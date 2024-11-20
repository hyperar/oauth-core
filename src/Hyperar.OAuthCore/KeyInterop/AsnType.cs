namespace Hyperar.OAuthCore.KeyInterop
{
    using System;

    public class AsnType
    {
        // Constructors
        // No default - must specify tag and data

        // Setters and Getters
        private readonly byte[] m_tag;

        private byte[]? m_length;

        private byte[] m_octets;

        public AsnType(byte tag, byte octet)
        {
            this.Raw = false;
            this.m_tag = new byte[] { tag };
            this.m_octets = new byte[] { octet };
        }

        public AsnType(byte tag, byte[] octets)
        {
            this.Raw = false;
            this.m_tag = new byte[] { tag };
            this.m_octets = octets;
        }

        public AsnType(byte tag, byte[] length, byte[] octets)
        {
            this.Raw = true;
            this.m_tag = new byte[] { tag };
            this.m_length = length;
            this.m_octets = octets;
        }

        public byte[] Length
        {
            get
            {
                if (null == this.m_length)
                {
                    return Constants.EMPTY;
                }

                return this.m_length;
            }

            // set { m_length = value; }
        }

        public byte[] Octets
        {
            get
            {
                if (null == this.m_octets)
                {
                    return Constants.EMPTY;
                }

                return this.m_octets;
            }

            set
            { this.m_octets = value; }
        }

        public byte[] Tag
        {
            get
            {
                if (null == this.m_tag)
                {
                    return Constants.EMPTY;
                }

                return this.m_tag;
            }
        }

        private bool Raw { get; set; }

        // Methods
        public byte[] GetBytes()
        {
            ArgumentNullException.ThrowIfNull(this.m_length);

            // Created raw by user
            // return the bytes....
            if (this.Raw)
            {
                return Concatenate(
                    new byte[][]
                    {
                            this.m_tag,
                            this.m_length,
                            this.m_octets
                    });
            }

            this.SetLength();

            // Special case
            // Null does not use length
            if (0x05 == this.m_tag[0])
            {
                return Concatenate(
                    new byte[][]
                    {
                            this.m_tag,
                            this.m_octets
                    });
            }

            return Concatenate(
                new byte[][]
                {
                        this.m_tag,
                        this.m_length,
                        this.m_octets
                });
        }

        private static byte[] Concatenate(byte[][] values)
        {
            // Nothing in, nothing out
            if (AsnKeyBuilder.IsEmpty(values))
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

        private void SetLength()
        {
            if (null == this.m_octets)
            {
                this.m_length = Constants.ZERO;
                return;
            }

            // Special case
            // Null does not use length
            if (0x05 == this.m_tag[0])
            {
                this.m_length = Constants.EMPTY;
                return;
            }

            byte[] length;

            // Length: 0 <= l < 0x80
            if (this.m_octets.Length < 0x80)
            {
                length = new byte[1];
                length[0] = (byte)this.m_octets.Length;
            }

            // 0x80 < length <= 0xFF
            else if (this.m_octets.Length <= 0xFF)
            {
                length = new byte[2];
                length[0] = 0x81;
                length[1] = (byte)(this.m_octets.Length & 0xFF);
            }

            //
            // We should almost never see these...
            //

            // 0xFF < length <= 0xFFFF
            else if (this.m_octets.Length <= 0xFFFF)
            {
                length = new byte[3];
                length[0] = 0x82;
                length[1] = (byte)((this.m_octets.Length & 0xFF00) >> 8);
                length[2] = (byte)(this.m_octets.Length & 0xFF);
            }

            // 0xFFFF < length <= 0xFFFFFF
            else if (this.m_octets.Length <= 0xFFFFFF)
            {
                length = new byte[4];
                length[0] = 0x83;
                length[1] = (byte)((this.m_octets.Length & 0xFF0000) >> 16);
                length[2] = (byte)((this.m_octets.Length & 0xFF00) >> 8);
                length[3] = (byte)(this.m_octets.Length & 0xFF);
            }

            // 0xFFFFFF < length <= 0xFFFFFFFF
            else
            {
                length = new byte[5];
                length[0] = 0x84;
                length[1] = (byte)((this.m_octets.Length & 0xFF000000) >> 24);
                length[2] = (byte)((this.m_octets.Length & 0xFF0000) >> 16);
                length[3] = (byte)((this.m_octets.Length & 0xFF00) >> 8);
                length[4] = (byte)(this.m_octets.Length & 0xFF);
            }

            this.m_length = length;
        }
    };
}
