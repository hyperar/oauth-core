namespace Hyperar.OAuthCore.KeyInterop
{
    using System;

    public class AsnMessage
    {
        private readonly string m_format;

        private readonly byte[] m_octets;

        public AsnMessage(byte[] octets, string format)
        {
            this.m_octets = octets;
            this.m_format = format;
        }

        public int Length
        {
            get
            {
                if (null == this.m_octets)
                {
                    return 0;
                }

                return this.m_octets.Length;
            }
        }

        public byte[] GetBytes()
        {
            if (null == this.m_octets)
            {
                return Array.Empty<byte>();
            }

            return this.m_octets;
        }

        public string GetFormat()
        {
            return this.m_format;
        }
    }
}
