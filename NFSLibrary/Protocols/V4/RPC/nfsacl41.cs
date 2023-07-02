/*
 * Automatically generated by jrpcgen 1.0.7 on 27/08/2010
 * jrpcgen is part of the "Remote Tea.Net" ONC/RPC package for C#
 * See http://remotetea.sourceforge.net for details
 */

namespace NFSLibrary.Protocols.V4.RPC
{
    using org.acplt.oncrpc;

    public class nfsacl41 : XdrAble
    {
        public aclflag4 na41_flag;
        public nfsace4[] na41_aces;

        public nfsacl41()
        {
        }

        public nfsacl41(XdrDecodingStream xdr)
        {
            xdrDecode(xdr);
        }

        public void xdrEncode(XdrEncodingStream xdr)
        {
            { int _size = na41_aces.Length; xdr.xdrEncodeInt(_size); for (int _idx = 0; _idx < _size; ++_idx) { na41_aces[_idx].xdrEncode(xdr); } }
        }

        public void xdrDecode(XdrDecodingStream xdr)
        {
            { int _size = xdr.xdrDecodeInt(); na41_aces = new nfsace4[_size]; for (int _idx = 0; _idx < _size; ++_idx) { na41_aces[_idx] = new nfsace4(xdr); } }
        }
    }
} // End of nfsacl41.cs