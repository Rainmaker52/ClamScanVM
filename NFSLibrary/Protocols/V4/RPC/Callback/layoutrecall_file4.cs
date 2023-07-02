/*
 * Automatically generated by jrpcgen 1.0.7 on 27/08/2010
 * jrpcgen is part of the "Remote Tea.Net" ONC/RPC package for C#
 * See http://remotetea.sourceforge.net for details
 */

namespace NFSLibrary.Protocols.V4.RPC.Callback
{
    using org.acplt.oncrpc;

    public class layoutrecall_file4 : XdrAble
    {
        public nfs_fh4 lor_fh;
        public offset4 lor_offset;
        public length4 lor_length;
        public stateid4 lor_stateid;

        public layoutrecall_file4()
        {
        }

        public layoutrecall_file4(XdrDecodingStream xdr)
        {
            xdrDecode(xdr);
        }

        public void xdrEncode(XdrEncodingStream xdr)
        {
            lor_offset.xdrEncode(xdr);
            lor_length.xdrEncode(xdr);
            lor_stateid.xdrEncode(xdr);
        }

        public void xdrDecode(XdrDecodingStream xdr)
        {
            lor_offset = new offset4(xdr);
            lor_length = new length4(xdr);
            lor_stateid = new stateid4(xdr);
        }
    }
} // End of layoutrecall_file4.cs