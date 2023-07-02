/*
 * Automatically generated by jrpcgen 1.0.7 on 27/08/2010
 * jrpcgen is part of the "Remote Tea.Net" ONC/RPC package for C#
 * See http://remotetea.sourceforge.net for details
 */

namespace NFSLibrary.Protocols.V4.RPC
{
    using org.acplt.oncrpc;

    public class open_read_delegation4 : XdrAble
    {
        public stateid4 stateid;
        public bool recall;
        public nfsace4 permissions;

        public open_read_delegation4()
        {
        }

        public open_read_delegation4(XdrDecodingStream xdr)
        {
            xdrDecode(xdr);
        }

        public void xdrEncode(XdrEncodingStream xdr)
        {
            xdr.xdrEncodeBoolean(recall);
            permissions.xdrEncode(xdr);
        }

        public void xdrDecode(XdrDecodingStream xdr)
        {
            recall = xdr.xdrDecodeBoolean();
            permissions = new nfsace4(xdr);
        }
    }
} // End of open_read_delegation4.cs