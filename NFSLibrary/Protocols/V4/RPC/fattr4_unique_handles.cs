/*
 * Automatically generated by jrpcgen 1.0.7 on 27/08/2010
 * jrpcgen is part of the "Remote Tea.Net" ONC/RPC package for C#
 * See http://remotetea.sourceforge.net for details
 */

namespace NFSLibrary.Protocols.V4.RPC
{
    using org.acplt.oncrpc;

    public class fattr4_unique_handles : XdrAble
    {
        public bool value;

        public fattr4_unique_handles()
        {
        }

        public fattr4_unique_handles(bool value)
        {
            this.value = value;
        }

        public fattr4_unique_handles(XdrDecodingStream xdr)
        {
            xdrDecode(xdr);
        }

        public void xdrEncode(XdrEncodingStream xdr)
        {
            xdr.xdrEncodeBoolean(value);
        }

        public void xdrDecode(XdrDecodingStream xdr)
        {
            value = xdr.xdrDecodeBoolean();
        }
    }
} // End of  fattr4_unique_handles.cs