/*
 * Automatically generated by jrpcgen 1.0.7 on 27/08/2010
 * jrpcgen is part of the "Remote Tea.Net" ONC/RPC package for C#
 * See http://remotetea.sourceforge.net for details
 */

namespace NFSLibrary.Protocols.V4.RPC.Callback
{
    using org.acplt.oncrpc;

    public class notify_rename4 : XdrAble
    {
        public notify_remove4 nrn_old_entry;
        public notify_add4 nrn_new_entry;

        public notify_rename4()
        {
        }

        public notify_rename4(XdrDecodingStream xdr)
        {
            xdrDecode(xdr);
        }

        public void xdrEncode(XdrEncodingStream xdr)
        {
            nrn_new_entry.xdrEncode(xdr);
        }

        public void xdrDecode(XdrDecodingStream xdr)
        {
            nrn_new_entry = new notify_add4(xdr);
        }
    }
} // End of notify_rename4.cs