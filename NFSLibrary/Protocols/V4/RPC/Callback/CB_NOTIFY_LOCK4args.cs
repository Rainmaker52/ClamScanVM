/*
 * Automatically generated by jrpcgen 1.0.7 on 27/08/2010
 * jrpcgen is part of the "Remote Tea.Net" ONC/RPC package for C#
 * See http://remotetea.sourceforge.net for details
 */

namespace NFSLibrary.Protocols.V4.RPC.Callback
{
    using org.acplt.oncrpc;

    public class CB_NOTIFY_LOCK4args : XdrAble
    {
        public nfs_fh4 cnla_fh;
        public lock_owner4 cnla_lock_owner;

        public CB_NOTIFY_LOCK4args()
        {
        }

        public CB_NOTIFY_LOCK4args(XdrDecodingStream xdr)
        {
            xdrDecode(xdr);
        }

        public void xdrEncode(XdrEncodingStream xdr)
        {
            cnla_lock_owner.xdrEncode(xdr);
        }

        public void xdrDecode(XdrDecodingStream xdr)
        {
            cnla_lock_owner = new lock_owner4(xdr);
        }
    }
} // End of CB_NOTIFY_LOCK4args.cs