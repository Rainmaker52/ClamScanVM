/*
 * Automatically generated by jrpcgen 1.0.7 on 27/08/2010
 * jrpcgen is part of the "Remote Tea.Net" ONC/RPC package for C#
 * See http://remotetea.sourceforge.net for details
 */

using NFSLibrary.Protocols.Commons;
using org.acplt.oncrpc;

namespace NFSLibrary.Protocols.V3.RPC
{
    public class FSStatisticsArguments : XdrAble
    {
        private NFSHandle _fsroot;

        public FSStatisticsArguments()
        { }

        public FSStatisticsArguments(XdrDecodingStream xdr)
        { xdrDecode(xdr); }

        public void xdrEncode(XdrEncodingStream xdr)
        { this._fsroot.xdrEncode(xdr); }

        public void xdrDecode(XdrDecodingStream xdr)
        {
            this._fsroot = new NFSHandle();
            this._fsroot.Version = V3.RPC.NFSv3Protocol.NFS_V3;
            this._fsroot.xdrDecode(xdr);
        }

        public NFSHandle FSRoot
        {
            get
            { return this._fsroot; }
            set
            { this._fsroot = value; }
        }
    }

    // End of FSSTAT3args.cs
}