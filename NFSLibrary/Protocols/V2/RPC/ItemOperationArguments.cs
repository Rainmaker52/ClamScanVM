/*
 * Automatically generated by jrpcgen 1.0.7 on 27/08/2010
 * jrpcgen is part of the "Remote Tea.Net" ONC/RPC package for C#
 * See http://remotetea.sourceforge.net for details
 */

using NFSLibrary.Protocols.Commons;
using org.acplt.oncrpc;

namespace NFSLibrary.Protocols.V2.RPC
{
    public class ItemOperationArguments : XdrAble
    {
        private NFSHandle _dir;
        private Name _name;

        public ItemOperationArguments()
        { }

        public ItemOperationArguments(XdrDecodingStream xdr)
        { xdrDecode(xdr); }

        public void xdrEncode(XdrEncodingStream xdr)
        {
            this._dir.xdrEncode(xdr);
            this._name.xdrEncode(xdr);
        }

        public void xdrDecode(XdrDecodingStream xdr)
        {
            this._dir = new NFSHandle();
            this._dir.Version = V2.RPC.NFSv2Protocol.NFS_VERSION;
            this._dir.xdrDecode(xdr);
            this._name = new Name(xdr);
        }

        public NFSHandle Directory
        {
            get
            { return this._dir; }
            set
            { this._dir = value; }
        }

        public Name Name
        {
            get
            { return this._name; }
            set
            { this._name = value; }
        }
    }

    // End of diropargs.cs
}