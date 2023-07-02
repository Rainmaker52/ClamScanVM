/*
 * Automatically generated by jrpcgen 1.0.7 on 27/08/2010
 * jrpcgen is part of the "Remote Tea.Net" ONC/RPC package for C#
 * See http://remotetea.sourceforge.net for details
 */

using NFSLibrary.Protocols.Commons;
using org.acplt.oncrpc;

namespace NFSLibrary.Protocols.V2.RPC
{
    public class SymlinkArguments : XdrAble
    {
        private ItemOperationArguments _from;
        private Name _to;
        private CreateAttributes _attributes;

        public SymlinkArguments()
        { }

        public SymlinkArguments(XdrDecodingStream xdr)
        { xdrDecode(xdr); }

        public void xdrEncode(XdrEncodingStream xdr)
        {
            this._from.xdrEncode(xdr);
            this._to.xdrEncode(xdr);
            this._attributes.xdrEncode(xdr);
        }

        public void xdrDecode(XdrDecodingStream xdr)
        {
            this._from = new ItemOperationArguments(xdr);
            this._to = new Name(xdr);
            this._attributes = new CreateAttributes(xdr);
        }

        public ItemOperationArguments From
        {
            get
            { return this._from; }
        }

        public Name To
        {
            get
            { return this._to; }
        }

        public CreateAttributes Attributes
        {
            get
            { return this._attributes; }
        }
    }

    // End of symlinkargs.cs
}