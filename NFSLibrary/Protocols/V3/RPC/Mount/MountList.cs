/*
 * Automatically generated by jrpcgen 1.0.7 on 27/08/2010
 * jrpcgen is part of the "Remote Tea.Net" ONC/RPC package for C#
 * See http://remotetea.sourceforge.net for details
 */

using org.acplt.oncrpc;

namespace NFSLibrary.Protocols.V3.RPC.Mount
{
    public class MountList : XdrAble
    {
        private MountBody _value;

        public MountList()
        { }

        public MountList(MountBody value)
        { this._value = value; }

        public MountList(XdrDecodingStream xdr)
        { xdrDecode(xdr); }

        public void xdrEncode(XdrEncodingStream xdr)
        {
            if (this._value != null)
            {
                xdr.xdrEncodeBoolean(true);
                this._value.xdrEncode(xdr);
            }
            else { xdr.xdrEncodeBoolean(false); };
        }

        public void xdrDecode(XdrDecodingStream xdr)
        {
            this._value = xdr.xdrDecodeBoolean() ? new MountBody(xdr) : null;
        }

        public MountBody Value
        {
            get
            { return this._value; }
        }
    }

    // End of mountlist3.cs
}