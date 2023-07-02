/*
 * Automatically generated by jrpcgen 1.0.7 on 27/08/2010
 * jrpcgen is part of the "Remote Tea.Net" ONC/RPC package for C#
 * See http://remotetea.sourceforge.net for details
 */

using NFSLibrary.Protocols.Commons;
using org.acplt.oncrpc;

namespace NFSLibrary.Protocols.V3.RPC
{
    public class ReadFolderArguments : XdrAble
    {
        private NFSHandle _item;
        private NFSCookie _cookie;
        private byte[] _cookieverf;
        private int _count;

        public ReadFolderArguments()
        { }

        public ReadFolderArguments(XdrDecodingStream xdr)
        { xdrDecode(xdr); }

        public void xdrEncode(XdrEncodingStream xdr)
        {
            this._item.xdrEncode(xdr);
            this._cookie.xdrEncode(xdr);

            xdr.xdrEncodeOpaque(this._cookieverf, NFSv3Protocol.NFS3_COOKIEVERFSIZE);
            xdr.xdrEncodeInt(this._count);
        }

        public void xdrDecode(XdrDecodingStream xdr)
        {
            this._item = new NFSHandle();
            this._item.Version = V3.RPC.NFSv3Protocol.NFS_V3;
            this._item.xdrDecode(xdr);
            this._cookie = new NFSCookie(xdr);
            this._cookieverf = xdr.xdrDecodeOpaque(NFSv3Protocol.NFS3_COOKIEVERFSIZE);
            this._count = xdr.xdrDecodeInt();
        }

        public NFSHandle HandleObject
        {
            get
            { return this._item; }
            set
            { this._item = value; }
        }

        public NFSCookie Cookie
        {
            get
            { return this._cookie; }
            set
            { this._cookie = value; }
        }

        public byte[] CookieData
        {
            get
            { return this._cookieverf; }
            set
            { this._cookieverf = value; }
        }

        public int Count
        {
            get
            { return this._count; }
            set
            { this._count = value; }
        }
    }

    // End of READDIR3args.cs
}