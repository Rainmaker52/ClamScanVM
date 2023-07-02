/*
 * Automatically generated by jrpcgen 1.0.7 on 27/08/2010
 * jrpcgen is part of the "Remote Tea.Net" ONC/RPC package for C#
 * See http://remotetea.sourceforge.net for details
 */

using NFSLibrary.Protocols.Commons;
using org.acplt.oncrpc;

namespace NFSLibrary.Protocols.V2.RPC
{
    public class ItemStatus : XdrAble
    {
        private NFSStats _status;
        private ItemAccessOK _ok;

        public ItemStatus()
        { }

        public ItemStatus(XdrDecodingStream xdr)
        { xdrDecode(xdr); }

        public void xdrEncode(XdrEncodingStream xdr)
        {
            xdr.xdrEncodeInt((int)this._status);

            switch (this._status)
            {
                case NFSStats.NFS_OK:
                    this._ok.xdrEncode(xdr);
                    break;

                default:
                    break;
            }
        }

        public void xdrDecode(XdrDecodingStream xdr)
        {
            this._status = (NFSStats)xdr.xdrDecodeInt();

            switch (this._status)
            {
                case NFSStats.NFS_OK:
                    this._ok = new ItemAccessOK(xdr);
                    break;

                default:
                    break;
            }
        }

        public NFSStats Status
        {
            get
            { return this._status; }
        }

        public ItemAccessOK OK
        {
            get
            { return this._ok; }
        }
    }

    public class ItemAccessOK : XdrAble
    {
        private Entry _entries;
        private bool _eof;

        public ItemAccessOK()
        { }

        public ItemAccessOK(XdrDecodingStream xdr)
        { xdrDecode(xdr); }

        public void xdrEncode(XdrEncodingStream xdr)
        {
            if (this._entries != null)
            {
                xdr.xdrEncodeBoolean(true);
                this._entries.xdrEncode(xdr);
            }
            else { xdr.xdrEncodeBoolean(false); };

            xdr.xdrEncodeBoolean(this._eof);
        }

        public void xdrDecode(XdrDecodingStream xdr)
        {
            this._entries = xdr.xdrDecodeBoolean() ? new Entry(xdr) : null;
            this._eof = xdr.xdrDecodeBoolean();
        }

        public Entry Entries
        {
            get
            { return this._entries; }
        }

        public bool EOF
        {
            get
            { return this._eof; }
        }
    }

    // End of readdirres.cs
}