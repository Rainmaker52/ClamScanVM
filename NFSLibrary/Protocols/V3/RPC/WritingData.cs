/*
 * Automatically generated by jrpcgen 1.0.7 on 27/08/2010
 * jrpcgen is part of the "Remote Tea.Net" ONC/RPC package for C#
 * See http://remotetea.sourceforge.net for details
 */

using org.acplt.oncrpc;

namespace NFSLibrary.Protocols.V3.RPC
{
    public class WritingData : XdrAble
    {
        private PreOperationAttributes _before;
        private PostOperationAttributes _after;

        public WritingData()
        { }

        public WritingData(XdrDecodingStream xdr)
        { xdrDecode(xdr); }

        public void xdrEncode(XdrEncodingStream xdr)
        {
            this._before.xdrEncode(xdr);
            this._after.xdrEncode(xdr);
        }

        public void xdrDecode(XdrDecodingStream xdr)
        {
            this._before = new PreOperationAttributes(xdr);
            this._after = new PostOperationAttributes(xdr);
        }

        public PreOperationAttributes Before
        {
            get
            { return this._before; }
        }

        public PostOperationAttributes After
        {
            get
            { return this._after; }
        }
    }

    // End of wcc_data.cs
}