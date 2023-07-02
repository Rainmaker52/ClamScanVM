/*
 * Automatically generated by jrpcgen 1.0.7 on 27/08/2010
 * jrpcgen is part of the "Remote Tea.Net" ONC/RPC package for C#
 * See http://remotetea.sourceforge.net for details
 */

using org.acplt.oncrpc;

namespace NFSLibrary.Protocols.V3.RPC
{
    public class CommitAccessOK : XdrAble
    {
        private WritingData _file_wcc;
        private byte[] _verf;

        public CommitAccessOK()
        { }

        public CommitAccessOK(XdrDecodingStream xdr)
        { xdrDecode(xdr); }

        public void xdrEncode(XdrEncodingStream xdr)
        {
            this._file_wcc.xdrEncode(xdr);
            xdr.xdrEncodeOpaque(this._verf, NFSv3Protocol.NFS3_WRITEVERFSIZE);
        }

        public void xdrDecode(XdrDecodingStream xdr)
        {
            this._file_wcc = new WritingData(xdr);
            this._verf = xdr.xdrDecodeOpaque(NFSv3Protocol.NFS3_WRITEVERFSIZE);
        }

        public WritingData Data
        {
            get
            { return this._file_wcc; }
        }

        public byte[] Verification
        {
            get
            { return this._verf; }
        }
    }

    public class CommitAccessFAIL : XdrAble
    {
        private WritingData _file_wcc;

        public CommitAccessFAIL()
        { }

        public CommitAccessFAIL(XdrDecodingStream xdr)
        { xdrDecode(xdr); }

        public void xdrEncode(XdrEncodingStream xdr)
        { this._file_wcc.xdrEncode(xdr); }

        public void xdrDecode(XdrDecodingStream xdr)
        { this._file_wcc = new WritingData(xdr); }

        public WritingData Data
        {
            get
            { return this._file_wcc; }
        }
    }

    // End of COMMIT3res.cs
}