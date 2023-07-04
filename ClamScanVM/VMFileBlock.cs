namespace ClamScanVM;

internal record VMFileBlock(string FileName, ulong BlockNumber, ReadOnlyMemory<byte> Content);
