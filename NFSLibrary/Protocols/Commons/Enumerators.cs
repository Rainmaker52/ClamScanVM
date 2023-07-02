/*
 * Automatically generated by jrpcgen 1.0.7 on 27/08/2010
 * jrpcgen is part of the "Remote Tea.Net" ONC/RPC package for C#
 * See http://remotetea.sourceforge.net for details
 */
/**
 * Enumeration (collection of constants).
 */

namespace NFSLibrary.Protocols.Commons
{
    public enum NFSItemTypes
    {
        NFNON = 0,
        NFREG = 1,
        NFDIR = 2,
        NFBLK = 3,
        NFCHR = 4,
        NFLNK = 5,
        NFSOCK = 6,
        NFFIFO = 7
    }

    public enum NFSStats
    {
        NFS_OK = 0,
        NFSERR_PERM = 1,
        NFSERR_NOENT = 2,
        NFSERR_IO = 5,
        NFSERR_NXIO = 6,
        NFSERR_ACCES = 13,
        NFSERR_EXIST = 17,
        NFSERR_XDEV = 18,
        NFSERR_NODEV = 19,
        NFSERR_NOTDIR = 20,
        NFSERR_ISDIR = 21,
        NFSERR_INVAL = 22,
        NFSERR_FBIG = 27,
        NFSERR_NOSPC = 28,
        NFSERR_ROFS = 30,
        NFSERR_MLINK = 31,
        NFSERR_NAMETOOLONG = 63,
        NFSERR_NOTEMPTY = 66,
        NFSERR_DQUOT = 69,
        NFSERR_STALE = 70,
        NFSERR_REMOTE = 71,
        NFSERR_WFLUSH = 99,

        NFSERR_BADHANDLE = 10001,
        NFSERR_NOT_SYNC = 10002,
        NFSERR_BAD_COOKIE = 10003,
        NFSERR_NOTSUPP = 10004,
        NFSERR_TOOSMALL = 10005,
        NFSERR_SERVERFAULT = 10006,
        NFSERR_BADTYPE = 10007,
        NFSERR_JUKEBOX = 10008
    }

    public enum NFSMountStats
    {
        MNT_OK = 0,                 /* no error */
        MNTERR_PERM = 1,            /* Not owner */
        MNTERR_NOENT = 2,           /* No such file or directory */
        MNTERR_SRCH = 3,            /* No such process */
        MNTERR_INTR = 4,            /* Interrupted system call */
        MNTERR_IO = 5,              /* I/O error */
        MNTERR_NXIO = 6,            /* No such device or address */
        MNTERR_TOOBIG = 7,          /* Arg list too long */
        MNTERR_NOEXEC = 8,          /* Exec format error */
        MNTERR_BADF = 9,            /* Bad file number */
        MNTERR_CHILD = 10,          /* No child processes */
        MNTERR_AGAIN = 11,          /* Try again (Linux), No more processes (SCO Unix) */
        MNTERR_NOMEM = 12,          /* Out of memory (Linux), Not enough space (SCO Unix) */
        MNTERR_ACCES = 13,          /* Permission denied */
        MNTERR_FAULT = 14,          /* Bad address */
        MNTERR_NOTBLK = 15,         /* Block device required */
        MNTERR_BUSY = 16,           /* Device or resource busy (Linux), Device busy (SCO Unix) */
        MNTERR_EXIST = 17,          /* File exists */
        MNTERR_XDEV = 18,           /* Cross-device link */
        MNTERR_NODEV = 19,          /* No such device */
        MNTERR_NOTDIR = 20,         /* Not a directory */
        MNTERR_ISDIR = 21,          /* Is a directory */
        MNTERR_INVAL = 22,          /* Invalid argument */
        MNTERR_NFILE = 23,          /* File table overflow */
        MNTERR_MFILE = 24,          /* Too many open files */
        MNTERR_NOTTY = 25,          /* Not a typewriter */
        MNTERR_TXTBSY = 26,         /* Text file busy */
        MNTERR_FBIG = 27,           /* File too large */
        MNTERR_NOSPC = 28,          /* No space left on device */
        MNTERR_SPIPE = 29,          /* Illegal seek */
        MNTERR_ROFS = 30,           /* Read-only file system */
        MNTERR_MLINK = 31,          /* Too many links */
        MNTERR_PIPE = 32,           /* Broken pipe */
        MNTERR_NAMETOOLONG = 63,    /* Filename too long */

        MNTERR_NOTSUPP = 10004,     /* Operation not supported */
        MNTERR_SERVERFAULT = 10006  /* A failure on the server */
    };

    // End of nfsstat.cs
}