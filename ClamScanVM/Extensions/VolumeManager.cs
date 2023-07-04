using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using DiscUtils;

namespace ClamScanVM;
internal static class Extensions
{
    internal static void AddDisks(this VolumeManager volumeManager, IEnumerable<DiscUtils.VirtualDisk> disks)
    {
        foreach(var disk in disks)
        {
            if(disk != null)
            {
                volumeManager.AddDisk(disk);
            }
        }
    }
}
