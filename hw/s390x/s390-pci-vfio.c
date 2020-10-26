/*
 * s390 vfio-pci interfaces
 *
 * Copyright 2020 IBM Corp.
 * Author(s): Matthew Rosato <mjrosato@linux.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or (at
 * your option) any later version. See the COPYING file in the top-level
 * directory.
 */

#include <sys/ioctl.h>

#include "qemu/osdep.h"
#include "hw/s390x/s390-pci-vfio.h"
#include "hw/vfio/vfio-common.h"

/*
 * Get the current DMA available count from vfio.  Returns true if vfio is
 * limiting DMA requests, false otherwise.  The current available count read
 * from vfio is returned in avail.
 */
bool s390_pci_update_dma_avail(int fd, unsigned int *avail)
{
    g_autofree struct vfio_iommu_type1_info *info;
    uint32_t argsz;

    assert(avail);

    argsz = sizeof(struct vfio_iommu_type1_info);
    info = g_malloc0(argsz);

    /*
     * If the specified argsz is not large enough to contain all capabilities
     * it will be updated upon return from the ioctl.  Retry until we have
     * a big enough buffer to hold the entire capability chain.
     */
retry:
    info->argsz = argsz;

    if (ioctl(fd, VFIO_IOMMU_GET_INFO, info)) {
        return false;
    }

    if (info->argsz > argsz) {
        argsz = info->argsz;
        info = g_realloc(info, argsz);
        goto retry;
    }

    /* If the capability exists, update with the current value */
    return vfio_get_info_dma_avail(info, avail);
}

