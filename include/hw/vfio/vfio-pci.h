#ifndef VFIO_PCI_H
#define VFIO_PCI_H

#include "qemu/typedefs.h"

/* We expose the concept of a VFIOGroup, though not its internals */
typedef struct VFIOGroup VFIOGroup;

extern VFIOGroup *vfio_pci_device_group(PCIDevice *pdev);

#endif /* VFIO_PCI_H */
