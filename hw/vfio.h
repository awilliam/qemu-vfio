#ifndef __VFIO_H__
#define __VFIO_H__

#include "qemu-common.h"
#include "qemu-queue.h"
#include "pci.h"
#include "ioapic.h"

typedef struct PCIHostDevice {
    uint16_t seg;
    uint8_t bus;
    uint8_t dev:5;
    uint8_t func:3;
} PCIHostDevice;

typedef struct PCIResource {
    bool valid;
    bool mem;
    bool msix;
    bool slow;
    uint8_t bar;
    uint64_t size;
    ram_addr_t memory_index[2];  /* cpu_register_physical_memory() index */
    void *r_virtbase[2];         /* mmapped address */
    int io_mem;                  /* cpu_register_io_memory index */
    pcibus_t e_phys;             /* emulated base address */
    pcibus_t e_size;             /* emulated size of region in bytes */
    uint32_t msix_offset;
    int vfiofd;                  /* see vfio_resource_read/write */
} PCIResource;

typedef struct INTx {
    bool pending;
    uint8_t pin;
    int irq;
    EventNotifier interrupt;
    Notifier eoi;
    Notifier update_irq;
} INTx;

struct VFIODevice;

typedef struct MSIVector {
    EventNotifier interrupt;
    struct VFIODevice *vdev;
    int vector;
} MSIVector;

enum {
    INT_NONE = 0,
    INT_INTx = 1,
    INT_MSI  = 2,
    INT_MSIX = 3,
};

typedef struct VFIOUIOMMU {
    int fd;
    bool opened; /* Did we open fd, or was it opened for us? */
    CPUPhysMemoryClient client;
    QLIST_HEAD(, VFIODevice) vdevs;
    QLIST_ENTRY(VFIOUIOMMU) next;
} VFIOUIOMMU;

typedef struct VFIODevice {
    PCIDevice pdev;
    int vfiofd;
    INTx intx;
    int msi_cap_size;
    MSIVector *msi_vectors;
    int nr_vectors;
    int interrupt;
    PCIResource resources[PCI_NUM_REGIONS - 1]; /* No ROM */
    PCIHostDevice host;
    VFIOUIOMMU *uiommu;
    QLIST_ENTRY(VFIODevice) iommu_next;
    QLIST_ENTRY(VFIODevice) nl_next;
    QEMUTimer *remove_timer;
    uint32_t flags;
    char *vfiofd_name;
    char *uiommufd_name;
} VFIODevice;

/* We can either create a domain per device or a domain per guest using
 * the uiommu interface.  By default we set this bit true to share an
 * iommu domain between devices for a guest.  This uses less resources
 * in the host and eliminates extra physical memory clients for us. */
#define VFIO_FLAG_UIOMMU_SHARED_BIT 0
#define VFIO_FLAG_UIOMMU_SHARED (1U << VFIO_FLAG_UIOMMU_SHARED_BIT)

#endif /* __VFIO_H__ */
