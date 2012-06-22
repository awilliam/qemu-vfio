#ifndef __VFIO_H__
#define __VFIO_H__

#include "qemu-common.h"
#include "qemu-queue.h"
#include "pci.h"
#include "ioapic.h"
#include "event_notifier.h"

typedef struct VFIOPCIHostDevice {
    uint16_t seg;
    uint8_t bus;
    uint8_t dev:5;
    uint8_t func:3;
} VFIOPCIHostDevice;

typedef struct VFIOBAR {
    off_t fd_offset;
    int fd;
    MemoryRegion mem;
    MemoryRegion mmap_mem;
    void *mmap;
    size_t size;
    uint8_t nr;
} VFIOBAR;

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
    int virq;
    bool use;
} MSIVector;

enum {
    INT_NONE = 0,
    INT_INTx = 1,
    INT_MSI  = 2,
    INT_MSIX = 3,
};

struct VFIOGroup;

typedef struct VFIOContainer {
    int fd;
    MemoryListener listener;
    QLIST_HEAD(, VFIOGroup) group_list;
    QLIST_ENTRY(VFIOContainer) next;
} VFIOContainer;

typedef struct MSIXInfo {
    uint8_t table_bar;
    uint8_t pba_bar;
    uint16_t entries;
    uint32_t table_offset;
    uint32_t pba_offset;
    MemoryRegion mmap_mem;
    void *mmap;
} MSIXInfo;

typedef struct VFIODevice {
    PCIDevice pdev;
    int fd;
    INTx intx;
    unsigned int config_size;
    off_t config_offset;
    unsigned int rom_size;
    off_t rom_offset;
    int msi_cap_size;
    MSIVector *msi_vectors;
    MSIXInfo *msix;
    int nr_vectors;
    int interrupt;
    VFIOBAR bars[PCI_NUM_REGIONS - 1]; /* No ROM */
    VFIOPCIHostDevice host;
    QLIST_ENTRY(VFIODevice) next;
    QEMUTimer *remove_timer;
    uint32_t flags;
    struct VFIOGroup *group;
    bool reset_works;
} VFIODevice;

typedef struct VFIOGroup {
    int fd;
    int groupid;
    VFIOContainer *container;
    QLIST_HEAD(, VFIODevice) device_list;
    QLIST_ENTRY(VFIOGroup) next;
    QLIST_ENTRY(VFIOGroup) container_next;
} VFIOGroup;

#define VFIO_FLAG_IOMMU_SHARED_BIT 0
#define VFIO_FLAG_IOMMU_SHARED (1U << VFIO_FLAG_UIOMMU_SHARED_BIT)

#endif /* __VFIO_H__ */
