/*
 * vfio based device assignment support
 *
 * Copyright Red Hat, Inc. 2012
 *
 * Authors:
 *  Alex Williamson <alex.williamson@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Based on qemu-kvm device-assignment:
 *  Adapted for KVM by Qumranet.
 *  Copyright (c) 2007, Neocleus, Alex Novik (alex@neocleus.com)
 *  Copyright (c) 2007, Neocleus, Guy Zana (guy@neocleus.com)
 *  Copyright (C) 2008, Qumranet, Amit Shah (amit.shah@qumranet.com)
 *  Copyright (C) 2008, Red Hat, Amit Shah (amit.shah@redhat.com)
 *  Copyright (C) 2008, IBM, Muli Ben-Yehuda (muli@il.ibm.com)
 */

#include <dirent.h>
#include <stdio.h>
#include <unistd.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#include <netlink/netlink.h>
#include <sys/io.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "config.h"
#include "event_notifier.h"
#include "exec-memory.h"
#include "hw.h"
#include "kvm.h"
#include "memory.h"
#include "monitor.h"
#include "msi.h"
#include "msix.h"
#include "notify.h"
#include "pc.h"
#include "qemu-error.h"
#include "qemu-timer.h"
#include "range.h"
#include "vfio_pci.h"
#include <pci/header.h>
#include <pci/types.h>
#include <linux/types.h>
#include "linux-vfio.h"

//#define DEBUG_VFIO
#ifdef DEBUG_VFIO
#define DPRINTF(fmt, ...) \
    do { printf("vfio: " fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

/* TODO: msix.h should define these */
#define MSIX_CAP_LENGTH 12
#define MSIX_PAGE_SIZE 0x1000

static QLIST_HEAD(, VFIOContainer)
    container_list = QLIST_HEAD_INITIALIZER(container_list);

static QLIST_HEAD(, VFIOGroup)
    group_list = QLIST_HEAD_INITIALIZER(group_list);

static void vfio_disable_interrupts(VFIODevice *vdev);
static uint32_t vfio_pci_read_config(PCIDevice *pdev, uint32_t addr, int len);

static uint8_t vfio_find_cap_offset(PCIDevice *pdev, uint8_t cap)
{
    int max_cap = (PCI_CONFIG_SPACE_SIZE - PCI_CONFIG_HEADER_SIZE) /
                  PCI_CAP_SIZEOF;
    uint8_t id, pos = PCI_CAPABILITY_LIST;

    if (!(pdev->config[PCI_STATUS] & PCI_STATUS_CAP_LIST)) {
        return 0;
    }

    while (max_cap--) {
        pos = pdev->config[pos] & ~3;
        if (pos < PCI_CONFIG_HEADER_SIZE) {
            break;
        }

        id = pdev->config[pos + PCI_CAP_LIST_ID];

        if (id == 0xff) {
            break;
        }
        if (id == cap) {
            return pos;
        }

        pos += PCI_CAP_LIST_NEXT;
    }
    return 0;
}

/*
 * QDev routines
 */
static int parse_hostaddr(DeviceState *qdev, Property *prop, const char *str)
{
    PCIHostDevice *ptr = qdev_get_prop_ptr(qdev, prop);
    const char *p = str;
    int n, seg, bus, dev, func;
    char field[5];

    if (sscanf(p, "%4[^:]%n", field, &n) != 1 || p[n] != ':') {
        return -EINVAL;
    }

    seg = strtol(field, NULL, 16);
    p += n + 1;

    if (sscanf(p, "%4[^:]%n", field, &n) != 1) {
        return -EINVAL;
    }

    if (p[n] == ':') {
        bus = strtol(field, NULL, 16);
        p += n + 1;
    } else {
        bus = seg;
        seg = 0;
    }

    if (sscanf(p, "%4[^.]%n", field, &n) != 1 || p[n] != '.') {
        return -EINVAL;
    }

    dev = strtol(field, NULL, 16);
    p += n + 1;

    if (!qemu_isdigit(*p)) {
        return -EINVAL;
    }

    func = *p - '0';

    ptr->seg = seg;
    ptr->bus = bus;
    ptr->dev = dev;
    ptr->func = func;
    return 0;
}

static int print_hostaddr(DeviceState *qdev, Property *prop,
                          char *dest, size_t len)
{
    PCIHostDevice *ptr = qdev_get_prop_ptr(qdev, prop);

    return snprintf(dest, len, "%04x:%02x:%02x.%x",
                    ptr->seg, ptr->bus, ptr->dev, ptr->func);
}

/*
 * INTx
 */
static inline void vfio_unmask_intx(VFIODevice *vdev)
{
    struct vfio_irq_set irq_set =
        {
            .argsz = sizeof(irq_set),
            .flags = VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_UNMASK,
            .index = VFIO_PCI_INTX_IRQ_INDEX,
            .start = 0,
            .count = 1,
        };

    ioctl(vdev->fd, VFIO_DEVICE_SET_IRQS, &irq_set);
}

static void vfio_intx_interrupt(void *opaque)
{
    VFIODevice *vdev = opaque;

    if (!event_notifier_test_and_clear(&vdev->intx.interrupt)) {
        return;
    }

    DPRINTF("%s(%04x:%02x:%02x.%x) Pin %c\n", __FUNCTION__, vdev->host.seg,
            vdev->host.bus, vdev->host.dev, vdev->host.func,
            'A' + vdev->intx.pin);

    vdev->intx.pending = true;
    qemu_set_irq(vdev->pdev.irq[vdev->intx.pin], 1);
}

static void vfio_eoi(Notifier *notify, void *data)
{
    VFIODevice *vdev = container_of(notify, VFIODevice, intx.eoi);

    if (!vdev->intx.pending) {
        return;
    }

    DPRINTF("%s(%04x:%02x:%02x.%x) EOI\n", __FUNCTION__, vdev->host.seg,
            vdev->host.bus, vdev->host.dev, vdev->host.func);

    vdev->intx.pending = false;
    qemu_set_irq(vdev->pdev.irq[vdev->intx.pin], 0);
    vfio_unmask_intx(vdev);
}

static void vfio_update_irq(Notifier *notify, void *data)
{
    VFIODevice *vdev = container_of(notify, VFIODevice, intx.update_irq);
    int irq = pci_get_irq(&vdev->pdev, vdev->intx.pin);

    if (irq == vdev->intx.irq) {
        return;
    }

    DPRINTF("%s(%04x:%02x:%02x.%x) IRQ moved %d -> %d\n", __FUNCTION__,
            vdev->host.seg, vdev->host.bus, vdev->host.dev,
            vdev->host.func, vdev->intx.irq, irq);

    ioapic_remove_gsi_eoi_notifier(&vdev->intx.eoi, vdev->intx.irq);

    vdev->intx.irq = irq;

    if (irq < 0) {
        fprintf(stderr, "vfio: Error - INTx moved to IRQ %d\n", irq);
        return;
    }

    ioapic_add_gsi_eoi_notifier(&vdev->intx.eoi, vdev->intx.irq);

    /* Re-enable the interrupt in cased we missed an EOI */
    vfio_eoi(&vdev->intx.eoi, NULL);
}

static int vfio_enable_intx(VFIODevice *vdev)
{
    struct vfio_irq_set *irq_set;
    int32_t *fd;
    int argsz = sizeof(*irq_set) + sizeof(*fd);
    uint8_t pin = vfio_pci_read_config(&vdev->pdev, PCI_INTERRUPT_PIN, 1);

    if (!pin) {
        return 0;
    }

    irq_set = g_malloc(argsz);
    irq_set->argsz = argsz;
    irq_set->flags = VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER;
    irq_set->index = VFIO_PCI_INTX_IRQ_INDEX;
    irq_set->start = 0;
    irq_set->count = 1;
    fd = (int32_t *)&irq_set->data;

    vfio_disable_interrupts(vdev);

    vdev->intx.pin = pin - 1; /* Pin A (1) -> irq[0] */
    vdev->intx.irq = pci_get_irq(&vdev->pdev, vdev->intx.pin);
    vdev->intx.eoi.notify = vfio_eoi;
    ioapic_add_gsi_eoi_notifier(&vdev->intx.eoi, vdev->intx.irq);

    vdev->intx.update_irq.notify = vfio_update_irq;
    pci_add_irq_update_notifier(&vdev->pdev, &vdev->intx.update_irq);

    if (event_notifier_init(&vdev->intx.interrupt, 0)) {
        fprintf(stderr, "vfio: Error: event_notifier_init failed\n");
        g_free(irq_set);
        return -1;
    }

    *fd = event_notifier_get_fd(&vdev->intx.interrupt);
    qemu_set_fd_handler(*fd, vfio_intx_interrupt, NULL, vdev);

    if (ioctl(vdev->fd, VFIO_DEVICE_SET_IRQS, irq_set)) {
        fprintf(stderr, "vfio: Error: Failed to setup INTx fd %s\n",
                strerror(errno));
        g_free(irq_set);
        return -1;
    }

    vdev->interrupt = INT_INTx;

    DPRINTF("%s(%04x:%02x:%02x.%x)\n", __FUNCTION__, vdev->host.seg,
            vdev->host.bus, vdev->host.dev, vdev->host.func);

    g_free(irq_set);

    return 0;
}

static void vfio_disable_intx(VFIODevice *vdev)
{
    int fd;
    struct vfio_irq_set irq_set =
        {
            .argsz = sizeof(irq_set),
            .flags = VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_TRIGGER,
            .index = VFIO_PCI_INTX_IRQ_INDEX,
            .start = 0,
            .count = 0,
        };

    ioctl(vdev->fd, VFIO_DEVICE_SET_IRQS, &irq_set);

    pci_remove_irq_update_notifier(&vdev->intx.update_irq);
    ioapic_remove_gsi_eoi_notifier(&vdev->intx.eoi, vdev->intx.irq);

    fd = event_notifier_get_fd(&vdev->intx.interrupt);
    qemu_set_fd_handler(fd, NULL, NULL, vdev);
    event_notifier_cleanup(&vdev->intx.interrupt);

    vdev->interrupt = INT_NONE;

    DPRINTF("%s(%04x:%02x:%02x.%x)\n", __FUNCTION__, vdev->host.seg,
            vdev->host.bus, vdev->host.dev, vdev->host.func);
}

/*
 * MSI/X
 */
static void vfio_msi_interrupt(void *opaque)
{
    MSIVector *vec = opaque;
    VFIODevice *vdev = vec->vdev;

    if (!event_notifier_test_and_clear(&vec->interrupt)) {
        return;
    }

    DPRINTF("%s(%04x:%02x:%02x.%x) vector %d\n", __FUNCTION__, vdev->host.seg,
            vdev->host.bus, vdev->host.dev, vdev->host.func, vec->vector);

    if (vdev->interrupt == INT_MSIX) {
        msix_notify(&vdev->pdev, vec->vector);
    } else if (vdev->interrupt == INT_MSI) {
        msi_notify(&vdev->pdev, vec->vector);
    } else {
        fprintf(stderr, "vfio: MSI interrupt receieved, but not enabled?\n");
    }
}

static void vfio_enable_msi(VFIODevice *vdev, bool msix)
{
    struct vfio_irq_set *irq_set;
    int ret, i, argsz;
    int32_t *fds;

    vfio_disable_interrupts(vdev);

    vdev->nr_vectors = msix ? vdev->pdev.msix_entries_nr :
                              msi_nr_vectors_allocated(&vdev->pdev);
retry:
    vdev->msi_vectors = g_malloc(vdev->nr_vectors * sizeof(MSIVector));

    argsz = sizeof(*irq_set) + (vdev->nr_vectors * sizeof(*fds));
    irq_set = g_malloc(argsz);
    irq_set->argsz = argsz;
    irq_set->flags = VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER;
    irq_set->index = msix ? VFIO_PCI_MSIX_IRQ_INDEX : VFIO_PCI_MSI_IRQ_INDEX;
    irq_set->start = 0;
    irq_set->count = vdev->nr_vectors;
    fds = (int32_t *)&irq_set->data;

    for (i = 0; i < vdev->nr_vectors; i++) {
        int fd;

        vdev->msi_vectors[i].vdev = vdev;
        vdev->msi_vectors[i].vector = i;

        if (event_notifier_init(&vdev->msi_vectors[i].interrupt, 0)) {
            fprintf(stderr, "vfio: Error: event_notifier_init failed\n");
        }

        fd = event_notifier_get_fd(&vdev->msi_vectors[i].interrupt);
        qemu_set_fd_handler(fd, vfio_msi_interrupt, NULL,
                            &vdev->msi_vectors[i]);

        fds[i] = fd;

        if (msix && msix_vector_use(&vdev->pdev, i) < 0) {
            fprintf(stderr, "vfio: Error msix_vector_use\n");
        }
    }

    ret = ioctl(vdev->fd, VFIO_DEVICE_SET_IRQS, irq_set);
    if (ret) {
        if (ret < 0) {
            fprintf(stderr, "vfio: Error: Failed to setup MSI/X fds %s\n",
                    strerror(errno));
        } else if (ret != vdev->nr_vectors) {
            DPRINTF("%s(): Unable to allocate %d MSI vectors, retry with %d\n",
                    __FUNCTION__, irq_set->count, ret);
        }
        for (i = 0; i < vdev->nr_vectors; i++) {
            if (msix) {
                msix_vector_unuse(&vdev->pdev, i);
            }
            qemu_set_fd_handler(fds[i], NULL, NULL, NULL);
            event_notifier_cleanup(&vdev->msi_vectors[i].interrupt);
        }
        g_free(irq_set);
        g_free(vdev->msi_vectors);
        if (ret > 0 && ret != vdev->nr_vectors) {
            vdev->nr_vectors = ret;
            goto retry;
        }
        vdev->nr_vectors = 0;
	
        return;
    }

    vdev->interrupt = msix ? INT_MSIX : INT_MSI;

    g_free(irq_set);

    DPRINTF("%s(%04x:%02x:%02x.%x) Enabled %d vectors\n", __FUNCTION__,
            vdev->host.seg, vdev->host.bus, vdev->host.dev,
            vdev->host.func, vdev->nr_vectors);
}

static void vfio_disable_msi(VFIODevice *vdev, bool msix)
{
    struct vfio_irq_set irq_set =
        {
            .argsz = sizeof(irq_set),
            .flags = VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_TRIGGER,
            .index = msix ? VFIO_PCI_MSIX_IRQ_INDEX : VFIO_PCI_MSI_IRQ_INDEX,
            .start = 0,
            .count = 0,
        };
    int i;

    ioctl(vdev->fd, VFIO_DEVICE_SET_IRQS, &irq_set);

    for (i = 0; i < vdev->nr_vectors; i++) {
        int fd = event_notifier_get_fd(&vdev->msi_vectors[i].interrupt);

        if (msix) {
            msix_vector_unuse(&vdev->pdev, i);
        }

        qemu_set_fd_handler(fd, NULL, NULL, NULL);
        event_notifier_cleanup(&vdev->msi_vectors[i].interrupt);
    }

    g_free(vdev->msi_vectors);
    vdev->nr_vectors = 0;
    vdev->interrupt = INT_NONE;

    DPRINTF("%s(%04x:%02x:%02x.%x)\n", __FUNCTION__, vdev->host.seg,
            vdev->host.bus, vdev->host.dev, vdev->host.func);

    vfio_enable_intx(vdev);
}

/*
 * IO Port/MMIO
 */
static void vfio_resource_write(void *opaque, target_phys_addr_t addr,
                                uint64_t data, unsigned size)
{
    PCIResource *res = opaque;
    uint8_t tmp[8];

    switch (size) {
    case 1:
        *tmp = data & 0xff;
        break;
    case 2:
        *(uint16_t *)tmp = cpu_to_le16(data);
        break;
    case 4:
        *(uint32_t *)tmp = cpu_to_le32(data);
        break;
    default:
        hw_error("vfio: unsupported write size, %d bytes\n", size);
    }

    if (pwrite(res->fd, tmp, size, res->offset + addr) != size) {
        fprintf(stderr, "%s(,0x%"PRIx64", 0x%"PRIx64", %d) failed: %s\n",
                __FUNCTION__, addr, data, size, strerror(errno));
    }

    DPRINTF("%s(BAR%d+0x%"PRIx64", 0x%"PRIx64", %d)\n",
            __FUNCTION__, res->bar, addr, data, size);
}

static uint64_t vfio_resource_read(void *opaque,
                                   target_phys_addr_t addr, unsigned size)
{
    PCIResource *res = opaque;
    uint8_t tmp[8];
    uint64_t data = 0;

    if (pread(res->fd, tmp, size, res->offset + addr) != size) {
        fprintf(stderr, "%s(,0x%"PRIx64", %d) failed: %s\n",
                __FUNCTION__, addr, size, strerror(errno));
        return (uint64_t)-1;
    }

    switch (size) {
    case 1:
        data = tmp[0];
        break;
    case 2:
        data = le16_to_cpu(*(uint16_t *)tmp);
        break;
    case 4:
        data = le32_to_cpu(*(uint32_t *)tmp);
        break;
    default:
        hw_error("vfio: unsupported read size, %d bytes\n", size);
    }

    DPRINTF("%s(BAR%d+0x%"PRIx64", %d) = 0x%"PRIx64"\n",
            __FUNCTION__, res->bar, addr, size, data);

    return data;
}

static const MemoryRegionOps vfio_resource_ops = {
    .read = vfio_resource_read,
    .write = vfio_resource_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

/*
 * PCI config space
 */
static uint32_t vfio_pci_read_config(PCIDevice *pdev, uint32_t addr, int len)
{
    VFIODevice *vdev = DO_UPCAST(VFIODevice, pdev, pdev);
    uint32_t val = 0;

    if (ranges_overlap(addr, len, PCI_ROM_ADDRESS, 4) ||
        (pdev->cap_present & QEMU_PCI_CAP_MSIX &&
         ranges_overlap(addr, len, pdev->msix_cap, MSIX_CAP_LENGTH)) ||
        (pdev->cap_present & QEMU_PCI_CAP_MSI &&
         ranges_overlap(addr, len, pdev->msi_cap, vdev->msi_cap_size))) {

        val = pci_default_read_config(pdev, addr, len);
    } else {
        if (pread(vdev->fd, &val, len, vdev->config_offset + addr) != len) {
            fprintf(stderr, "%s(%04x:%02x:%02x.%x, 0x%x, 0x%x) failed: %s\n",
                    __FUNCTION__, vdev->host.seg, vdev->host.bus,
                    vdev->host.dev, vdev->host.func, addr, len,
                    strerror(errno));
            return -1;
        }
        val = le32_to_cpu(val);
    }

    /* Multifunction bit is virualized in qemu */
    if (unlikely(ranges_overlap(addr, len, PCI_HEADER_TYPE, 1))) {
        uint32_t mask = PCI_HEADER_TYPE_MULTI_FUNCTION;

        if (len == 4) {
            mask <<= 16;
        }

        if (pdev->cap_present & QEMU_PCI_CAP_MULTIFUNCTION) {
            val |= mask;
        } else {
            val &= ~mask;
        }
    }

    DPRINTF("%s(%04x:%02x:%02x.%x, @0x%x, len=0x%x) %x\n", __FUNCTION__,
            vdev->host.seg, vdev->host.bus, vdev->host.dev,
            vdev->host.func, addr, len, val);
    return val;
}

static void vfio_pci_write_config(PCIDevice *pdev, uint32_t addr,
                                  uint32_t val, int len)
{
    VFIODevice *vdev = DO_UPCAST(VFIODevice, pdev, pdev);
    uint32_t val_le = cpu_to_le32(val);

    DPRINTF("%s(%04x:%02x:%02x.%x, @0x%x, 0x%x, len=0x%x)\n", __FUNCTION__,
            vdev->host.seg, vdev->host.bus, vdev->host.dev,
            vdev->host.func, addr, val, len);

    /* Write everything to VFIO, let it filter out what we can't write */
    if (pwrite(vdev->fd, &val_le, len, vdev->config_offset + addr) != len) {
        fprintf(stderr, "%s(%04x:%02x:%02x.%x, 0x%x, 0x%x, 0x%x) failed: %s\n",
                __FUNCTION__, vdev->host.seg, vdev->host.bus, vdev->host.dev,
                vdev->host.func, addr, val, len, strerror(errno));
    }

    /* Write standard header bits to emulation */
    if (addr < PCI_CONFIG_HEADER_SIZE) {
        pci_default_write_config(pdev, addr, val, len);
        return;
    }

    /* MSI/MSI-X Enabling/Disabling */
    if (pdev->cap_present & QEMU_PCI_CAP_MSI &&
        ranges_overlap(addr, len, pdev->msi_cap, vdev->msi_cap_size)) {
        int is_enabled, was_enabled = msi_enabled(pdev);

        pci_default_write_config(pdev, addr, val, len);
        msi_write_config(pdev, addr, val, len);

        is_enabled = msi_enabled(pdev);

        if (!was_enabled && is_enabled) {
            vfio_enable_msi(vdev, false);
        } else if (was_enabled && !is_enabled) {
            vfio_disable_msi(vdev, false);
        }
    }

    if (pdev->cap_present & QEMU_PCI_CAP_MSIX &&
        ranges_overlap(addr, len, pdev->msix_cap, MSIX_CAP_LENGTH)) {
        int is_enabled, was_enabled = msix_enabled(pdev);

        pci_default_write_config(pdev, addr, val, len);
        msix_write_config(pdev, addr, val, len);

        is_enabled = msix_enabled(pdev);

        if (!was_enabled && is_enabled) {
            vfio_enable_msi(vdev, true);
        } else if (was_enabled && !is_enabled) {
            vfio_disable_msi(vdev, true);
        }
    }
}

/*
 * DMA
 */
static int vfio_dma_map(VFIOContainer *container,
                        target_phys_addr_t iova,
                        ram_addr_t size, void* vaddr)
{
    struct vfio_iommu_x86_dma_map map =
        {
            .argsz = sizeof(map),
            .flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE,
            .vaddr = (__u64)vaddr,
            .iova = iova,
            .size = size,
        };

    if (ioctl(container->fd, VFIO_IOMMU_MAP_DMA, &map)) {
        DPRINTF("VFIO_MAP_DMA: %d\n", errno);
        return -errno;
    }

    return 0;
}

static int vfio_dma_unmap(VFIOContainer *container,
                          target_phys_addr_t iova, ram_addr_t size)
{
    struct vfio_iommu_x86_dma_unmap unmap =
        {
            .argsz = sizeof(unmap),
            .flags = 0,
            .iova = iova,
            .size = size,
        };

    if (ioctl(container->fd, VFIO_IOMMU_UNMAP_DMA, &unmap)) {
        DPRINTF("VFIO_UNMAP_DMA: %d\n", errno);
        return -errno;
    }

    return 0;
}

static void vfio_listener_dummy1(MemoryListener *listener)
{
    /* We don't do batching (begin/commit) or care about logging */
}

static void vfio_listener_dummy2(MemoryListener *listener,
                                 MemoryRegionSection *section)
{
    /* We don't do logging or care about nops */
}

static void vfio_listener_dummy3(MemoryListener *listener,
                                 MemoryRegionSection *section,
                                 bool match_data, uint64_t data, int fd)
{
    /* We don't care about eventfds */
}
 
static bool vfio_listener_skipped_section(MemoryRegionSection *section)
{
    return (section->address_space != get_system_memory() ||
            !memory_region_is_ram(section->mr));
}

static void vfio_listener_region_add(MemoryListener *listener,
                                     MemoryRegionSection *section)
{
    VFIOContainer *container = container_of(listener, VFIOContainer, listener);
    target_phys_addr_t iova = section->offset_within_address_space;
    ram_addr_t size = section->size;
    void *vaddr;
    int ret;

    if (vfio_listener_skipped_section(section)) {
        DPRINTF("vfio: SKIPPING region_add %016lx - %016lx\n",
                iova, iova + size - 1);
        return;
    }

    vaddr = memory_region_get_ram_ptr(section->mr) +
            section->offset_within_region;

    DPRINTF("vfio: region_add %016lx - %016lx [%p]\n",
            iova, iova + size - 1, vaddr);

    ret = vfio_dma_map(container, iova, size, vaddr);
    if (ret) {
        error_report("vfio_dma_map(%p, 0x%016lx, 0x%lx, %p) = %d (%s)\n",
                     container, iova, size, vaddr, ret, strerror(errno));
    }
}

static void vfio_listener_region_del(MemoryListener *listener,
                                     MemoryRegionSection *section)
{
    VFIOContainer *container = container_of(listener, VFIOContainer, listener);
    target_phys_addr_t iova = section->offset_within_address_space;
    ram_addr_t size = section->size;
    int ret;

    if (vfio_listener_skipped_section(section)) {
        DPRINTF("vfio: SKIPPING region_del %016lx - %016lx\n",
                iova, iova + size - 1);
        return;
    }

    DPRINTF("vfio: region_del %016lx - %016lx\n", iova, iova + size - 1);

    ret = vfio_dma_unmap(container, iova, size);
    if (ret) {
        error_report("vfio_dma_unmap(%p, 0x%016lx, 0x%lx) = %d (%s)\n",
                     container, iova, size, ret, strerror(errno));
    }
}

/*
 * Interrupt setup
 */
static void vfio_disable_interrupts(VFIODevice *vdev)
{
    switch (vdev->interrupt) {
    case INT_INTx:
        vfio_disable_intx(vdev);
        break;
    case INT_MSI:
        vfio_disable_msi(vdev, false);
        break;
    case INT_MSIX:
        vfio_disable_msi(vdev, true);
    }
}

static int vfio_setup_msi(VFIODevice *vdev)
{
    int pos;

    if ((pos = vfio_find_cap_offset(&vdev->pdev, PCI_CAP_ID_MSI))) {
        uint16_t ctrl;
        bool msi_64bit, msi_maskbit;
        int entries;

        if (pread(vdev->fd, &ctrl, sizeof(ctrl),
                  vdev->config_offset + pos + PCI_CAP_FLAGS) != sizeof(ctrl)) {
            return -1;
        }
        ctrl = le16_to_cpu(ctrl);

        msi_64bit = !!(ctrl & PCI_MSI_FLAGS_64BIT);
        msi_maskbit = !!(ctrl & PCI_MSI_FLAGS_MASKBIT);
        entries = 1 << ((ctrl & PCI_MSI_FLAGS_QMASK) >> 1);

        DPRINTF("%04x:%02x:%02x.%x PCI MSI CAP @0x%x\n", vdev->host.seg,
                vdev->host.bus, vdev->host.dev, vdev->host.func, pos);

        if (msi_init(&vdev->pdev, pos, entries, msi_64bit, msi_maskbit) < 0) {
            fprintf(stderr, "vfio: msi_init failed\n");
            return -1;
        }
        vdev->msi_cap_size = 0xa + (msi_maskbit ? 0xa : 0) +
                             (msi_64bit ? 0x4 : 0);
    }

    if ((pos = vfio_find_cap_offset(&vdev->pdev, PCI_CAP_ID_MSIX))) {
        uint16_t ctrl;
        uint32_t table;

        if (pread(vdev->fd, &ctrl, sizeof(ctrl),
                  vdev->config_offset + pos + PCI_CAP_FLAGS) != sizeof(ctrl)) {
            return -1;
        }

        if (pread(vdev->fd, &table, sizeof(table), vdev->config_offset +
                  pos + PCI_MSIX_TABLE) != sizeof(table)) {
            return -1;
        }

        ctrl = le16_to_cpu(ctrl);
        table = le32_to_cpu(table);

        vdev->msix = g_malloc0(sizeof(*(vdev->msix)));
        vdev->msix->bar = table & PCI_MSIX_BIR;
        vdev->msix->offset = table & ~(MSIX_PAGE_SIZE - 1);
        vdev->msix->entries = (ctrl & PCI_MSIX_TABSIZE) + 1;

        DPRINTF("%04x:%02x:%02x.%x PCI MSI-X CAP @0x%x, BAR %d, offset 0x%x\n",
                vdev->host.seg, vdev->host.bus, vdev->host.dev,
                vdev->host.func, pos, vdev->msix->bar, table & ~PCI_MSIX_BIR);
    }
    return 0;
}

static void vfio_teardown_msi(VFIODevice *vdev)
{
    msi_uninit(&vdev->pdev);
    msix_uninit(&vdev->pdev, &vdev->resources[vdev->msix->bar].region);
}

/*
 * Resource setup
 */
static void vfio_unmap_region(VFIODevice *vdev, int bar)
{
    PCIResource *res = &vdev->resources[bar];

    if (res->slow) {
        memory_region_destroy(&res->region);
    } else if (vdev->msix && vdev->msix->bar == bar) {
        if (res->virtbase) {
            memory_region_del_subregion(&res->region, &vdev->msix->region_lo);
            munmap(res->virtbase, vdev->msix->offset);
            memory_region_destroy(&vdev->msix->region_lo);
        }

        if (vdev->msix->virtbase) {
            memory_region_del_subregion(&res->region, &vdev->msix->region_hi);
            munmap(vdev->msix->virtbase,
                   res->size - (vdev->msix->offset + MSIX_PAGE_SIZE));
            memory_region_destroy(&vdev->msix->region_hi);
        }

        memory_region_destroy(&res->region);
    } else {
        memory_region_destroy(&res->region);
        munmap(res->virtbase, res->size);
    }
}

static void vfio_map_region(VFIODevice *vdev, int bar, char *name)
{
    PCIResource *res = &vdev->resources[bar];

    if (res->size & 0xfff) {
        goto slow;
    }

    if (!vdev->msix || vdev->msix->bar != bar) {
        res->virtbase = mmap(NULL, res->size, PROT_READ | PROT_WRITE,
                             MAP_SHARED, vdev->fd, res->offset);
        if (res->virtbase == MAP_FAILED) {
            goto slow;
        }

        memory_region_init_ram_ptr(&res->region,
                                   name, res->size, res->virtbase);
        return; /* Done */
    }

    memory_region_init(&res->region, name, res->size);

    if (vdev->msix->offset) {
        res->virtbase = mmap(NULL, vdev->msix->offset, PROT_READ | PROT_WRITE,
                             MAP_SHARED, vdev->fd, res->offset);
        if (res->virtbase == MAP_FAILED) {
            memory_region_destroy(&res->region);
            goto slow;
        }

        memory_region_init_ram_ptr(&vdev->msix->region_lo,
                                   "lo", vdev->msix->offset, res->virtbase);
        memory_region_add_subregion(&res->region, 0, &vdev->msix->region_lo);
    }

    if (res->size > vdev->msix->offset + MSIX_PAGE_SIZE) {
        off_t offset = vdev->msix->offset + MSIX_PAGE_SIZE;
        size_t size = res->size - offset;

        vdev->msix->virtbase = mmap(NULL, size, PROT_READ | PROT_WRITE,
                                    MAP_SHARED, vdev->fd, res->offset + offset);
        if (vdev->msix->virtbase == MAP_FAILED) {
            if (res->virtbase) {
                memory_region_del_subregion(&res->region,
                                            &vdev->msix->region_lo);
                munmap(res->virtbase, vdev->msix->offset);
                memory_region_destroy(&vdev->msix->region_lo);
            }
            memory_region_destroy(&res->region);
            goto slow;
        }

        memory_region_init_ram_ptr(&vdev->msix->region_hi,
                                   "hi", size, vdev->msix->virtbase);
        memory_region_add_subregion(&res->region, offset,
                                    &vdev->msix->region_hi);
    }

    return; /* Done */

slow:

    res->slow = true;

    DPRINTF("%s(%04x:%02x:%02x.%x) Using slow mapping for BAR %d\n",
            __FUNCTION__, vdev->host.seg, vdev->host.bus,
            vdev->host.dev, vdev->host.func, bar);

    memory_region_init_io(&res->region, &vfio_resource_ops,
                          res, name, res->size);
}

static int vfio_map_resources(VFIODevice *vdev)
{
    int i;

    for (i = 0; i < VFIO_PCI_ROM_REGION_INDEX; i++) {
        PCIResource *res;
        uint32_t bar;
        uint8_t offset;
        int ret, space;
        const VMStateDescription *vmsd;
        char name[32];

        res = &vdev->resources[i];
        res->fd = vdev->fd;
        res->bar = i;

        if (!res->size) {
            continue;
        }

        offset = PCI_BASE_ADDRESS_0 + (4 * i);
        ret = pread(vdev->fd, &bar, sizeof(bar), vdev->config_offset + offset);
        if (ret != sizeof(bar)) {
            fprintf(stderr, "vfio: Failed to read BAR %d (%s)\n",
                    i, strerror(errno));
            return -1;
        }

        bar = le32_to_cpu(bar);
        space = bar & PCI_BASE_ADDRESS_SPACE;

        vmsd = qdev_get_vmsd(DEVICE(&vdev->pdev));

        if (vmsd) {
            snprintf(name, sizeof(name), "%s.bar%d", vmsd->name, i);
        } else {
            snprintf(name, sizeof(name), "%s.bar%d",
                     object_get_typename(OBJECT(&vdev->pdev)), i);
        }

        if (space == PCI_BASE_ADDRESS_SPACE_MEMORY) {
            res->mem = true;

            vfio_map_region(vdev, i, name);

            if (vdev->msix && vdev->msix->bar == i) {
                if (msix_init(&vdev->pdev, vdev->msix->entries,
                              &res->region, i, res->size) < 0) {
                    vfio_unmap_region(vdev, i);

                    fprintf(stderr, "vfio: msix_init failed\n");
                    return -1;
                }
            }

            pci_register_bar(&vdev->pdev, i,
                             bar & ~PCI_BASE_ADDRESS_MEM_MASK, &res->region);

            if (bar & PCI_BASE_ADDRESS_MEM_TYPE_64) {
                i++;
            }

            res->valid = true;
        } else if (space == PCI_BASE_ADDRESS_SPACE_IO) {

            memory_region_init_io(&res->region, &vfio_resource_ops, res,
                                  name, res->size);

            pci_register_bar(&vdev->pdev, i,
                             PCI_BASE_ADDRESS_SPACE_IO, &res->region);
            res->valid = true;
        }
    }
    return 0;
}

static void vfio_unmap_resources(VFIODevice *vdev)
{
    int i;
    PCIResource *res = vdev->resources;

    for (i = 0; i < PCI_ROM_SLOT; i++, res++) {
        if (res->valid) {
            if (res->mem) {
                vfio_unmap_region(vdev, i);
            } else {
                memory_region_destroy(&res->region);
            }
            res->valid = false;
        }
    }
}

#if 0
/*
 * Netlink
 */
static QLIST_HEAD(, VFIODevice) nl_list = QLIST_HEAD_INITIALIZER(nl_list);
static struct nl_handle *vfio_nl_handle;
static int vfio_nl_family;

static void vfio_netlink_event(void *opaque)
{
    nl_recvmsgs_default(vfio_nl_handle);
}

static void vfio_remove_abort(void *opaque)
{
    VFIODevice *vdev = opaque;

    error_report("ERROR: Host requested removal of VFIO device "
                 "%04x:%02x:%02x.%x, guest did not respond.  Abort.\n",
                 vdev->host.seg, vdev->host.bus,
                 vdev->host.dev, vdev->host.func);
    abort();
}

static int vfio_parse_netlink(struct nl_msg *msg, void *arg)
{
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct sockaddr_nl *sockaddr = nlmsg_get_src(msg);
    struct genlmsghdr *genl;
    struct nlattr *attrs[VFIO_NL_ATTR_MAX + 1];
    VFIODevice *vdev = NULL;
    int cmd;
    u16 seg;
    u8 bus, dev, func;

    /* Filter out any messages not from the kernel */
    if (sockaddr->nl_pid != 0) {
        return 0;
    }

    genl = nlmsg_data(nlh);
    cmd = genl->cmd;        

    genlmsg_parse(nlh, 0, attrs, VFIO_NL_ATTR_MAX, NULL);

    if (!attrs[VFIO_ATTR_PCI_DOMAIN] || !attrs[VFIO_ATTR_PCI_BUS] ||
        !attrs[VFIO_ATTR_PCI_SLOT] || !attrs[VFIO_ATTR_PCI_FUNC]) {
        fprintf(stderr, "vfio: Invalid netlink message, no device info\n");
        return -1;
    }

    seg = nla_get_u16(attrs[VFIO_ATTR_PCI_DOMAIN]);
    bus = nla_get_u8(attrs[VFIO_ATTR_PCI_BUS]);
    dev = nla_get_u8(attrs[VFIO_ATTR_PCI_SLOT]);
    func = nla_get_u8(attrs[VFIO_ATTR_PCI_FUNC]);

    DPRINTF("Received command %d from netlink for device %04x:%02x:%02x.%x\n",
            cmd, seg, bus, dev, func);

    QLIST_FOREACH(vdev, &nl_list, nl_next) {
        if (seg == vdev->host.seg && bus == vdev->host.bus &&
            dev == vdev->host.dev && func == vdev->host.func) {
            break;
        }
    }

    if (!vdev) {
        return 0;
    }

    switch (cmd) {
    case VFIO_MSG_REMOVE:
        fprintf(stderr, "vfio: Host requests removal of device "
                "%04x:%02x:%02x.%x, sending unplug request to guest.\n",
                seg, bus, dev, func);

        qdev_unplug(&vdev->pdev.qdev);

        /* This isn't an optional request, give the guest some time to release
         * the device.  If it doesn't, we need to trigger a bigger hammer. */
        vdev->remove_timer = qemu_new_timer_ms(rt_clock,
                                               vfio_remove_abort, vdev);
        qemu_mod_timer(vdev->remove_timer,
                       qemu_get_clock_ms(rt_clock) + 30000);
        break;
    /* TODO: Handle errors & suspend/resume */
    }

    return 0;
}

static int vfio_register_netlink(VFIODevice *vdev)
{
    struct nl_msg *msg;

    if (QLIST_EMPTY(&nl_list)) {
        int fd;

        vfio_nl_handle = nl_handle_alloc();
        if (!vfio_nl_handle) {
            error_report("vfio: Failed nl_handle_alloc\n");
            return -1;
        }

        genl_connect(vfio_nl_handle);
        vfio_nl_family = genl_ctrl_resolve(vfio_nl_handle, "VFIO");
        if (vfio_nl_family < 0) {
            error_report("vfio: Failed to resolve netlink channel\n");
            nl_handle_destroy(vfio_nl_handle);
            return -1;
        }
        nl_disable_sequence_check(vfio_nl_handle);
        if (nl_socket_modify_cb(vfio_nl_handle, NL_CB_VALID, NL_CB_CUSTOM,
                                vfio_parse_netlink, NULL)) {
            error_report("vfio: Failed to modify netlink callback\n");
            nl_handle_destroy(vfio_nl_handle);
            return -1;
        }

        fd = nl_socket_get_fd(vfio_nl_handle);
        qemu_set_fd_handler(fd, vfio_netlink_event, NULL, vdev);
    }

    QLIST_INSERT_HEAD(&nl_list, vdev, nl_next);

    msg = nlmsg_alloc();
    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, vfio_nl_family, 0,
                NLM_F_REQUEST, VFIO_MSG_REGISTER, 1);
    nla_put_u64(msg, VFIO_ATTR_MSGCAP, 1ULL << VFIO_MSG_REMOVE);
    nla_put_u16(msg, VFIO_ATTR_PCI_DOMAIN, vdev->host.seg);
    nla_put_u8(msg, VFIO_ATTR_PCI_BUS, vdev->host.bus);
    nla_put_u8(msg, VFIO_ATTR_PCI_SLOT, vdev->host.dev);
    nla_put_u8(msg, VFIO_ATTR_PCI_FUNC, vdev->host.func);
    nl_send_auto_complete(vfio_nl_handle, msg);
    nlmsg_free(msg);

    return 0;
}

static void vfio_unregister_netlink(VFIODevice *vdev)
{
    if (qemu_timer_pending(vdev->remove_timer)) {
        qemu_del_timer(vdev->remove_timer);
        qemu_free_timer(vdev->remove_timer);
    }

    QLIST_REMOVE(vdev, nl_next);

    if (QLIST_EMPTY(&nl_list)) {
        int fd;

        fd = nl_socket_get_fd(vfio_nl_handle);
        qemu_set_fd_handler(fd, NULL, NULL, NULL);
        nl_handle_destroy(vfio_nl_handle);
    }
}
#endif

/*
 * General setup
 */
static int vfio_load_rom(VFIODevice *vdev)
{
    uint64_t size = vdev->rom_size;
    const VMStateDescription *vmsd;
    char name[32];
    off_t off = 0, voff = vdev->rom_offset;
    ssize_t bytes;
    void *ptr;

    /* If loading ROM from file, pci handles it */
    if (vdev->pdev.romfile || !vdev->pdev.rom_bar || !size)
        return 0;

    DPRINTF("%s(%04x:%02x:%02x.%x)\n", __FUNCTION__,
            vdev->host.seg, vdev->host.bus, vdev->host.dev, vdev->host.func);

    vmsd = qdev_get_vmsd(DEVICE(&vdev->pdev));

    if (vmsd) {
        snprintf(name, sizeof(name), "%s.rom", vmsd->name);
    } else {
        snprintf(name, sizeof(name), "%s.rom",
                 object_get_typename(OBJECT(&vdev->pdev)));
    }
    memory_region_init_ram(&vdev->pdev.rom, name, size);
    ptr = memory_region_get_ram_ptr(&vdev->pdev.rom);
    memset(ptr, 0xff, size);

    while (size) {
        bytes = pread(vdev->fd, ptr + off, size, voff + off);
        if (bytes == 0) {
            break; /* expect that we could get back less than the ROM BAR */
        } else if (bytes > 0) {
            off += bytes;
            size -= bytes;
        } else {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            fprintf(stderr, "vfio: Error reading device ROM: %s\n",
                    strerror(errno));
            memory_region_destroy(&vdev->pdev.rom);
            return -1;
        }
    }

    pci_register_bar(&vdev->pdev, PCI_ROM_SLOT, 0, &vdev->pdev.rom);
    vdev->pdev.has_rom = true;
    return 0;
}

static int vfio_connect_container(VFIOGroup *group, bool prefer_shared)
{
    VFIOContainer *container;
    int ret, fd;

    if (group->container) {
        return 0;
    }

    if (prefer_shared) {
        QLIST_FOREACH(container, &container_list, next) {
            if (!ioctl(group->fd, VFIO_GROUP_SET_CONTAINER, &container->fd)) {
                group->container = container;
                QLIST_INSERT_HEAD(&container->group_list, group,
                                  container_next);
                return 0;
            }
        }
    }

    fd = open("/dev/vfio/vfio", O_RDWR);
    if (fd < 0) {
        error_report("vfio: failed to open /dev/vfio/vfio: %s\n",
                     strerror(errno));
        return -1;
    }

    ret = ioctl(fd, VFIO_GET_API_VERSION);
    if (ret != VFIO_API_VERSION) {
        error_report("vfio: supported vfio version: %d, "
                     "reported version: %d\n", VFIO_API_VERSION, ret);
        close(fd);
        return -1;
    }

    container = g_malloc0(sizeof(*container));
    container->fd = fd;

    if (ioctl(fd, VFIO_CHECK_EXTENSION, VFIO_X86_IOMMU)) {
        ret = ioctl(group->fd, VFIO_GROUP_SET_CONTAINER, &fd);
        if (ret) {
            error_report("vfio: failed to set group container: %s\n",
                         strerror(errno));
            g_free(container);
            close(fd);
            return -1;
        }

        ret = ioctl(fd, VFIO_SET_IOMMU, VFIO_X86_IOMMU);
        if (ret) {
            error_report("vfio: failed to set iommu for container: %s\n",
                         strerror(errno));
            g_free(container);
            close(fd);
            return -1;
        }

        container->listener = (MemoryListener) {
            .begin = vfio_listener_dummy1,
            .commit = vfio_listener_dummy1,
            .region_add = vfio_listener_region_add,
            .region_del = vfio_listener_region_del,
            .region_nop = vfio_listener_dummy2,
            .log_start = vfio_listener_dummy2,
            .log_stop = vfio_listener_dummy2,
            .log_sync = vfio_listener_dummy2,
            .log_global_start = vfio_listener_dummy1,
            .log_global_stop = vfio_listener_dummy1,
            .eventfd_add = vfio_listener_dummy3,
            .eventfd_del =vfio_listener_dummy3,
        };

        memory_listener_register(&container->listener, get_system_memory());

    } else {
        error_report("vfio: No available IOMMU models\n");
        g_free(container);
        close(fd);
        return -1;
    }

    QLIST_INIT(&container->group_list);
    QLIST_INSERT_HEAD(&container_list, container, next);

    group->container = container;
    QLIST_INSERT_HEAD(&container->group_list, group, container_next);

    return 0;
}

static void vfio_disconnect_container(VFIOGroup *group)
{
    VFIOContainer *container = group->container;

    if (ioctl(group->fd, VFIO_GROUP_UNSET_CONTAINER, &container->fd)) {
        error_report("vfio: error disconnecting group %d from container\n",
                     group->groupid);
    }

    QLIST_REMOVE(group, container_next);
    group->container = NULL;

    if (QLIST_EMPTY(&container->group_list)) {
        if (container->listener.begin) {
            memory_listener_unregister(&container->listener);
        }
        QLIST_REMOVE(container, next);
        DPRINTF("vfio_disconnect_container: close container->fd\n");
        close(container->fd);
        g_free(container);
    }
}

static VFIOGroup *vfio_get_group(int groupid)
{
    VFIOGroup *group;
    char path[32];
    struct vfio_group_status status = { .argsz = sizeof(status) };

    QLIST_FOREACH(group, &group_list, next) {
        if (group->groupid == groupid) {
            return group;
        }
    }

    group = g_malloc0(sizeof(*group));

    sprintf(path, "/dev/vfio/%d", groupid);
    group->fd = open(path, O_RDWR);
    if (group->fd < 0) {
        error_report("vfio: error opening %s: %s", path, strerror(errno));
        g_free(group);
        return NULL;
    }

    if (ioctl(group->fd, VFIO_GROUP_GET_STATUS, &status)) {
        error_report("vfio: error getting group status: %s\n",
                     strerror(errno));
        close(group->fd);
        g_free(group);
        return NULL;
    }

    if (!(status.flags & VFIO_GROUP_FLAGS_VIABLE)) {
        error_report("vfio: error, group %d is not viable, please ensure "
                     "all devices within the iommu_group are bound to their "
                     "vfio bus driver.\n", groupid);
        close(group->fd);
        g_free(group);
        return NULL;
    }

    group->groupid = groupid;
    QLIST_INIT(&group->device_list);

    if (vfio_connect_container(group, true)) {
        error_report("vfio: failed to setup container for group %d\n", groupid);
        close(group->fd);
        g_free(group);
        return NULL;
    }

    QLIST_INSERT_HEAD(&group_list, group, next);

    return group;
}

static void vfio_put_group(VFIOGroup *group)
{
    if (!QLIST_EMPTY(&group->device_list)) {
        return;
    }

    vfio_disconnect_container(group);
    QLIST_REMOVE(group, next);
    DPRINTF("vfio_put_group: close group->fd\n");
    close(group->fd);
    g_free(group);
}

static int __vfio_get_device(VFIOGroup *group,
                             const char *name, VFIODevice *vdev)
{
    int ret;

    ret = ioctl(group->fd, VFIO_GROUP_GET_DEVICE_FD, name);
    if (ret < 0) {
        error_report("vfio: error getting device %s from group %d: %s",
                     name, group->groupid, strerror(errno));
        error_report("Verify all devices in group %d "
                     "are bound to the vfio driver and not already in use",
                     group->groupid);
        return -1;
    }

    vdev->group = group;
    QLIST_INSERT_HEAD(&group->device_list, vdev, next);

    vdev->fd = ret;

    return 0;
}

static int vfio_get_device(VFIOGroup *group, const char *name, VFIODevice *vdev)
{
    struct vfio_device_info dev_info = { .argsz = sizeof(dev_info) };
    struct vfio_region_info reg_info = { .argsz = sizeof(reg_info) };
    int ret, i;

    ret = __vfio_get_device(group, name, vdev);
    if (ret) {
        return ret;
    }

    /* Sanity check device */
    ret = ioctl(vdev->fd, VFIO_DEVICE_GET_INFO, &dev_info);
    if (ret) {
        error_report("vfio: error getting device info: %s", strerror(errno));
        goto error;
    }

    DPRINTF("Device %s flags: %u, regions: %u, irgs: %u\n", name,
            dev_info.flags, dev_info.num_regions, dev_info.num_irqs);

    if (!(dev_info.flags & VFIO_DEVICE_FLAGS_PCI)) {
        error_report("vfio: Um, this isn't a PCI device");
        goto error;
    }

    vdev->reset_works = !!(dev_info.flags & VFIO_DEVICE_FLAGS_RESET);
    if (!vdev->reset_works) {
        fprintf(stderr, "Warning, device %s does not support reset\n", name);
    }

    if (dev_info.num_regions != VFIO_PCI_NUM_REGIONS) {
        error_report("vfio: unexpected number of io regions %u",
                     dev_info.num_regions);
        goto error;
    }

    if (dev_info.num_irqs != VFIO_PCI_NUM_IRQS) {
        error_report("vfio: unexpected number of irqs %u", dev_info.num_irqs);
        goto error;
    }

    for (i = VFIO_PCI_BAR0_REGION_INDEX; i < VFIO_PCI_ROM_REGION_INDEX; i++) {
        reg_info.index = i;

        ret = ioctl(vdev->fd, VFIO_DEVICE_GET_REGION_INFO, &reg_info);
        if (ret) {
            error_report("vfio: Error getting region %d info: %s", i,
                         strerror(errno));
            goto error;
        }

        DPRINTF("Device %s region %d:\n", name, i);
        DPRINTF("  size: 0x%lx, offset: 0x%lx, flags: 0x%lx\n",
                (unsigned long)reg_info.size, (unsigned long)reg_info.offset,
                (unsigned long)reg_info.flags);

        vdev->resources[i].size = reg_info.size;
        vdev->resources[i].offset = reg_info.offset;
    }

    reg_info.index = VFIO_PCI_ROM_REGION_INDEX;

    ret = ioctl(vdev->fd, VFIO_DEVICE_GET_REGION_INFO, &reg_info);
    if (ret) {
        error_report("vfio: Error getting ROM info: %s",
                     strerror(errno));
        goto error;
    }

    DPRINTF("Device %s ROM:\n", name);
    DPRINTF("  size: 0x%lx, offset: 0x%lx, flags: 0x%lx\n",
            (unsigned long)reg_info.size, (unsigned long)reg_info.offset,
            (unsigned long)reg_info.flags);

    vdev->rom_size = reg_info.size;
    vdev->rom_offset = reg_info.offset;

    reg_info.index = VFIO_PCI_CONFIG_REGION_INDEX;

    ret = ioctl(vdev->fd, VFIO_DEVICE_GET_REGION_INFO, &reg_info);
    if (ret) {
        error_report("vfio: Error getting config info: %s",
                     strerror(errno));
        goto error;
    }

    DPRINTF("Device %s config:\n", name);
    DPRINTF("  size: 0x%lx, offset: 0x%lx, flags: 0x%lx\n",
            (unsigned long)reg_info.size, (unsigned long)reg_info.offset,
            (unsigned long)reg_info.flags);

    vdev->config_size = reg_info.size;
    vdev->config_offset = reg_info.offset;

error:
    if (ret) {
        QLIST_REMOVE(vdev, next);
        vdev->group = NULL;
        close(vdev->fd);
    }
    return ret;
}

static void vfio_put_device(VFIODevice *vdev)
{
    QLIST_REMOVE(vdev, next);
    vdev->group = NULL;
    DPRINTF("vfio_put_device: close vdev->fd\n");
    close(vdev->fd);
}

static int vfio_initfn(struct PCIDevice *pdev)
{
    VFIODevice *pvdev, *vdev = DO_UPCAST(VFIODevice, pdev, pdev);
    VFIOGroup *group;
    char path[PATH_MAX], iommu_group_path[PATH_MAX], *group_name;
    ssize_t len;
    struct stat st;
    int groupid;
    int ret;

    sprintf(pdev->name, "vfio-%04x:%02x:%02x.%01x",
            vdev->host.seg, vdev->host.bus, vdev->host.dev, vdev->host.func);

    /* Check that the host device exists */
    sprintf(path, "/sys/bus/pci/devices/%04x:%02x:%02x.%01x/",
            vdev->host.seg, vdev->host.bus, vdev->host.dev, vdev->host.func);
    if (stat(path, &st) < 0) {
        error_report("vfio: error: no such host device: %s", path);
        return -1;
    }

    strcat(path, "iommu_group");

    len = readlink(path, iommu_group_path, PATH_MAX);
    if (len <= 0) {
        error_report("vfio: error no iommu_group for device\n");
        return -1;
    }

    iommu_group_path[len] = 0;
    group_name = basename(iommu_group_path);

    if (sscanf(group_name, "%d", &groupid) != 1) {
        error_report("vfio: error reading %s: %s", path, strerror(errno));
        return -1;
    }

    DPRINTF("%s(%04x:%02x:%02x.%x) group %d\n", __FUNCTION__, vdev->host.seg,
            vdev->host.bus, vdev->host.dev, vdev->host.func, groupid);

    group = vfio_get_group(groupid);
    if (!group) {
        error_report("vfio: failed to get group %d", groupid);
        return -1;
    }

    sprintf(path, "%04x:%02x:%02x.%01x",
            vdev->host.seg, vdev->host.bus, vdev->host.dev, vdev->host.func);

    QLIST_FOREACH(pvdev, &group->device_list, next) {
        if (pvdev->host.seg == vdev->host.seg &&
            pvdev->host.bus == vdev->host.bus &&
            pvdev->host.dev == vdev->host.dev &&
            pvdev->host.func == vdev->host.func) {

            error_report("vfio: error: device %s is already attached\n", path);
            vfio_put_group(group);
            return -1;
        }
    }

    ret = vfio_get_device(group, path, vdev);
    if (ret) {
        error_report("vfio: failed to get device %s", path);
        vfio_put_group(group);
        return -1;
    }

    /* Get a copy of config space */
    assert(pci_config_size(&vdev->pdev) <= vdev->config_size);
    ret = pread(vdev->fd, vdev->pdev.config,
                pci_config_size(&vdev->pdev), vdev->config_offset);
    if (ret < (int)pci_config_size(&vdev->pdev)) {
        fprintf(stderr, "vfio: Failed to read device config space\n");
        goto out;
    }

    /* Clear host resource mapping info.  If we choose not to register a
     * BAR, such as might be the case with the option ROM, we can get
     * confusing, unwritable, residual addresses from the host here. */
    memset(&vdev->pdev.config[PCI_BASE_ADDRESS_0], 0, 24);
    memset(&vdev->pdev.config[PCI_ROM_ADDRESS], 0, 4);

    vfio_load_rom(vdev);

#if 0
    if (vfio_register_netlink(vdev)) {
        goto out_disable_vfiofd;
    }
#endif

    if (msi_supported && vfio_setup_msi(vdev))
        goto out;

    if (vfio_map_resources(vdev))
        goto out_disable_msi;

    if (vfio_enable_intx(vdev))
        goto out_unmap_resources;

    return 0;

out_unmap_resources:
    vfio_unmap_resources(vdev);
out_disable_msi:
    vfio_teardown_msi(vdev);
#if 0
out_disable_netlink:
    vfio_unregister_netlink(vdev);
#endif
out:
    vfio_put_device(vdev);
    vfio_put_group(group);
    return -1;
}

static int vfio_exitfn(struct PCIDevice *pdev)
{
    VFIODevice *vdev = DO_UPCAST(VFIODevice, pdev, pdev);
    VFIOGroup *group = vdev->group;

    vfio_disable_interrupts(vdev);
    vfio_teardown_msi(vdev);
    vfio_unmap_resources(vdev);
#if 0
    vfio_unregister_netlink(vdev);
#endif
    vfio_put_device(vdev);
    vfio_put_group(group);
    return 0;
}

static void vfio_reset(DeviceState *dev)
{
    PCIDevice *pdev = DO_UPCAST(PCIDevice, qdev, dev);
    VFIODevice *vdev = DO_UPCAST(VFIODevice, pdev, pdev);

    if (!vdev->reset_works) {
        return;
    }

    if (ioctl(vdev->fd, VFIO_DEVICE_RESET)) {
        fprintf(stderr, "vfio: Error unable to reset physical device "
                "(%04x:%02x:%02x.%x): %s\n", vdev->host.seg, vdev->host.bus,
                vdev->host.dev, vdev->host.func, strerror(errno));
    }
}

static PropertyInfo qdev_prop_hostaddr = {
    .name  = "pci-hostaddr",
    .parse = parse_hostaddr,
    .print = print_hostaddr,
};

static Property vfio_pci_dev_properties[] = {
    DEFINE_PROP("host", VFIODevice, host, qdev_prop_hostaddr, PCIHostDevice),
    //TODO - support passed fds
    //DEFINE_PROP_STRING("vfiofd", VFIODevice, vfiofd_name),
    //DEFINE_PROP_STRING("vfiogroupfd, VFIODevice, vfiogroupfd_name),
    DEFINE_PROP_END_OF_LIST(),
};


static void vfio_pci_dev_class_init(ObjectClass *klass, void *data)
{
    PCIDeviceClass *dc = PCI_DEVICE_CLASS(klass);

    dc->parent_class.reset = vfio_reset;
    dc->init = vfio_initfn;
    dc->exit = vfio_exitfn;
    dc->config_read = vfio_pci_read_config;
    dc->config_write = vfio_pci_write_config;
    dc->parent_class.props = vfio_pci_dev_properties;
}

static TypeInfo vfio_pci_dev_info = {
    .name          = "vfio-pci",
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(VFIODevice),
    .class_init    = vfio_pci_dev_class_init,
};

static void register_vfio_pci_dev_type(void)
{
    type_register_static(&vfio_pci_dev_info);
}

type_init(register_vfio_pci_dev_type)
