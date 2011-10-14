/*
 * vfio based device assignment support
 *
 * Copyright Red Hat, Inc. 2011
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

#define DEBUG_VFIO
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
    int intx = VFIO_PCI_INTX_IRQ_INDEX;

    ioctl(vdev->fd, VFIO_DEVICE_UNMASK_IRQ, &intx);
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
    int fd[3] = { VFIO_PCI_INTX_IRQ_INDEX, 1 };
    uint8_t pin = vfio_pci_read_config(&vdev->pdev, PCI_INTERRUPT_PIN, 1);

    if (!pin) {
        return 0;
    }

    vfio_disable_interrupts(vdev);

    vdev->intx.pin = pin - 1; /* Pin A (1) -> irq[0] */
    vdev->intx.irq = pci_get_irq(&vdev->pdev, vdev->intx.pin);
    vdev->intx.eoi.notify = vfio_eoi;
    ioapic_add_gsi_eoi_notifier(&vdev->intx.eoi, vdev->intx.irq);

    vdev->intx.update_irq.notify = vfio_update_irq;
    pci_add_irq_update_notifier(&vdev->pdev, &vdev->intx.update_irq);

    if (event_notifier_init(&vdev->intx.interrupt, 0)) {
        fprintf(stderr, "vfio: Error: event_notifier_init failed\n");
        return -1;
    }

    fd[2] = event_notifier_get_fd(&vdev->intx.interrupt);
    qemu_set_fd_handler(fd[2], vfio_intx_interrupt, NULL, vdev);

    if (ioctl(vdev->fd, VFIO_DEVICE_SET_IRQ_EVENTFDS, fd)) {
        fprintf(stderr, "vfio: Error: Failed to setup INTx fd %s\n",
                strerror(errno));
        return -1;
    }

    vdev->interrupt = INT_INTx;

    vfio_unmask_intx(vdev);

    DPRINTF("%s(%04x:%02x:%02x.%x)\n", __FUNCTION__, vdev->host.seg,
            vdev->host.bus, vdev->host.dev, vdev->host.func);

    return 0;
}

static void vfio_disable_intx(VFIODevice *vdev)
{
    int fd[2] = { VFIO_PCI_INTX_IRQ_INDEX, 0 };

    ioctl(vdev->fd, VFIO_DEVICE_SET_IRQ_EVENTFDS, fd);

    pci_remove_irq_update_notifier(&vdev->pdev, &vdev->intx.update_irq);
    ioapic_remove_gsi_eoi_notifier(&vdev->intx.eoi, vdev->intx.irq);

    fd[0] = event_notifier_get_fd(&vdev->intx.interrupt);
    qemu_set_fd_handler(fd[0], NULL, NULL, vdev);
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
    int i, *fds;

    vfio_disable_interrupts(vdev);

    vdev->nr_vectors = msix ? vdev->pdev.msix_entries_nr :
                              msi_nr_vectors_allocated(&vdev->pdev);
    vdev->msi_vectors = g_malloc(vdev->nr_vectors * sizeof(MSIVector));

    fds = g_malloc((vdev->nr_vectors + 2) * sizeof(int));
    fds[0] = msix ? VFIO_PCI_MSIX_IRQ_INDEX : VFIO_PCI_MSI_IRQ_INDEX;
    fds[1] = vdev->nr_vectors;

    for (i = 0; i < vdev->nr_vectors; i++) {
        vdev->msi_vectors[i].vdev = vdev;
        vdev->msi_vectors[i].vector = i;

        if (event_notifier_init(&vdev->msi_vectors[i].interrupt, 0)) {
            fprintf(stderr, "vfio: Error: event_notifier_init failed\n");
        }

        fds[i + 2] = event_notifier_get_fd(&vdev->msi_vectors[i].interrupt);
        qemu_set_fd_handler(fds[i + 2], vfio_msi_interrupt, NULL,
                            &vdev->msi_vectors[i]);

        if (msix && msix_vector_use(&vdev->pdev, i) < 0) {
            fprintf(stderr, "vfio: Error msix_vector_use\n");
        }
    }

    if (ioctl(vdev->fd, VFIO_DEVICE_SET_IRQ_EVENTFDS, fds)) {
        fprintf(stderr, "vfio: Error: Failed to setup MSI/X fds %s\n",
                strerror(errno));
        for (i = 0; i < vdev->nr_vectors; i++) {
            if (msix) {
                msix_vector_unuse(&vdev->pdev, i);
            }
            qemu_set_fd_handler(fds[i + 1], NULL, NULL, NULL);
            event_notifier_cleanup(&vdev->msi_vectors[i].interrupt);
        }
        g_free(fds);
        g_free(vdev->msi_vectors);
        vdev->nr_vectors = 0;
        return;
    }

    vdev->interrupt = msix ? INT_MSIX : INT_MSI;

    g_free(fds);

    DPRINTF("%s(%04x:%02x:%02x.%x) Enabled %d vectors\n", __FUNCTION__,
            vdev->host.seg, vdev->host.bus, vdev->host.dev,
            vdev->host.func, vdev->nr_vectors);
}

static void vfio_disable_msi(VFIODevice *vdev, bool msix)
{
    int fds[2] = { msix ? VFIO_PCI_MSIX_IRQ_INDEX : VFIO_PCI_MSI_IRQ_INDEX, 0 };
    int i;

    ioctl(vdev->fd, VFIO_DEVICE_SET_IRQ_EVENTFDS, &fds);

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

    if (pwrite(res->fd, &data, size, res->offset + addr) != size) {
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
    uint64_t data = 0;

    if (pread(res->fd, &data, size, res->offset + addr) != size) {
        fprintf(stderr, "%s(,0x%"PRIx64", %d) failed: %s\n",
                __FUNCTION__, addr, size, strerror(errno));
        return (uint64_t)-1;
    }

    DPRINTF("%s(BAR%d+0x%"PRIx64", %d) = 0x%"PRIx64"\n",
            __FUNCTION__, res->bar, addr, size, data);

    return data;
}

static const MemoryRegionOps vfio_resource_ops = {
    .read = vfio_resource_read,
    .write = vfio_resource_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
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
    }
    DPRINTF("%s(%04x:%02x:%02x.%x, 0x%x, 0x%x) %x\n", __FUNCTION__,
            vdev->host.seg, vdev->host.bus, vdev->host.dev,
            vdev->host.func, addr, len, val);
    return val;
}

static void vfio_pci_write_config(PCIDevice *pdev, uint32_t addr,
                                  uint32_t val, int len)
{
    VFIODevice *vdev = DO_UPCAST(VFIODevice, pdev, pdev);

    DPRINTF("%s(%04x:%02x:%02x.%x, 0x%x, 0x%x, 0x%x)\n", __FUNCTION__,
            vdev->host.seg, vdev->host.bus, vdev->host.dev,
            vdev->host.func, addr, val, len);

    /* Write everything to VFIO, let it filter out what we can't write */
    if (pwrite(vdev->fd, &val, len, vdev->config_offset + addr) != len) {
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
static int vfio_dma_map(VFIOIOMMU *iommu, target_phys_addr_t start_addr,
                        ram_addr_t size, ram_addr_t phys_offset)
{
    struct vfio_dma_map dma_map;

    dma_map.vaddr = (uintptr_t)qemu_get_ram_ptr(phys_offset);
    dma_map.dmaaddr = start_addr;
    dma_map.flags = VFIO_DMA_MAP_FLAG_WRITE;
    dma_map.size = size;

    if (ioctl(iommu->fd, VFIO_IOMMU_MAP_DMA, &dma_map)) {
        DPRINTF("VFIO_MAP_DMA: %d\n", errno);
        return -errno;
    }

    return 0;
}

static int vfio_dma_unmap(VFIOIOMMU *iommu, target_phys_addr_t start_addr,
                          ram_addr_t size, ram_addr_t phys_offset)
{
    struct vfio_dma_map dma_map;

    dma_map.vaddr = (uintptr_t)qemu_get_ram_ptr(phys_offset);
    dma_map.dmaaddr = start_addr;
    dma_map.flags = VFIO_DMA_MAP_FLAG_WRITE;
    dma_map.size = size;

    if (ioctl(iommu->fd, VFIO_IOMMU_UNMAP_DMA, &dma_map)) {
        DPRINTF("VFIO_UNMAP_DMA: %d\n", errno);
        return -errno;
    }

    return 0;
}

static void vfio_client_set_memory(struct CPUPhysMemoryClient *client,
                                   target_phys_addr_t start_addr,
                                   ram_addr_t size, ram_addr_t phys_offset,
                                   bool log_dirty)
{
    VFIOIOMMU *iommu = container_of(client, VFIOIOMMU, client);
    ram_addr_t flags = phys_offset & ~TARGET_PAGE_MASK;
    int ret;

    if ((start_addr | size) & ~TARGET_PAGE_MASK) {
        return;
    }

    if (flags == IO_MEM_RAM) {
        ret = vfio_dma_map(iommu, start_addr, size, phys_offset);
        if (!ret) {
            return;
        }

        if (ret == -EBUSY) {
            /* EBUSY means the target address is already set.  Check if the
             * current mapping has changed.  If it hasn't, do nothing.  If it
             * has, unmap and remap the new phys_offset for each page.  On x86
             * this typically only happens for remapping of areas below 1MB. */
            target_phys_addr_t curr = start_addr;
            target_phys_addr_t end = start_addr + size;
            ram_addr_t curr_phys = phys_offset;

            while (curr < end) {
                ram_addr_t phys = cpu_get_physical_page_desc(curr);

                if (phys != curr_phys) {
                    vfio_dma_unmap(iommu, curr, TARGET_PAGE_SIZE, phys);
                    ret = vfio_dma_map(iommu, curr,
                                       TARGET_PAGE_SIZE, curr_phys);
                    if (ret) {
                        break;
                    }
                }
                curr += TARGET_PAGE_SIZE;
                curr_phys += TARGET_PAGE_SIZE;
            }

            if (curr >= end) {
                return;
            }
        }

        vfio_dma_unmap(iommu, start_addr, size, phys_offset);

        fprintf(stderr, "%s: "
                "Failed to map region %llx - %llx: %s\n", __FUNCTION__,
                (unsigned long long)start_addr,
                (unsigned long long)(start_addr + size - 1),
                strerror(-ret));

    } else if (flags == IO_MEM_UNASSIGNED) {
        ret = vfio_dma_unmap(iommu, start_addr, size, phys_offset);
        if (!ret) {
            return;
        }
        fprintf(stderr, "%s: "
                "Failed to unmap region %llx - %llx: %s\n", __FUNCTION__,
                (unsigned long long)start_addr,
                (unsigned long long)(start_addr + size - 1),
                strerror(-ret));
    }
}

static int vfio_client_sync_dirty_bitmap(struct CPUPhysMemoryClient *client,
                                         target_phys_addr_t start_addr,
                                         target_phys_addr_t end_addr)
{
    return 0;
}

static int vfio_client_migration_log(struct CPUPhysMemoryClient *client,
                                     int enable)
{
    return 0;
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

        vdev->msix = true;
        vdev->msix_bar = table & PCI_MSIX_BIR;
        vdev->msix_entries = (ctrl & PCI_MSIX_TABSIZE) + 1;

        DPRINTF("%04x:%02x:%02x.%x PCI MSI-X CAP @0x%x, BAR %d, offset 0x%x\n",
                vdev->host.seg, vdev->host.bus, vdev->host.dev,
                vdev->host.func, pos, vdev->msix_bar, table & ~PCI_MSIX_BIR);
    }
    return 0;
}

static void vfio_teardown_msi(VFIODevice *vdev)
{
    msi_uninit(&vdev->pdev);
    msix_uninit(&vdev->pdev, &vdev->resources[vdev->msix_bar].region);
}

/*
 * Resource setup
 */
static int vfio_map_resources(VFIODevice *vdev)
{
    int i;

    for (i = 0; i < VFIO_PCI_ROM_REGION_INDEX; i++) {
        PCIResource *res;
        uint32_t bar;
        uint8_t offset;
        int ret, space;
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

        if (vdev->pdev.qdev.info->vmsd) {
            snprintf(name, sizeof(name), "%s.bar%d",
                     vdev->pdev.qdev.info->vmsd->name, i);
        } else {
            snprintf(name, sizeof(name), "%s.bar%d",
                     vdev->pdev.qdev.info->name, i);
        }

        if (space == PCI_BASE_ADDRESS_SPACE_MEMORY) {
            res->mem = true;

            if ((res->size & 0xfff) == 0) {
                /* Page aligned MMIO BARs - direct map */
                res->virtbase = mmap(NULL, res->size, PROT_READ | PROT_WRITE,
                                     MAP_SHARED, vdev->fd, res->offset);

                if (res->virtbase == MAP_FAILED) {
                    fprintf(stderr, "vfio: Failed to mmap BAR %d (%s), "
                            "using slow access instead\n", i, strerror(errno));
                    goto slow;
                }

                memory_region_init_ram_ptr(&res->region, &vdev->pdev.qdev,
                                           name, res->size, res->virtbase);
            } else {
                /* Non-page aligned MMIO - slow map */
slow:
                /* Note that we could still mmap and do reads/writes from the
                 * mmap'd region in qemu.  For now we do pread/pwrite to
                 * exercise that path in VFIO. */
                res->slow = true;

                DPRINTF("%s(%04x:%02x:%02x.%x) Using slow mapping for BAR %d\n",
                        __FUNCTION__, vdev->host.seg, vdev->host.bus,
                        vdev->host.dev, vdev->host.func, i);

                memory_region_init_io(&res->region, &vfio_resource_ops,
                                      res, name, res->size);
            }

            if (vdev->msix && vdev->msix_bar == i) {
                if (msix_init(&vdev->pdev, vdev->msix_entries,
                              &res->region, i, res->size) < 0) {
                    memory_region_destroy(&res->region);

                    if (!res->slow) {
                        munmap(res->virtbase, res->size);
                    }

                    fprintf(stderr, "vfio: msix_init failed\n");
                    return -1;
                }
            }

            pci_register_bar(&vdev->pdev, i,
                             bar & PCI_BASE_ADDRESS_MEM_PREFETCH ?
                             PCI_BASE_ADDRESS_MEM_PREFETCH :
                             PCI_BASE_ADDRESS_SPACE_MEMORY,
                             &res->region);

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
            memory_region_destroy(&res->region);

            if (res->mem && !res->slow) {
                munmap(res->virtbase, res->size);
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
    char name[32];
    off_t off = 0, voff = vdev->rom_offset;
    ssize_t bytes;
    void *ptr;

    /* If loading ROM from file, pci handles it */
    if (vdev->pdev.romfile || !vdev->pdev.rom_bar || !size)
        return 0;

    DPRINTF("%s(%04x:%02x:%02x.%x)\n", __FUNCTION__,
            vdev->host.seg, vdev->host.bus, vdev->host.dev, vdev->host.func);

    snprintf(name, sizeof(name), "%s.rom", vdev->pdev.qdev.info->name);
    memory_region_init_ram(&vdev->pdev.rom, &vdev->pdev.qdev, name, size);
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

static QLIST_HEAD(, VFIOGroup)
    group_list = QLIST_HEAD_INITIALIZER(group_list);

static VFIOGroup *vfio_get_group(unsigned int groupid)
{
    VFIOGroup *group;

    QLIST_FOREACH(group, &group_list, group_next) {
        if (group->groupid == groupid) {
            break;
        }
    }

    if (!group) {
        char path[32];

        group = g_malloc0(sizeof(*group));

        sprintf(path, "/dev/vfio/%u", groupid);
        group->fd = open(path, O_RDWR);
        if (group->fd < 0) {
            error_report("vfio: error opening %s: %s", path, strerror(errno));
            g_free(group);
            return NULL;
        }

        group->groupid = groupid;
        QLIST_INSERT_HEAD(&group_list, group, group_next);
        QLIST_INIT(&group->device_list);
    }

    return group;
}

static void vfio_put_group(VFIOGroup *group)
{
    if (QLIST_EMPTY(&group->device_list)) {
        QLIST_REMOVE(group, group_next);
        close(group->fd);
        g_free(group);
    }
}

static int __vfio_get_device(VFIOGroup *group,
                             const char *name, VFIODevice *vdev)
{
    int ret;

    ret = ioctl(group->fd, VFIO_GROUP_GET_DEVICE_FD, name);
    if (ret < 0) {
        error_report("vfio: error getting device %s from group %u: %s",
                     name, group->groupid, strerror(errno));
        error_report("Verify all devices in group %u "
                     "are bound to the vfio driver and not already in use",
                     group->groupid);
        return -1;
    }

    vdev->group = group;
    QLIST_INSERT_HEAD(&group->device_list, vdev, group_next);

    vdev->fd = ret;

    return 0;
}

static int vfio_get_device(VFIOGroup *group, const char *name, VFIODevice *vdev)
{
    int ret, num_regions, num_irqs, i;
    uint64_t device_flags;
    struct vfio_region_info info;

    ret = __vfio_get_device(group, name, vdev);
    if (ret) {
        return ret;
    }

    /* Sanity check device */
    ret = ioctl(vdev->fd, VFIO_DEVICE_GET_FLAGS, &device_flags);
    if (ret) {
        error_report("vfio: error getting device flags: %s", strerror(errno));
        goto error;
    }

    DPRINTF("Device %s flags: %lx\n", name, device_flags);

    if (!(device_flags & VFIO_DEVICE_FLAGS_PCI)) {
        error_report("vfio: Um, this isn't a PCI device");
        goto error;
    }

    vdev->reset_works = !!(device_flags & VFIO_DEVICE_FLAGS_RESET);
    if (!vdev->reset_works) {
        fprintf(stderr, "Warning, device %s does not support reset\n", name);
    }

    ret = ioctl(vdev->fd, VFIO_DEVICE_GET_NUM_REGIONS, &num_regions);
    if (ret || num_regions < VFIO_PCI_NUM_REGIONS) {
        if (ret) {
            error_report("vfio: error getting number of io regions: %s",
                         strerror(errno));
        } else {
            error_report("vfio: unexpected number of io regions %d",
                         num_regions);
        }
        goto error;
    }

    ret = ioctl(vdev->fd, VFIO_DEVICE_GET_NUM_IRQS, &num_irqs);
    if (ret || num_irqs < VFIO_PCI_NUM_IRQS) {
        if (ret) {
            error_report("vfio: error getting number of irqs: %s",
                         strerror(errno));
        } else {
            error_report("vfio: unexpected number of irqs %d", num_irqs);
        }
        goto error;
    }

    for (i = VFIO_PCI_BAR0_REGION_INDEX; i < VFIO_PCI_ROM_REGION_INDEX; i++) {

        info.len = sizeof(info);
        info.index = i;

        ret = ioctl(vdev->fd, VFIO_DEVICE_GET_REGION_INFO, &info);
        if (ret) {
            error_report("vfio: Error getting region %d info: %s", i,
                         strerror(errno));
            goto error;
        }

        DPRINTF("Device %s region %d:\n", name, i);
        DPRINTF("  size: 0x%lx, offset: 0x%lx, flags: 0x%lx\n",
                (unsigned long)info.size, (unsigned long)info.offset,
                (unsigned long)info.flags);

        vdev->resources[i].size = info.size;
        vdev->resources[i].offset = info.offset;
    }

    info.len = sizeof(info);
    info.index = VFIO_PCI_ROM_REGION_INDEX;

    ret = ioctl(vdev->fd, VFIO_DEVICE_GET_REGION_INFO, &info);
    if (ret) {
        error_report("vfio: Error getting ROM info: %s",
                     strerror(errno));
        goto error;
    }

    DPRINTF("Device %s ROM:\n", name);
    DPRINTF("  size: 0x%lx, offset: 0x%lx, flags: 0x%lx\n",
            (unsigned long)info.size, (unsigned long)info.offset,
            (unsigned long)info.flags);

    vdev->rom_size = info.size;
    vdev->rom_offset = info.offset;

    info.len = sizeof(info);
    info.index = VFIO_PCI_CONFIG_REGION_INDEX;

    ret = ioctl(vdev->fd, VFIO_DEVICE_GET_REGION_INFO, &info);
    if (ret) {
        error_report("vfio: Error getting config info: %s",
                     strerror(errno));
        goto error;
    }

    DPRINTF("Device %s config:\n", name);
    DPRINTF("  size: 0x%lx, offset: 0x%lx, flags: 0x%lx\n",
            (unsigned long)info.size, (unsigned long)info.offset,
            (unsigned long)info.flags);

    vdev->config_size = info.size;
    vdev->config_offset = info.offset;

error:
    if (ret) {
        QLIST_REMOVE(vdev, group_next);
        vdev->group = NULL;
        close(vdev->fd);
    }
    return ret;
}

static void vfio_put_device(VFIODevice *vdev)
{
    QLIST_REMOVE(vdev, group_next);
    vdev->group = NULL;
    close(vdev->fd);
}

static int vfio_get_iommu(VFIOGroup *group)
{
    group->iommu = g_malloc0(sizeof(*(group->iommu)));
    group->iommu->fd = ioctl(group->fd, VFIO_GROUP_GET_IOMMU_FD);
    if (group->iommu->fd < 0) {
        error_report("vfio: error getting iommu from group %u: %s",
                     group->groupid, strerror(errno));
            return -1;
    }
    QLIST_INIT(&group->iommu->group_list);
    QLIST_INSERT_HEAD(&group->iommu->group_list, group, iommu_next);

    group->iommu->client.set_memory = vfio_client_set_memory;
    group->iommu->client.sync_dirty_bitmap = vfio_client_sync_dirty_bitmap;
    group->iommu->client.migration_log = vfio_client_migration_log;
    DPRINTF("%s() Registering phys memory client\n", __FUNCTION__);
    cpu_register_phys_memory_client(&group->iommu->client);

    return 0;
}

static void vfio_put_iommu(VFIOGroup *group)
{
    QLIST_REMOVE(group, iommu_next);
    if (QLIST_EMPTY(&group->iommu->group_list)) {
        cpu_unregister_phys_memory_client(&group->iommu->client);
        close(group->iommu->fd);
    }
    group->iommu = NULL;
}

static int vfio_initfn(struct PCIDevice *pdev)
{
    VFIODevice *vdev = DO_UPCAST(VFIODevice, pdev, pdev);
    VFIOGroup *group, *mgroup;
    char path[64];
    struct stat st;
    FILE *iommu_group;
    unsigned int groupid;
    int ret;

    /* Check that the host device exists */
    sprintf(path, "/sys/bus/pci/devices/%04x:%02x:%02x.%01x/",
            vdev->host.seg, vdev->host.bus, vdev->host.dev, vdev->host.func);
    if (stat(path, &st) < 0) {
        error_report("vfio: error: no such host device: %s", path);
        return -1;
    }

    strcat(path, "iommu_group");
    iommu_group = fopen(path, "r");
    if (!iommu_group) {
        error_report("vfio: error opening %s: %s", path, strerror(errno));
        return -1;
    }

    if (fscanf(iommu_group, "%u", &groupid) != 1) {
        error_report("vfio: error reading %s: %s", path, strerror(errno));
        return -1;
    }

    DPRINTF("%s(%04x:%02x:%02x.%x) group %u\n", __FUNCTION__, vdev->host.seg,
            vdev->host.bus, vdev->host.dev, vdev->host.func, groupid);

    fclose(iommu_group);

    group = vfio_get_group(groupid);
    if (!group) {
        error_report("vfio: failed to get group %u", groupid);
        return -1;
    }

    sprintf(path, "%04x:%02x:%02x.%01x",
            vdev->host.seg, vdev->host.bus, vdev->host.dev, vdev->host.func);

    ret = vfio_get_device(group, path, vdev);
    if (ret) {
        error_report("vfio: failed to get device %s", path);
        vfio_put_group(group);
        return -1;
    }

    assert(QLIST_FIRST(&group->device_list) == vdev);

    /* If this is the only device in the group and there are other
     * groups, try to merge. */
    if (!QLIST_NEXT(QLIST_FIRST(&group->device_list), group_next)) {
        vfio_put_device(vdev);

        QLIST_FOREACH(mgroup, &group_list, group_next) {
            if (mgroup == group) {
                continue;
            }

            if (ioctl(mgroup->fd, VFIO_GROUP_MERGE, group->fd) == 0) {
                DPRINTF("%s() merged with group %u\n", __FUNCTION__,
                        mgroup->groupid);
                break;
            }
        }

        ret = __vfio_get_device(group, path, vdev);
        if (ret) {
            error_report("vfio: error re-getting device %s from group %u",
                         path, groupid);
            vfio_put_group(group);
            return -1;
        }

        if (mgroup) {
            group->iommu = mgroup->iommu;
            QLIST_INSERT_HEAD(&group->iommu->group_list, group, iommu_next);
        }
    }

    if (!group->iommu) {
        ret = vfio_get_iommu(group);
        if (ret) {
            vfio_put_device(vdev);
            vfio_put_group(group);
            return -1;
        }
    }

    /* Get a copy of config space */
    assert(pci_config_size(&vdev->pdev) <= vdev->config_size);
    ret = pread(vdev->fd, vdev->pdev.config,
                pci_config_size(&vdev->pdev), vdev->config_offset);
    if (ret < pci_config_size(&vdev->pdev)) {
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

    if (vfio_setup_msi(vdev))
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
    vfio_put_iommu(group);
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
    vfio_put_iommu(group);
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
    .type  = -1,
    .size  = sizeof(PCIHostDevice),
    .parse = parse_hostaddr,
    .print = print_hostaddr,
};

static PCIDeviceInfo vfio_info = {
    .qdev.name    = "vfio-pci",
    .qdev.desc    = "pass through host pci devices to the guest via vfio",
    .qdev.size    = sizeof(VFIODevice),
    .qdev.reset   = vfio_reset,
    .init         = vfio_initfn,
    .exit         = vfio_exitfn,
    .config_read  = vfio_pci_read_config,
    .config_write = vfio_pci_write_config,
    .qdev.props   = (Property[]) {
        DEFINE_PROP("host", VFIODevice, host,
                    qdev_prop_hostaddr, PCIHostDevice),
        //DEFINE_PROP_STRING("vfiofd", VFIODevice, vfiofd_name),
        DEFINE_PROP_END_OF_LIST(),
    },
};

static void vfio_register_devices(void)
{
    pci_qdev_register(&vfio_info);
}

device_init(vfio_register_devices)
