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
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/vfio.h>

#include "config.h"
#include "event_notifier.h"
#include "exec-memory.h"
#include "kvm.h"
#include "memory.h"
#include "msi.h"
#include "msix.h"
#include "qemu-error.h"
#include "range.h"
#include "vfio_pci.h"

/* #define DEBUG_VFIO */
#ifdef DEBUG_VFIO
#define DPRINTF(fmt, ...) \
    do { fprintf(stderr, "vfio: " fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

#define MSIX_CAP_LENGTH 12

static QLIST_HEAD(, VFIOContainer)
    container_list = QLIST_HEAD_INITIALIZER(container_list);

static QLIST_HEAD(, VFIOGroup)
    group_list = QLIST_HEAD_INITIALIZER(group_list);

static void vfio_disable_interrupts(VFIODevice *vdev);
static uint32_t vfio_pci_read_config(PCIDevice *pdev, uint32_t addr, int len);

/*
 * Common VFIO interrupt disable
 */
static void vfio_disable_irqindex(VFIODevice *vdev, int index)
{
    struct vfio_irq_set irq_set = {
        .argsz = sizeof(irq_set),
        .flags = VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_TRIGGER,
        .index = index,
        .start = 0,
        .count = 0,
    };

    ioctl(vdev->fd, VFIO_DEVICE_SET_IRQS, &irq_set);

    vdev->interrupt = INT_NONE;
}

/*
 * INTx
 */
static void vfio_unmask_intx(VFIODevice *vdev)
{
    struct vfio_irq_set irq_set = {
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

    DPRINTF("%s(%04x:%02x:%02x.%x) Pin %c\n", __func__, vdev->host.domain,
            vdev->host.bus, vdev->host.slot, vdev->host.function,
            'A' + vdev->intx.pin);

    vdev->intx.pending = true;
    qemu_set_irq(vdev->pdev.irq[vdev->intx.pin], 1);
}

static void vfio_eoi(VFIODevice *vdev)
{
    if (!vdev->intx.pending) {
        return;
    }

    DPRINTF("%s(%04x:%02x:%02x.%x) EOI\n", __func__, vdev->host.domain,
            vdev->host.bus, vdev->host.slot, vdev->host.function);

    vdev->intx.pending = false;
    qemu_set_irq(vdev->pdev.irq[vdev->intx.pin], 0);
    vfio_unmask_intx(vdev);
}

struct vfio_irq_set_fd {
    struct vfio_irq_set irq_set;
    int32_t fd;
} QEMU_PACKED;

static void vfio_enable_intx_kvm(VFIODevice *vdev)
{
#ifdef CONFIG_KVM
    /*
     * VFIO supports an eventfd for INTx notification and an irqfd-like
     * mechanism for unmasking INTx.  If we could get a level irqfd in
     * KVM and an eventfd triggered on EOI from guest, we could interlock
     * these and avoid userspace for INTx.  Work in progress.
     */
#endif
}

static void vfio_disable_intx_kvm(VFIODevice *vdev)
{
#ifdef CONFIG_KVM
    /* Same. */
#endif
}

static void vfio_update_irq(PCIDevice *pdev)
{
    VFIODevice *vdev = DO_UPCAST(VFIODevice, pdev, pdev);
    PCIINTxRoute route;

    if (vdev->interrupt != INT_INTx) {
        return;
    }

    route = pci_device_route_intx_to_irq(&vdev->pdev, vdev->intx.pin);
    if (!memcmp(&route, &vdev->intx.route, sizeof(route))) {
        return; /* Nothing changed */
    }

    DPRINTF("%s(%04x:%02x:%02x.%x) IRQ moved %d -> %d\n", __func__,
            vdev->host.domain, vdev->host.bus, vdev->host.slot,
            vdev->host.function, vdev->intx.route.irq, route.irq);

    vfio_disable_intx_kvm(vdev);
    /* TBD - Disable QEMU eoi notifier */

    vdev->intx.route = route;

    if (route.mode == PCI_INTX_DISABLED) {
        return;
    }

    /* TBD - Enable QEMU eoi notifier */
    vfio_enable_intx_kvm(vdev);

    /* Re-enable the interrupt in cased we missed an EOI */
    vfio_eoi(vdev);
}

static int vfio_enable_intx(VFIODevice *vdev)
{
    struct vfio_irq_set_fd irq_set_fd = {
        .irq_set = {
            .argsz = sizeof(irq_set_fd),
            .flags = VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER,
            .index = VFIO_PCI_INTX_IRQ_INDEX,
            .start = 0,
            .count = 1,
        },
    };
    uint8_t pin = vfio_pci_read_config(&vdev->pdev, PCI_INTERRUPT_PIN, 1);

    if (!pin) {
        return 0;
    }

    vfio_disable_interrupts(vdev);

    vdev->intx.pin = pin - 1; /* Pin A (1) -> irq[0] */
    vdev->intx.route = pci_device_route_intx_to_irq(&vdev->pdev,
                                                    vdev->intx.pin);
    /* TBD - Enable QEMU eoi notifier */

    if (event_notifier_init(&vdev->intx.interrupt, 0)) {
        error_report("vfio: Error: event_notifier_init failed\n");
        return -1;
    }

    irq_set_fd.fd = event_notifier_get_fd(&vdev->intx.interrupt);
    qemu_set_fd_handler(irq_set_fd.fd, vfio_intx_interrupt, NULL, vdev);

    if (ioctl(vdev->fd, VFIO_DEVICE_SET_IRQS, &irq_set_fd)) {
        error_report("vfio: Error: Failed to setup INTx fd: %s\n",
                     strerror(errno));
        return -1;
    }

    vfio_enable_intx_kvm(vdev);

    vdev->interrupt = INT_INTx;

    DPRINTF("%s(%04x:%02x:%02x.%x)\n", __func__, vdev->host.domain,
            vdev->host.bus, vdev->host.slot, vdev->host.function);

    return 0;
}

static void vfio_disable_intx(VFIODevice *vdev)
{
    int fd;

    vfio_disable_intx_kvm(vdev);
    vfio_disable_irqindex(vdev, VFIO_PCI_INTX_IRQ_INDEX);

    /* TBD - Disable QEMU eoi notifier */

    fd = event_notifier_get_fd(&vdev->intx.interrupt);
    qemu_set_fd_handler(fd, NULL, NULL, vdev);
    event_notifier_cleanup(&vdev->intx.interrupt);

    vdev->interrupt = INT_NONE;

    DPRINTF("%s(%04x:%02x:%02x.%x)\n", __func__, vdev->host.domain,
            vdev->host.bus, vdev->host.slot, vdev->host.function);
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

    DPRINTF("%s(%04x:%02x:%02x.%x) vector %d\n", __func__,
            vdev->host.domain, vdev->host.bus, vdev->host.slot,
            vdev->host.function, vec->vector);

    if (vdev->interrupt == INT_MSIX) {
        msix_notify(&vdev->pdev, vec->vector);
    } else if (vdev->interrupt == INT_MSI) {
        msi_notify(&vdev->pdev, vec->vector);
    } else {
        error_report("vfio: MSI interrupt receieved, but not enabled?\n");
    }
}

static int vfio_enable_vectors(VFIODevice *vdev, bool msix)
{
    struct vfio_irq_set *irq_set;
    int ret = 0, i, argsz;
    int32_t *fds;

    argsz = sizeof(*irq_set) + (vdev->nr_vectors * sizeof(*fds));

    irq_set = g_malloc0(argsz);
    irq_set->argsz = argsz;
    irq_set->flags = VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER;
    irq_set->index = msix ? VFIO_PCI_MSIX_IRQ_INDEX : VFIO_PCI_MSI_IRQ_INDEX;
    irq_set->start = 0;
    irq_set->count = vdev->nr_vectors;
    fds = (int32_t *)&irq_set->data;

    for (i = 0; i < vdev->nr_vectors; i++) {
        if (!vdev->msi_vectors[i].use) {
            fds[i] = -1;
            continue;
        }

        fds[i] = event_notifier_get_fd(&vdev->msi_vectors[i].interrupt);
    }

    ret = ioctl(vdev->fd, VFIO_DEVICE_SET_IRQS, irq_set);

    g_free(irq_set);

    if (!ret) {
        vdev->interrupt = msix ? INT_MSIX : INT_MSI;
    }

    return ret;
}

static int vfio_msix_vector_use(PCIDevice *pdev,
                                unsigned int vector, MSIMessage msg)
{
    VFIODevice *vdev = DO_UPCAST(VFIODevice, pdev, pdev);
    int ret, fd;

    DPRINTF("%s(%04x:%02x:%02x.%x) vector %d used\n", __func__,
            vdev->host.domain, vdev->host.bus, vdev->host.slot,
            vdev->host.function, vector);

    if (vdev->interrupt != INT_MSIX) {
        vfio_disable_interrupts(vdev);
    }

    if (!vdev->msi_vectors) {
        vdev->msi_vectors = g_malloc0(vdev->msix->entries * sizeof(MSIVector));
    }

    vdev->msi_vectors[vector].vdev = vdev;
    vdev->msi_vectors[vector].vector = vector;
    vdev->msi_vectors[vector].use = true;

    msix_vector_use(pdev, vector);

    if (event_notifier_init(&vdev->msi_vectors[vector].interrupt, 0)) {
        error_report("vfio: Error: event_notifier_init failed\n");
    }

    fd = event_notifier_get_fd(&vdev->msi_vectors[vector].interrupt);

    /*
     * Attempt to enable route through KVM irqchip,
     * default to userspace handling if unavailable.
     */
    vdev->msi_vectors[vector].virq = kvm_irqchip_add_msi_route(kvm_state, msg);
    if (vdev->msi_vectors[vector].virq < 0 ||
        kvm_irqchip_add_irqfd(kvm_state, fd,
                              vdev->msi_vectors[vector].virq) < 0) {
        qemu_set_fd_handler(fd, vfio_msi_interrupt, NULL,
                            &vdev->msi_vectors[vector]);
    }

    /*
     * We don't want to have the host allocate all possible MSI vectors
     * for a device if they're not in use, so we shutdown and incrementally
     * increase them as needed.
     */
    if (vdev->nr_vectors < vector + 1) {
        int i;

        vfio_disable_irqindex(vdev, VFIO_PCI_MSIX_IRQ_INDEX);
        vdev->nr_vectors = vector + 1;
        ret = vfio_enable_vectors(vdev, true);
        if (ret) {
            error_report("vfio: failed to enable vectors, %d\n", ret);
        }

        /* We don't know if we've missed interrupts in the interim... */
        for (i = 0; i < vdev->msix->entries; i++) {
            if (vdev->msi_vectors[i].use) {
                msix_notify(&vdev->pdev, i);
            }
        }
    } else {
        struct vfio_irq_set_fd irq_set_fd = {
            .irq_set = {
                .argsz = sizeof(irq_set_fd),
                .flags = VFIO_IRQ_SET_DATA_EVENTFD |
                         VFIO_IRQ_SET_ACTION_TRIGGER,
                .index = VFIO_PCI_MSIX_IRQ_INDEX,
                .start = vector,
                .count = 1,
            },
            .fd = fd,
        };
        ret = ioctl(vdev->fd, VFIO_DEVICE_SET_IRQS, &irq_set_fd);
        if (ret) {
            error_report("vfio: failed to modify vector, %d\n", ret);
        }
        msix_notify(&vdev->pdev, vector);
    }

    return 0;
}

static void vfio_msix_vector_release(PCIDevice *pdev, unsigned int vector)
{
    VFIODevice *vdev = DO_UPCAST(VFIODevice, pdev, pdev);
    struct vfio_irq_set_fd irq_set_fd = {
        .irq_set = {
            .argsz = sizeof(irq_set_fd),
            .flags = VFIO_IRQ_SET_DATA_EVENTFD |
                     VFIO_IRQ_SET_ACTION_TRIGGER,
            .index = VFIO_PCI_MSIX_IRQ_INDEX,
            .start = vector,
            .count = 1,
        },
        .fd = -1,
    };
    int fd;

    DPRINTF("%s(%04x:%02x:%02x.%x) vector %d released\n", __func__,
            vdev->host.domain, vdev->host.bus, vdev->host.slot,
            vdev->host.function, vector);

    /*
     * XXX What's the right thing to do here?  This turns off the interrupt
     * completely, but do we really just want to switch the interrupt to
     * bouncing through userspace and let msix.c drop it?  Not sure.
     */
    msix_vector_unuse(pdev, vector);
    ioctl(vdev->fd, VFIO_DEVICE_SET_IRQS, &irq_set_fd);

    fd = event_notifier_get_fd(&vdev->msi_vectors[vector].interrupt);

    if (vdev->msi_vectors[vector].virq < 0) {
        qemu_set_fd_handler(fd, NULL, NULL, NULL);
    } else {
        kvm_irqchip_remove_irqfd(kvm_state, fd, vdev->msi_vectors[vector].virq);
        kvm_irqchip_release_virq(kvm_state, vdev->msi_vectors[vector].virq);
        vdev->msi_vectors[vector].virq = -1;
    }

    event_notifier_cleanup(&vdev->msi_vectors[vector].interrupt);
    vdev->msi_vectors[vector].use = false;
}

/* XXX This should move to msi.c */
static MSIMessage msi_get_msg(PCIDevice *pdev, unsigned int vector)
{
    uint16_t flags = pci_get_word(pdev->config + pdev->msi_cap + PCI_MSI_FLAGS);
    bool msi64bit = flags & PCI_MSI_FLAGS_64BIT;
    MSIMessage msg;

    if (msi64bit) {
        msg.address = pci_get_quad(pdev->config +
                                   pdev->msi_cap + PCI_MSI_ADDRESS_LO);
    } else {
        msg.address = pci_get_long(pdev->config +
                                   pdev->msi_cap + PCI_MSI_ADDRESS_LO);
    }

    msg.data = pci_get_word(pdev->config + pdev->msi_cap +
                            (msi64bit ? PCI_MSI_DATA_64 : PCI_MSI_DATA_32));
    msg.data += vector;

    return msg;
}

/* So should this */
static void msi_set_qsize(PCIDevice *pdev, uint8_t size)
{
    uint8_t *config = pdev->config + pdev->msi_cap;
    uint16_t flags;

    flags = pci_get_word(config + PCI_MSI_FLAGS);
    flags = le16_to_cpu(flags);
    flags &= ~PCI_MSI_FLAGS_QSIZE;
    flags |= (size & 0x7) << 4;
    flags = cpu_to_le16(flags);
    pci_set_word(config + PCI_MSI_FLAGS, flags);
}

static void vfio_enable_msi(VFIODevice *vdev)
{
    int ret, i;

    vfio_disable_interrupts(vdev);

    vdev->nr_vectors = msi_nr_vectors_allocated(&vdev->pdev);
retry:
    vdev->msi_vectors = g_malloc0(vdev->nr_vectors * sizeof(MSIVector));

    for (i = 0; i < vdev->nr_vectors; i++) {
        MSIMessage msg;
        int fd;

        vdev->msi_vectors[i].vdev = vdev;
        vdev->msi_vectors[i].vector = i;
        vdev->msi_vectors[i].use = true;

        if (event_notifier_init(&vdev->msi_vectors[i].interrupt, 0)) {
            error_report("vfio: Error: event_notifier_init failed\n");
        }

        fd = event_notifier_get_fd(&vdev->msi_vectors[i].interrupt);

        msg = msi_get_msg(&vdev->pdev, i);

        /*
         * Attempt to enable route through KVM irqchip,
         * default to userspace handling if unavailable.
         */
        vdev->msi_vectors[i].virq = kvm_irqchip_add_msi_route(kvm_state, msg);
        if (vdev->msi_vectors[i].virq < 0 ||
            kvm_irqchip_add_irqfd(kvm_state, fd,
                                  vdev->msi_vectors[i].virq) < 0) {
            qemu_set_fd_handler(fd, vfio_msi_interrupt, NULL,
                                &vdev->msi_vectors[i]);
        }
    }

    ret = vfio_enable_vectors(vdev, false);
    if (ret) {
        if (ret < 0) {
            error_report("vfio: Error: Failed to setup MSI fds: %s\n",
                         strerror(errno));
        } else if (ret != vdev->nr_vectors) {
            error_report("vfio: Error: Failed to enable %d "
                         "MSI vectors, retry with %d\n", vdev->nr_vectors, ret);
        }

        for (i = 0; i < vdev->nr_vectors; i++) {
            int fd = event_notifier_get_fd(&vdev->msi_vectors[i].interrupt);
            if (vdev->msi_vectors[i].virq >= 0) {
                kvm_irqchip_remove_irqfd(kvm_state, fd,
                                         vdev->msi_vectors[i].virq);
                kvm_irqchip_release_virq(kvm_state, vdev->msi_vectors[i].virq);
                vdev->msi_vectors[i].virq = -1;
            } else {
                qemu_set_fd_handler(fd, NULL, NULL, NULL);
            }
            event_notifier_cleanup(&vdev->msi_vectors[i].interrupt);
        }

        g_free(vdev->msi_vectors);

        if (ret > 0 && ret != vdev->nr_vectors) {
            vdev->nr_vectors = ret;
            goto retry;
        }
        vdev->nr_vectors = 0;

        return;
    }

    msi_set_qsize(&vdev->pdev, vdev->nr_vectors);

    DPRINTF("%s(%04x:%02x:%02x.%x) Enabled %d MSI vectors\n", __func__,
            vdev->host.domain, vdev->host.bus, vdev->host.slot,
            vdev->host.function, vdev->nr_vectors);
}

static void vfio_disable_msi_x(VFIODevice *vdev, bool msix)
{
    int i;

    vfio_disable_irqindex(vdev, msix ? VFIO_PCI_MSIX_IRQ_INDEX :
                                       VFIO_PCI_MSI_IRQ_INDEX);

    for (i = 0; i < vdev->nr_vectors; i++) {
        int fd;

        if (!vdev->msi_vectors[i].use) {
            continue;
        }

        fd = event_notifier_get_fd(&vdev->msi_vectors[i].interrupt);

        if (vdev->msi_vectors[i].virq >= 0) {
            kvm_irqchip_remove_irqfd(kvm_state, fd, vdev->msi_vectors[i].virq);
            kvm_irqchip_release_virq(kvm_state, vdev->msi_vectors[i].virq);
            vdev->msi_vectors[i].virq = -1;
        } else {
            qemu_set_fd_handler(fd, NULL, NULL, NULL);
        }

        if (msix) {
            msix_vector_unuse(&vdev->pdev, i);
        }

        event_notifier_cleanup(&vdev->msi_vectors[i].interrupt);
    }

    g_free(vdev->msi_vectors);
    vdev->msi_vectors = NULL;
    vdev->nr_vectors = 0;

    if (!msix) {
        msi_set_qsize(&vdev->pdev, 0); /* Actually still means 1 vector */
    }

    DPRINTF("%s(%04x:%02x:%02x.%x, msi%s)\n", __func__,
            vdev->host.domain, vdev->host.bus, vdev->host.slot,
            vdev->host.function, msix ? "x" : "");

    vfio_enable_intx(vdev);
}

/*
 * IO Port/MMIO - Beware of the endians, VFIO is always little endian
 */
static void vfio_bar_write(void *opaque, target_phys_addr_t addr,
                           uint64_t data, unsigned size)
{
    VFIOBAR *bar = opaque;
    uint8_t buf[8];

    switch (size) {
    case 1:
        *buf = data & 0xff;
        break;
    case 2:
        *(uint16_t *)buf = cpu_to_le16(data);
        break;
    case 4:
        *(uint32_t *)buf = cpu_to_le32(data);
        break;
    default:
        hw_error("vfio: unsupported write size, %d bytes\n", size);
        break;
    }

    if (pwrite(bar->fd, buf, size, bar->fd_offset + addr) != size) {
        error_report("%s(,0x%"PRIx64", 0x%"PRIx64", %d) failed: %s\n",
                     __func__, addr, data, size, strerror(errno));
    }

    DPRINTF("%s(BAR%d+0x%"PRIx64", 0x%"PRIx64", %d)\n",
            __func__, bar->nr, addr, data, size);
}

static uint64_t vfio_bar_read(void *opaque,
                              target_phys_addr_t addr, unsigned size)
{
    VFIOBAR *bar = opaque;
    uint8_t buf[8];
    uint64_t data = 0;

    if (pread(bar->fd, buf, size, bar->fd_offset + addr) != size) {
        error_report("%s(,0x%"PRIx64", %d) failed: %s\n",
                     __func__, addr, size, strerror(errno));
        return (uint64_t)-1;
    }

    switch (size) {
    case 1:
        data = buf[0];
        break;
    case 2:
        data = le16_to_cpu(*(uint16_t *)buf);
        break;
    case 4:
        data = le32_to_cpu(*(uint32_t *)buf);
        break;
    default:
        hw_error("vfio: unsupported read size, %d bytes\n", size);
        break;
    }

    DPRINTF("%s(BAR%d+0x%"PRIx64", %d) = 0x%"PRIx64"\n",
            __func__, bar->nr, addr, size, data);

    return data;
}

static const MemoryRegionOps vfio_bar_ops = {
    .read = vfio_bar_read,
    .write = vfio_bar_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

/*
 * PCI config space
 */
static uint32_t vfio_pci_read_config(PCIDevice *pdev, uint32_t addr, int len)
{
    VFIODevice *vdev = DO_UPCAST(VFIODevice, pdev, pdev);
    uint32_t val = 0;

    /*
     * We only need QEMU PCI config support for the ROM BAR, the MSI and MSIX
     * capabilities, and the multifunction bit below.  We let VFIO handle
     * virtualizing everything else.  Performance is not a concern here.
     */
    if (ranges_overlap(addr, len, PCI_ROM_ADDRESS, 4) ||
        (pdev->cap_present & QEMU_PCI_CAP_MSIX &&
         ranges_overlap(addr, len, pdev->msix_cap, MSIX_CAP_LENGTH)) ||
        (pdev->cap_present & QEMU_PCI_CAP_MSI &&
         ranges_overlap(addr, len, pdev->msi_cap, vdev->msi_cap_size))) {

        val = pci_default_read_config(pdev, addr, len);
    } else {
        if (pread(vdev->fd, &val, len, vdev->config_offset + addr) != len) {
            error_report("%s(%04x:%02x:%02x.%x, 0x%x, 0x%x) failed: %s\n",
                         __func__, vdev->host.domain, vdev->host.bus,
                         vdev->host.slot, vdev->host.function, addr, len,
                         strerror(errno));
            return -1;
        }
        val = le32_to_cpu(val);
    }

    /* Multifunction bit is virualized in QEMU */
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

    DPRINTF("%s(%04x:%02x:%02x.%x, @0x%x, len=0x%x) %x\n", __func__,
            vdev->host.domain, vdev->host.bus, vdev->host.slot,
            vdev->host.function, addr, len, val);

    return val;
}

static void vfio_pci_write_config(PCIDevice *pdev, uint32_t addr,
                                  uint32_t val, int len)
{
    VFIODevice *vdev = DO_UPCAST(VFIODevice, pdev, pdev);
    uint32_t val_le = cpu_to_le32(val);

    DPRINTF("%s(%04x:%02x:%02x.%x, @0x%x, 0x%x, len=0x%x)\n", __func__,
            vdev->host.domain, vdev->host.bus, vdev->host.slot,
            vdev->host.function, addr, val, len);

    /* Write everything to VFIO, let it filter out what we can't write */
    if (pwrite(vdev->fd, &val_le, len, vdev->config_offset + addr) != len) {
        error_report("%s(%04x:%02x:%02x.%x, 0x%x, 0x%x, 0x%x) failed: %s\n",
                     __func__, vdev->host.domain, vdev->host.bus,
                     vdev->host.slot, vdev->host.function, addr, val, len,
                     strerror(errno));
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

        is_enabled = msi_enabled(pdev);

        if (!was_enabled && is_enabled) {
            vfio_enable_msi(vdev);
        } else if (was_enabled && !is_enabled) {
            vfio_disable_msi_x(vdev, false);
        }
    }

    if (pdev->cap_present & QEMU_PCI_CAP_MSIX &&
        ranges_overlap(addr, len, pdev->msix_cap, MSIX_CAP_LENGTH)) {
        int is_enabled, was_enabled = msix_enabled(pdev);

        pci_default_write_config(pdev, addr, val, len);

        is_enabled = msix_enabled(pdev);

        if (!was_enabled && is_enabled) {
            /* vfio_msix_vector_use handles this automatically */
        } else if (was_enabled && !is_enabled) {
            vfio_disable_msi_x(vdev, true);
        }
    }
}

/*
 * DMA - Mapping and unmapping for the "type1" IOMMU interface used on x86
 */
static int vfio_dma_map(VFIOContainer *container, target_phys_addr_t iova,
                        ram_addr_t size, void *vaddr, bool readonly)
{
    struct vfio_iommu_type1_dma_map map = {
        .argsz = sizeof(map),
        .flags = VFIO_DMA_MAP_FLAG_READ,
        .vaddr = (__u64)vaddr,
        .iova = iova,
        .size = size,
    };

    if (!readonly) {
        map.flags |= VFIO_DMA_MAP_FLAG_WRITE;
    }

    if (ioctl(container->fd, VFIO_IOMMU_MAP_DMA, &map)) {
        DPRINTF("VFIO_MAP_DMA: %d\n", -errno);
        return -errno;
    }

    return 0;
}

static int vfio_dma_unmap(VFIOContainer *container,
                          target_phys_addr_t iova, ram_addr_t size)
{
    struct vfio_iommu_type1_dma_unmap unmap = {
        .argsz = sizeof(unmap),
        .flags = 0,
        .iova = iova,
        .size = size,
    };

    if (ioctl(container->fd, VFIO_IOMMU_UNMAP_DMA, &unmap)) {
        DPRINTF("VFIO_UNMAP_DMA: %d\n", -errno);
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
                                 bool match_data, uint64_t data,
                                 EventNotifier *e)
{
    /* We don't care about eventfds */
}

static bool vfio_listener_skipped_section(MemoryRegionSection *section)
{
    return !memory_region_is_ram(section->mr);
}

static void vfio_listener_region_add(MemoryListener *listener,
                                     MemoryRegionSection *section)
{
    VFIOContainer *container = container_of(listener, VFIOContainer,
                                            iommu_data.listener);
    target_phys_addr_t iova, end;
    void *vaddr;
    int ret;

    if (vfio_listener_skipped_section(section)) {
        DPRINTF("vfio: SKIPPING region_add %016lx - %016lx\n",
                section->offset_within_address_space,
                section->offset_within_address_space + section->size - 1);
        return;
    }

    if (unlikely((section->offset_within_address_space & ~TARGET_PAGE_MASK) !=
                 (section->offset_within_region & ~TARGET_PAGE_MASK))) {
        error_report("%s received unaligned region\n", __func__);
        return;
    }

    iova = TARGET_PAGE_ALIGN(section->offset_within_address_space);
    end = (section->offset_within_address_space + section->size) &
          TARGET_PAGE_MASK;

    if (iova >= end) {
        return;
    }

    vaddr = memory_region_get_ram_ptr(section->mr) +
            section->offset_within_region +
            (iova - section->offset_within_address_space);

    DPRINTF("vfio: region_add %016lx - %016lx [%p]\n",
            iova, end - 1, vaddr);

    ret = vfio_dma_map(container, iova, end - iova, vaddr, section->readonly);
    if (ret) {
        error_report("vfio_dma_map(%p, 0x%016lx, 0x%lx, %p) = %d (%s)\n",
                     container, iova, end - iova, vaddr, ret, strerror(errno));
    }
}

static void vfio_listener_region_del(MemoryListener *listener,
                                     MemoryRegionSection *section)
{
    VFIOContainer *container = container_of(listener, VFIOContainer,
                                            iommu_data.listener);
    target_phys_addr_t iova, end;
    int ret;

    if (vfio_listener_skipped_section(section)) {
        DPRINTF("vfio: SKIPPING region_del %016lx - %016lx\n",
                section->offset_within_address_space,
                section->offset_within_address_space + section->size - 1);
        return;
    }

    if (unlikely((section->offset_within_address_space & ~TARGET_PAGE_MASK) !=
                 (section->offset_within_region & ~TARGET_PAGE_MASK))) {
        error_report("%s received unaligned region\n", __func__);
        return;
    }

    iova = TARGET_PAGE_ALIGN(section->offset_within_address_space);
    end = (section->offset_within_address_space + section->size) &
          TARGET_PAGE_MASK;

    if (iova >= end) {
        return;
    }

    DPRINTF("vfio: region_del %016lx - %016lx\n", iova, end - 1);

    ret = vfio_dma_unmap(container, iova, end - iova);
    if (ret) {
        error_report("vfio_dma_unmap(%p, 0x%016lx, 0x%lx) = %d (%s)\n",
                     container, iova, end - iova, ret, strerror(errno));
    }
}

static void vfio_listener_release(VFIOContainer *container)
{
    memory_listener_unregister(&container->iommu_data.listener);
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
        vfio_disable_msi_x(vdev, false);
        break;
    case INT_MSIX:
        vfio_disable_msi_x(vdev, true);
        break;
    }
}

static int vfio_setup_msi(VFIODevice *vdev, int pos)
{
    uint16_t ctrl;
    bool msi_64bit, msi_maskbit;
    int ret, entries;

    if (!msi_supported) {
        return 0;
    }

    if (pread(vdev->fd, &ctrl, sizeof(ctrl),
              vdev->config_offset + pos + PCI_CAP_FLAGS) != sizeof(ctrl)) {
        return -1;
    }
    ctrl = le16_to_cpu(ctrl);

    msi_64bit = !!(ctrl & PCI_MSI_FLAGS_64BIT);
    msi_maskbit = !!(ctrl & PCI_MSI_FLAGS_MASKBIT);
    entries = 1 << ((ctrl & PCI_MSI_FLAGS_QMASK) >> 1);

    DPRINTF("%04x:%02x:%02x.%x PCI MSI CAP @0x%x\n", vdev->host.domain,
            vdev->host.bus, vdev->host.slot, vdev->host.function, pos);

    ret = msi_init(&vdev->pdev, pos, entries, msi_64bit, msi_maskbit);
    if (ret < 0) {
        error_report("vfio: msi_init failed\n");
        return ret;
    }
    vdev->msi_cap_size = 0xa + (msi_maskbit ? 0xa : 0) + (msi_64bit ? 0x4 : 0);

    return 0;
}

/*
 * We don't have any control over how pci_add_capability() inserts
 * capabilities into the chain.  In order to setup MSI-X we need a
 * MemoryRegion for the BAR.  In order to setup the BAR and not
 * attempt to mmap the MSI-X table area, which VFIO won't allow, we
 * need to first look for where the MSI-X table lives.  So we
 * unfortunately split MSI-X setup across two functions.
 */
static int vfio_early_setup_msix(VFIODevice *vdev)
{
    uint8_t pos;
    uint16_t ctrl;
    uint32_t table, pba;

    pos = pci_find_capability(&vdev->pdev, PCI_CAP_ID_MSIX);
    if (!pos) {
        return 0;
    }

    if (pread(vdev->fd, &ctrl, sizeof(ctrl),
              vdev->config_offset + pos + PCI_CAP_FLAGS) != sizeof(ctrl)) {
        return -1;
    }

    if (pread(vdev->fd, &table, sizeof(table),
              vdev->config_offset + pos + PCI_MSIX_TABLE) != sizeof(table)) {
        return -1;
    }

    if (pread(vdev->fd, &pba, sizeof(pba),
              vdev->config_offset + pos + PCI_MSIX_PBA) != sizeof(pba)) {
        return -1;
    }

    ctrl = le16_to_cpu(ctrl);
    table = le32_to_cpu(table);
    pba = le32_to_cpu(pba);

    vdev->msix = g_malloc0(sizeof(*(vdev->msix)));
    vdev->msix->table_bar = table & PCI_MSIX_FLAGS_BIRMASK;
    vdev->msix->table_offset = table & ~PCI_MSIX_FLAGS_BIRMASK;
    vdev->msix->pba_bar = pba & PCI_MSIX_FLAGS_BIRMASK;
    vdev->msix->pba_offset = pba & ~PCI_MSIX_FLAGS_BIRMASK;
    vdev->msix->entries = (ctrl & PCI_MSIX_FLAGS_QSIZE) + 1;

    DPRINTF("%04x:%02x:%02x.%x "
            "PCI MSI-X CAP @0x%x, BAR %d, offset 0x%x, entries %d\n",
            vdev->host.domain, vdev->host.bus, vdev->host.slot,
            vdev->host.function, pos, vdev->msix->table_bar,
            vdev->msix->table_offset, vdev->msix->entries);

    return 0;
}

static int vfio_setup_msix(VFIODevice *vdev, int pos)
{
    int ret;

    if (!msi_supported) {
        return 0;
    }

    ret = msix_init(&vdev->pdev, vdev->msix->entries,
                    &vdev->bars[vdev->msix->table_bar].mem,
                    vdev->msix->table_bar, vdev->msix->table_offset,
                    &vdev->bars[vdev->msix->pba_bar].mem,
                    vdev->msix->pba_bar, vdev->msix->pba_offset, pos);
    if (ret < 0) {
        error_report("vfio: msix_init failed\n");
        return ret;
    }

    ret = msix_set_vector_notifiers(&vdev->pdev, vfio_msix_vector_use,
                                    vfio_msix_vector_release);
    if (ret) {
        error_report("vfio: msix_set_vector_notifiers failed %d\n", ret);
        msix_uninit(&vdev->pdev, &vdev->bars[vdev->msix->table_bar].mem,
                    &vdev->bars[vdev->msix->pba_bar].mem);
        return ret;
    }

    return 0;
}

static void vfio_teardown_msi(VFIODevice *vdev)
{
    msi_uninit(&vdev->pdev);

    if (vdev->msix) {
        /* FIXME: Why can't unset just silently do nothing?? */
        if (vdev->pdev.msix_vector_use_notifier &&
            vdev->pdev.msix_vector_release_notifier) {
            msix_unset_vector_notifiers(&vdev->pdev);
        }

        msix_uninit(&vdev->pdev, &vdev->bars[vdev->msix->table_bar].mem,
                    &vdev->bars[vdev->msix->pba_bar].mem);
    }
}

/*
 * Resource setup
 */
static void vfio_unmap_bar(VFIODevice *vdev, int nr)
{
    VFIOBAR *bar = &vdev->bars[nr];

    if (!bar->size) {
        return;
    }

    memory_region_del_subregion(&bar->mem, &bar->mmap_mem);
    munmap(bar->mmap, memory_region_size(&bar->mmap_mem));

    if (vdev->msix && vdev->msix->table_bar == nr) {
        memory_region_del_subregion(&bar->mem, &vdev->msix->mmap_mem);
        munmap(vdev->msix->mmap, memory_region_size(&vdev->msix->mmap_mem));
    }

    memory_region_destroy(&bar->mem);
}

static int vfio_mmap_bar(VFIOBAR *bar, MemoryRegion *mem, MemoryRegion *submem,
                         void **map, size_t size, off_t offset,
                         const char *name)
{
    int ret = 0;

    if (size && bar->flags & VFIO_REGION_INFO_FLAG_MMAP) {
        int prot = 0;

        if (bar->flags & VFIO_REGION_INFO_FLAG_READ) {
            prot |= PROT_READ;
        }

        if (bar->flags & VFIO_REGION_INFO_FLAG_WRITE) {
            prot |= PROT_WRITE;
        }

        *map = mmap(NULL, size, prot, MAP_SHARED,
                    bar->fd, bar->fd_offset + offset);
        if (*map == MAP_FAILED) {
            *map = NULL;
            ret = -errno;
            goto empty_region;
        }

        memory_region_init_ram_ptr(submem, name, size, *map);
    } else {
empty_region:
        /* Create a zero sized sub-region to make cleanup easy. */
        memory_region_init(submem, name, 0);
    }

    memory_region_add_subregion(mem, offset, submem);

    return ret;
}

static void vfio_map_bar(VFIODevice *vdev, int nr)
{
    VFIOBAR *bar = &vdev->bars[nr];
    unsigned size = bar->size;
    char name[64];
    uint32_t pci_bar;
    uint8_t type;
    int ret;

    /* Skip both unimplemented BARs and the upper half of 64bit BARS. */
    if (!size) {
        return;
    }

    snprintf(name, sizeof(name), "VFIO %04x:%02x:%02x.%x BAR %d",
             vdev->host.domain, vdev->host.bus, vdev->host.slot,
             vdev->host.function, nr);

    /* Determine what type of BAR this is for registration */
    ret = pread(vdev->fd, &pci_bar, sizeof(pci_bar),
                vdev->config_offset + PCI_BASE_ADDRESS_0 + (4 * nr));
    if (ret != sizeof(pci_bar)) {
        error_report("vfio: Failed to read BAR %d (%s)\n", nr, strerror(errno));
        return;
    }

    pci_bar = le32_to_cpu(pci_bar);
    type = pci_bar & (pci_bar & PCI_BASE_ADDRESS_SPACE_IO ?
           ~PCI_BASE_ADDRESS_IO_MASK : ~PCI_BASE_ADDRESS_MEM_MASK);

    /* A "slow" read/write mapping underlies all BARs */
    memory_region_init_io(&bar->mem, &vfio_bar_ops, bar, name, size);
    pci_register_bar(&vdev->pdev, nr, type, &bar->mem);

    /*
     * We can't mmap areas overlapping the MSIX vector table, so we
     * potentially insert a direct-mapped subregion before and after it.
     */
    if (vdev->msix && vdev->msix->table_bar == nr) {
        size = vdev->msix->table_offset & TARGET_PAGE_MASK;
    }

    strncat(name, " mmap", sizeof(name) - strlen(name) - 1);
    if (vfio_mmap_bar(bar, &bar->mem,
                      &bar->mmap_mem, &bar->mmap, size, 0, name)) {
        error_report("%s unsupported. Performance may be slow\n", name);
    }

    if (vdev->msix && vdev->msix->table_bar == nr) {
        unsigned start;

        start = TARGET_PAGE_ALIGN(vdev->msix->table_offset +
                                  (vdev->msix->entries * PCI_MSIX_ENTRY_SIZE));

        size = start < bar->size ? bar->size - start : 0;
        strncat(name, " msix-hi", sizeof(name) - strlen(name) - 1);
        /* MSIXInfo contains another MemoryRegion for this mapping */
        if (vfio_mmap_bar(bar, &bar->mem, &vdev->msix->mmap_mem,
                          &vdev->msix->mmap, size, start, name)) {
            error_report("%s unsupported. Performance may be slow\n", name);
        }
    }

    return;
}

static void vfio_map_bars(VFIODevice *vdev)
{
    int i;

    for (i = 0; i < PCI_ROM_SLOT; i++) {
        vfio_map_bar(vdev, i);
    }
}

static void vfio_unmap_bars(VFIODevice *vdev)
{
    int i;

    for (i = 0; i < PCI_ROM_SLOT; i++) {
        vfio_unmap_bar(vdev, i);
    }
}

/*
 * General setup
 */
static uint8_t vfio_std_cap_max_size(PCIDevice *pdev, uint8_t pos)
{
    uint8_t tmp, next = 0xff;

    for (tmp = pdev->config[PCI_CAPABILITY_LIST]; tmp;
         tmp = pdev->config[tmp + 1]) {
        if (tmp > pos && tmp < next) {
            next = tmp;
        }
    }

    return next - pos;
}

static int vfio_add_std_cap(VFIODevice *vdev, uint8_t pos)
{
    PCIDevice *pdev = &vdev->pdev;
    uint8_t cap_id, next, size;
    int ret;

    cap_id = pdev->config[pos];
    next = pdev->config[pos + 1];

    /*
     * If it becomes important to configure capabilities to their actual
     * size, use this as the default when it's something we don't recognize.
     * Since QEMU doesn't actually handle many of the config accesses,
     * exact size doesn't seem worthwhile.
     */
    size = vfio_std_cap_max_size(pdev, pos);

    /*
     * pci_add_capability always inserts the new capability at the head
     * of the chain.  Therefore to end up with a chain that matches the
     * physical device, we insert from the end by making this recursive.
     * This is also why we pre-caclulate size above as cached config space
     * will be changed as we unwind the stack.
     */
    if (next) {
        ret = vfio_add_std_cap(vdev, next);
        if (ret) {
            return ret;
        }
    } else {
        pdev->config[PCI_CAPABILITY_LIST] = 0; /* Begin the rebuild */
    }

    switch (cap_id) {
    case PCI_CAP_ID_MSI:
        ret = vfio_setup_msi(vdev, pos);
        break;
    case PCI_CAP_ID_MSIX:
        ret = vfio_setup_msix(vdev, pos);
        break;
    default:
        ret = pci_add_capability(pdev, cap_id, pos, size);
        break;
    }

    if (ret < 0) {
        error_report("vfio: %04x:%02x:%02x.%x Error adding PCI capability "
                     "0x%x[0x%x]@0x%x: %d\n", vdev->host.domain,
                     vdev->host.bus, vdev->host.slot, vdev->host.function,
                     cap_id, size, pos, ret);
        return ret;
    }

    return 0;
}

static int vfio_add_capabilities(VFIODevice *vdev)
{
    PCIDevice *pdev = &vdev->pdev;

    if (!(pdev->config[PCI_STATUS] & PCI_STATUS_CAP_LIST) ||
        !pdev->config[PCI_CAPABILITY_LIST]) {
        return 0; /* Nothing to add */
    }

    return vfio_add_std_cap(vdev, pdev->config[PCI_CAPABILITY_LIST]);
}

static int vfio_load_rom(VFIODevice *vdev)
{
    uint64_t size = vdev->rom_size;
    const VMStateDescription *vmsd;
    char name[32];
    off_t off = 0, voff = vdev->rom_offset;
    ssize_t bytes;
    void *ptr;

    /* If loading ROM from file, pci handles it */
    if (vdev->pdev.romfile || !vdev->pdev.rom_bar || !size) {
        return 0;
    }

    DPRINTF("%s(%04x:%02x:%02x.%x)\n", __func__, vdev->host.domain,
            vdev->host.bus, vdev->host.slot, vdev->host.function);

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
            error_report("vfio: Error reading device ROM: %s\n",
                         strerror(errno));
            memory_region_destroy(&vdev->pdev.rom);
            return -1;
        }
    }

    pci_register_bar(&vdev->pdev, PCI_ROM_SLOT, 0, &vdev->pdev.rom);
    vdev->pdev.has_rom = true;
    return 0;
}

static int vfio_connect_container(VFIOGroup *group)
{
    VFIOContainer *container;
    int ret, fd;

    if (group->container) {
        return 0;
    }

    QLIST_FOREACH(container, &container_list, next) {
        if (!ioctl(group->fd, VFIO_GROUP_SET_CONTAINER, &container->fd)) {
            group->container = container;
            QLIST_INSERT_HEAD(&container->group_list, group, container_next);
            return 0;
        }
    }

    fd = qemu_open("/dev/vfio/vfio", O_RDWR);
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

    if (ioctl(fd, VFIO_CHECK_EXTENSION, VFIO_TYPE1_IOMMU)) {
        ret = ioctl(group->fd, VFIO_GROUP_SET_CONTAINER, &fd);
        if (ret) {
            error_report("vfio: failed to set group container: %s\n",
                         strerror(errno));
            g_free(container);
            close(fd);
            return -1;
        }

        ret = ioctl(fd, VFIO_SET_IOMMU, VFIO_TYPE1_IOMMU);
        if (ret) {
            error_report("vfio: failed to set iommu for container: %s\n",
                         strerror(errno));
            g_free(container);
            close(fd);
            return -1;
        }

        container->iommu_data.listener = (MemoryListener) {
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
            .eventfd_del = vfio_listener_dummy3,
        };
        container->iommu_data.release = vfio_listener_release;

        memory_listener_register(&container->iommu_data.listener,
                                 get_system_memory());
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
        if (container->iommu_data.release) {
            container->iommu_data.release(container);
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

    snprintf(path, sizeof(path), "/dev/vfio/%d", groupid);
    group->fd = qemu_open(path, O_RDWR);
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

    if (vfio_connect_container(group)) {
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

static int vfio_get_device(VFIOGroup *group, const char *name, VFIODevice *vdev)
{
    struct vfio_device_info dev_info = { .argsz = sizeof(dev_info) };
    struct vfio_region_info reg_info = { .argsz = sizeof(reg_info) };
    int ret, i;

    ret = ioctl(group->fd, VFIO_GROUP_GET_DEVICE_FD, name);
    if (ret < 0) {
        error_report("vfio: error getting device %s from group %d: %s",
                     name, group->groupid, strerror(errno));
        error_report("Verify all devices in group %d "
                     "are bound to vfio-pci or pci-stub and not already in use",
                     group->groupid);
        return ret;
    }

    vdev->fd = ret;
    vdev->group = group;
    QLIST_INSERT_HEAD(&group->device_list, vdev, next);

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
        error_report("Warning, device %s does not support reset\n", name);
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

        vdev->bars[i].flags = reg_info.flags;
        vdev->bars[i].size = reg_info.size;
        vdev->bars[i].fd_offset = reg_info.offset;
        vdev->bars[i].fd = vdev->fd;
        vdev->bars[i].nr = i;
    }

    reg_info.index = VFIO_PCI_ROM_REGION_INDEX;

    ret = ioctl(vdev->fd, VFIO_DEVICE_GET_REGION_INFO, &reg_info);
    if (ret) {
        error_report("vfio: Error getting ROM info: %s", strerror(errno));
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
        error_report("vfio: Error getting config info: %s", strerror(errno));
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
    if (vdev->msix) {
        g_free(vdev->msix);
        vdev->msix = NULL;
    }
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

    /* Check that the host device exists */
    snprintf(path, sizeof(path),
             "/sys/bus/pci/devices/%04x:%02x:%02x.%01x/",
             vdev->host.domain, vdev->host.bus, vdev->host.slot,
             vdev->host.function);
    if (stat(path, &st) < 0) {
        error_report("vfio: error: no such host device: %s", path);
        return -1;
    }

    strncat(path, "iommu_group", sizeof(path) - strlen(path) - 1);

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

    DPRINTF("%s(%04x:%02x:%02x.%x) group %d\n", __func__, vdev->host.domain,
            vdev->host.bus, vdev->host.slot, vdev->host.function, groupid);

    group = vfio_get_group(groupid);
    if (!group) {
        error_report("vfio: failed to get group %d", groupid);
        return -1;
    }

    snprintf(path, sizeof(path), "%04x:%02x:%02x.%01x",
            vdev->host.domain, vdev->host.bus, vdev->host.slot,
            vdev->host.function);

    QLIST_FOREACH(pvdev, &group->device_list, next) {
        if (pvdev->host.domain == vdev->host.domain &&
            pvdev->host.bus == vdev->host.bus &&
            pvdev->host.slot == vdev->host.slot &&
            pvdev->host.function == vdev->host.function) {

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
        error_report("vfio: Failed to read device config space\n");
        goto out_put;
    }

    /*
     * Clear host resource mapping info.  If we choose not to register a
     * BAR, such as might be the case with the option ROM, we can get
     * confusing, unwritable, residual addresses from the host here.
     */
    memset(&vdev->pdev.config[PCI_BASE_ADDRESS_0], 0, 24);
    memset(&vdev->pdev.config[PCI_ROM_ADDRESS], 0, 4);

    vfio_load_rom(vdev);

    if (vfio_early_setup_msix(vdev)) {
        goto out_put;
    }

    vfio_map_bars(vdev);

    if (vfio_add_capabilities(vdev)) {
        goto out_teardown;
    }

    if (vfio_pci_read_config(&vdev->pdev, PCI_INTERRUPT_PIN, 1)) {
        pci_device_set_intx_routing_notifier(&vdev->pdev, vfio_update_irq);
    }

    if (vfio_enable_intx(vdev)) {
        goto out_teardown;
    }

    return 0;

out_teardown:
    pci_device_set_intx_routing_notifier(&vdev->pdev, NULL);
    vfio_teardown_msi(vdev);
    vfio_unmap_bars(vdev);
out_put:
    vfio_put_device(vdev);
    vfio_put_group(group);
    return -1;
}

static void vfio_exitfn(struct PCIDevice *pdev)
{
    VFIODevice *vdev = DO_UPCAST(VFIODevice, pdev, pdev);
    VFIOGroup *group = vdev->group;

    pci_device_set_intx_routing_notifier(&vdev->pdev, NULL);
    vfio_disable_interrupts(vdev);
    vfio_teardown_msi(vdev);
    vfio_unmap_bars(vdev);
    vfio_put_device(vdev);
    vfio_put_group(group);
}

static void vfio_reset(DeviceState *dev)
{
    PCIDevice *pdev = DO_UPCAST(PCIDevice, qdev, dev);
    VFIODevice *vdev = DO_UPCAST(VFIODevice, pdev, pdev);

    if (!vdev->reset_works) {
        return;
    }

    if (ioctl(vdev->fd, VFIO_DEVICE_RESET)) {
        error_report("vfio: Error unable to reset physical device "
                     "(%04x:%02x:%02x.%x): %s\n", vdev->host.domain,
                     vdev->host.bus, vdev->host.slot, vdev->host.function,
                     strerror(errno));
    }
}

static Property vfio_pci_dev_properties[] = {
    DEFINE_PROP_PCI_HOST_DEVADDR("host", VFIODevice, host),
    /*
     * TODO - support passed fds... is this necessary?
     * DEFINE_PROP_STRING("vfiofd", VFIODevice, vfiofd_name),
     * DEFINE_PROP_STRING("vfiogroupfd, VFIODevice, vfiogroupfd_name),
     */
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
