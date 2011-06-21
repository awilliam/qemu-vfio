/*
 * Copyright 2010 Cisco Systems, Inc.  All rights reserved.
 * Author: Tom Lyon, pugs@cisco.com
 *
 * This program is free software; you may redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Portions derived from drivers/uio/uio.c:
 * Copyright(C) 2005, Benedikt Spranger <b.spranger@linutronix.de>
 * Copyright(C) 2005, Thomas Gleixner <tglx@linutronix.de>
 * Copyright(C) 2006, Hans J. Koch <hjk@linutronix.de>
 * Copyright(C) 2006, Greg Kroah-Hartman <greg@kroah.com>
 *
 * Portions derived from drivers/uio/uio_pci_generic.c:
 * Copyright (C) 2009 Red Hat, Inc.
 * Author: Michael S. Tsirkin <mst@redhat.com>
 */
#include <linux/types.h>

/*
 * VFIO driver - allow mapping and use of certain PCI devices
 * in unprivileged user processes. (If IOMMU is present)
 * Especially useful for Virtual Function parts of SR-IOV devices
 */

#ifdef __KERNEL__

struct vfio_nl_client {
	struct list_head	list;
	u64			msgcap;
	struct net		*net;
	u32			pid;
};

struct vfio_uiommu {
	struct uiommu_domain	*udomain;
	struct mutex		dgate;		/* dma op gate */
	struct list_head	dm_list;
	u32			locked_pages;
	struct mm_struct	*mm;
	struct list_head	next;
	int			refcnt;
	int			cachec;
};

struct perm_bits;
struct eoi_eventfd;
struct vfio_dev {
	struct device	*dev;
	struct pci_dev	*pdev;
	char		name[8];
	u8		*pci_config_map;
	int		pci_config_size;
	int		devnum;
	void __iomem	*barmap[PCI_STD_RESOURCE_END+1];
	spinlock_t	irqlock;	/* guards command register accesses */
	struct vfio_uiommu	*uiommu;
	int		refcnt;
	struct mutex	vgate;		/* device init/shutdown, refcnt gate */
	struct mutex	igate;		/* intr op gate */
	struct mutex	ngate;		/* netlink op gate */
	struct list_head nlc_list;	/* netlink clients */
	wait_queue_head_t dev_idle_q;
	wait_queue_head_t nl_wait_q;
	u32		nl_reply_seq;
	u32		nl_reply_value;
	struct msix_entry	*msix;
	struct eventfd_ctx	*ev_irq;
	struct eventfd_ctx	**ev_msi;
	struct eventfd_ctx	**ev_msix;
	int			msi_nvec;
	int			msix_nvec;
	u8		*vconfig;
	u32		rbar[7];	/* copies of real bars */
	u8		msi_qmax;
	u8		bardirty;
	struct perm_bits	*msi_perm;
	bool		pci_2_3;
	bool		irq_disabled;
	bool		virq_disabled;
	struct eoi_eventfd	*ev_eoi;
	bool		remove_pending;
	struct pci_saved_state	*pci_saved_state;
};

/*
 * Structure for keeping track of memory nailed down by the
 * user for DMA
 */
struct dma_map_page {
	struct list_head list;
	dma_addr_t      daddr;
	unsigned long	vaddr;
	int		npage;
	int		rdwr;
};

/* VFIO class infrastructure */
struct vfio_class {
	struct kref kref;
	struct class *class;
};
extern struct vfio_class *vfio_class;

ssize_t vfio_io_readwrite(int, struct vfio_dev *,
			char __user *, size_t, loff_t *);
ssize_t vfio_mem_readwrite(int, struct vfio_dev *,
			char __user *, size_t, loff_t *);
ssize_t vfio_config_readwrite(int, struct vfio_dev *,
			char __user *, size_t, loff_t *);

void vfio_drop_msi(struct vfio_dev *);
void vfio_drop_msix(struct vfio_dev *);
int vfio_setup_msi(struct vfio_dev *, int, int __user *);
int vfio_setup_msix(struct vfio_dev *, int, int __user *);

#ifndef PCI_MSIX_ENTRY_SIZE
#define	PCI_MSIX_ENTRY_SIZE	16
#endif
#ifndef PCI_STATUS_INTERRUPT
#define	PCI_STATUS_INTERRUPT	0x08
#endif

struct vfio_dma_map;
int vfio_dma_unmap_dm(struct vfio_uiommu *, struct vfio_dma_map *);
int vfio_dma_map_dm(struct vfio_uiommu *, struct vfio_dma_map *);
int vfio_domain_set(struct vfio_dev *, int, int);
int vfio_domain_unset(struct vfio_dev *);

int vfio_class_init(void);
void vfio_class_destroy(void);
int vfio_dev_add_attributes(struct vfio_dev *);
int vfio_build_config_map(struct vfio_dev *);
void vfio_init_pci_perm_bits(void);

int vfio_nl_init(void);
void vfio_nl_freeclients(struct vfio_dev *);
void vfio_nl_exit(void);
int vfio_nl_remove(struct vfio_dev *);
int vfio_validate(struct vfio_dev *);
int vfio_nl_upcall(struct vfio_dev *, u8, int, int);
void vfio_pm_process_reply(int);
pci_ers_result_t vfio_error_detected(struct pci_dev *, pci_channel_state_t);
pci_ers_result_t vfio_mmio_enabled(struct pci_dev *);
pci_ers_result_t vfio_link_reset(struct pci_dev *);
pci_ers_result_t vfio_slot_reset(struct pci_dev *);
void vfio_error_resume(struct pci_dev *);
#define VFIO_ERROR_REPLY_TIMEOUT	(3*HZ)
#define VFIO_SUSPEND_REPLY_TIMEOUT	(5*HZ)

irqreturn_t vfio_interrupt(int, void *);
int vfio_irq_eoi(struct vfio_dev *);
int vfio_irq_eoi_eventfd(struct vfio_dev *, int);
int vfio_eoi_module_init(void);
void vfio_eoi_module_exit(void);
irqreturn_t vfio_disable_intx(struct vfio_dev *vdev);
void vfio_enable_intx(struct vfio_dev *vdev);

#endif	/* __KERNEL__ */

/* Kernel & User level defines for ioctls */

/*
 * Structure for DMA mapping of user buffers
 * vaddr, dmaaddr, and size must all be page aligned
 */
struct vfio_dma_map {
	__u64	vaddr;		/* process virtual addr */
	__u64	dmaaddr;	/* desired and/or returned dma address */
	__u64	size;		/* size in bytes */
#define	VFIO_MAX_MAP_SIZE	(1LL<<30) /* 1G, must be < (PAGE_SIZE<<32) */
	__u64	flags;		/* bool: 0 for r/o; 1 for r/w */
#define	VFIO_FLAG_WRITE		0x1	/* req writeable DMA mem */
};

/* map user pages at specific dma address */
/* requires previous VFIO_DOMAIN_SET */
#define	VFIO_DMA_MAP_IOVA	_IOWR(';', 101, struct vfio_dma_map)

/* unmap user pages */
#define	VFIO_DMA_UNMAP		_IOW(';', 102, struct vfio_dma_map)

/* request IRQ interrupts; use given eventfd */
#define	VFIO_EVENTFD_IRQ	_IOW(';', 103, int)

/* Request MSI interrupts: arg[0] is #, arg[1-n] are eventfds */
#define	VFIO_EVENTFDS_MSI	_IOW(';', 104, int)

/* Request MSI-X interrupts: arg[0] is #, arg[1-n] are eventfds */
#define	VFIO_EVENTFDS_MSIX	_IOW(';', 105, int)

/* Get length of a BAR */
#define	VFIO_BAR_LEN		_IOWR(';', 167, __u32)

/* Set the IOMMU domain - arg is fd from uiommu driver */
#define	VFIO_DOMAIN_SET		_IOW(';', 107, int)

/* Unset the IOMMU domain */
#define	VFIO_DOMAIN_UNSET	_IO(';', 108)

/* Re-enable INTx */
#define	VFIO_IRQ_EOI		_IO(';', 109)

/* Re-enable INTx via eventfd */
#define	VFIO_IRQ_EOI_EVENTFD	_IOW(';', 110, int)

/* Reset PCI function */
#define VFIO_RESET_FUNCTION	_IO(';', 111)

/*
 * Reads, writes, and mmaps determine which PCI BAR (or config space)
 * from the high level bits of the file offset
 */
#define	VFIO_PCI_BAR0_RESOURCE		0x0
#define	VFIO_PCI_BAR1_RESOURCE		0x1
#define	VFIO_PCI_BAR2_RESOURCE		0x2
#define	VFIO_PCI_BAR3_RESOURCE		0x3
#define	VFIO_PCI_BAR4_RESOURCE		0x4
#define	VFIO_PCI_BAR5_RESOURCE		0x5
#define	VFIO_PCI_ROM_RESOURCE		0x6
#define	VFIO_PCI_CONFIG_RESOURCE	0xF
#define	VFIO_PCI_SPACE_SHIFT		48
#define VFIO_PCI_CONFIG_OFF vfio_pci_space_to_offset(VFIO_PCI_CONFIG_RESOURCE)

static inline int vfio_offset_to_pci_space(__u64 off)
{
	return (off >> VFIO_PCI_SPACE_SHIFT) & 0xF;
}

static inline __u64 vfio_offset_to_pci_offset(__u64 off)
{
	return off & (((__u64)(1) << VFIO_PCI_SPACE_SHIFT) - 1);
}

static inline __u64 vfio_pci_space_to_offset(int sp)
{
	return (__u64)(sp) << VFIO_PCI_SPACE_SHIFT;
}

/*
 * Netlink defines:
 */
#define VFIO_GENL_NAME	"VFIO"

/* message types */
enum {
	VFIO_MSG_INVAL = 0,
	/* kernel to user */
	VFIO_MSG_REMOVE,		/* unbind, module or hotplug remove */
	VFIO_MSG_ERROR_DETECTED,	/* pci err handling - error detected */
	VFIO_MSG_MMIO_ENABLED,		/* pci err handling - mmio enabled */
	VFIO_MSG_LINK_RESET,		/* pci err handling - link reset */
	VFIO_MSG_SLOT_RESET,		/* pci err handling - slot reset */
	VFIO_MSG_ERROR_RESUME,		/* pci err handling - resume normal */
	VFIO_MSG_PM_SUSPEND,		/* suspend or hibernate notification */
	VFIO_MSG_PM_RESUME,		/* resume after suspend or hibernate */
	/* user to kernel */
	VFIO_MSG_REGISTER,
	VFIO_MSG_ERROR_HANDLING_REPLY,	/* err handling reply */
	VFIO_MSG_PM_SUSPEND_REPLY,	/* suspend notify reply */
};

/* attributes */
enum {
	VFIO_ATTR_UNSPEC,
	VFIO_ATTR_MSGCAP,	/* bitmask of messages desired */
	VFIO_ATTR_PCI_DOMAIN,
	VFIO_ATTR_PCI_BUS,
	VFIO_ATTR_PCI_SLOT,
	VFIO_ATTR_PCI_FUNC,
	VFIO_ATTR_CHANNEL_STATE,
	VFIO_ATTR_ERROR_HANDLING_REPLY,
	VFIO_ATTR_PM_SUSPEND_REPLY,
	__VFIO_NL_ATTR_MAX
};
#define VFIO_NL_ATTR_MAX (__VFIO_NL_ATTR_MAX - 1)
