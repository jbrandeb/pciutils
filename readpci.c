// SPDX-License-Identifier: GPL-2.0-only
/*
 *	The PCI Utilities -- read and write PCI registers
 *
 *	Copyright(c) 2022 Intel Corporation. All rights reserved.
 *	Originally authored by: Shannon Nelson <shannon.nelson@intel.com>
 *	Changes and published by: Jesse Brandeburg <jesse.brandeburg@intel.com>
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include "pciutils.h"

#include <fcntl.h>
#include <getopt.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <linux/types.h>

static struct pci_filter filter;    /* Device filter */

static struct option opts[] = {
	{"write", 1, NULL, 'w' },
	{"address", 1, NULL, 'a' },
	{"debug", 0, NULL, 'D' },
	{"verbose", 0, NULL, 'v' },
	{"device", 1, NULL, 'd' },
	{"slot", 1, NULL, 's' },
	{ 0, 0, NULL, '0' }
};

static void usage(char *progname, char *idfile)
{
	printf("Usage: %s [options] [device]   (%s)\n\n"
	       "Options:\n"
	       "-w <value>\t\tValue to write to the address\n"
	       "-W <value>\t\tValue to write to the address (no read)\n"
	       "-a <value>\t\tRegister address\n"
	       "-b <value>\t\tBAR to access other than BAR 0\n"
	       "-m\t\t\tAccess MSI-X BAR instead of BAR 0\n"
	       "-D\t\t\tPCI debugging\n"
	       "-q \t\t\tQuiet mode, no banner\n"
	       "-v \t\t\tEnable more verbose output\n"
	       "Device:\n"
	       "-d [<vendor>]:[<device>]\t\t\tShow selected devices\n"
	       "-s [[[[<domain>]:]<bus>]:][<slot>][.[<func>]]"
	       	"\tShow devices in selected slots\n\n",
	       progname, idfile);
}

static int find_msix(struct pci_dev *dev, u8 *bir)
{
	struct pci_cap *msix_cap;

	msix_cap = pci_find_cap(dev, PCI_CAP_ID_MSIX, PCI_CAP_NORMAL);

	/* no MSI-X capabilities found, just exit without error */
	if (!msix_cap) {
		printf("Cannot find MSI-X capability!\n");
		return -1;
	}

	/* determine which BAR contains MSI-X data */
	*bir = pci_read_long(dev, msix_cap->addr + 4) & 0x7;
	if (!*bir) {
		printf("Cannot find MSI-X BAR!\n");
		return -1;
	}

	return 0;
}

static int print_register(struct pci_dev *dev, u8 bir, u32 address)
{
	volatile void *mem;
	int dev_mem_fd;

	dev_mem_fd = open("/dev/mem", O_RDONLY);
	if (dev_mem_fd < 0) {
		perror("open");
		return -1;
	}

	mem = (u8 *)mmap(NULL, dev->size[bir], PROT_READ, MAP_SHARED, dev_mem_fd, (dev->base_addr[bir] & PCI_ADDR_MEM_MASK));
	if (mem == MAP_FAILED) {
		perror("mmap/readable - try rebooting with iomem=relaxed");
		close(dev_mem_fd);
		return -1;
	}

	printf("0x%x == 0x%x\n", address, *((u32 *)(mem + address)));

	close(dev_mem_fd);
	munmap((void *)mem, dev->size[bir]);

	return 0;
}

static int write_register(struct pci_dev *dev, u8 bir, u32 address, u32 value)
{
	volatile void *mem;
	int dev_mem_fd;

	dev_mem_fd = open("/dev/mem", O_RDWR);
	if (dev_mem_fd < 0) {
		perror("open");
		return -1;
	}

	mem = mmap(NULL, dev->size[bir], PROT_WRITE, MAP_SHARED, dev_mem_fd, (dev->base_addr[bir] & PCI_ADDR_MEM_MASK));
	if (mem == MAP_FAILED) {
		perror("mmap/writable - try rebooting with iomem=relaxed");
		close(dev_mem_fd);
		return -1;
	}

	*((u32 *)(mem + address)) = value;

	close(dev_mem_fd);
	munmap((void *)mem, dev->size[bir]);

	return 0;
}

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#endif

int main(int argc, char **argv)
{
	int ch, debug = 0, quiet = 0;
	struct pci_access *pacc;
	struct pci_dev *dev;
	char *errmsg;
	char buf[128];
	u32 address = 0;
	u32 value = 0;
	u64 lvalue = 0;
	int device_specified = 0;
	int do_write = 0;
	int do_writeonly = 0;
	int got_address = 0;
	int ret = 0;
	int msix = 0;
	u8 bir = 0;

	if (getuid() != 0) {
		printf("%s: must be run as root\n", argv[0]);
		exit(1);
	}

	pacc = pci_alloc();		/* Get the pci_access structure */
	if (pacc == NULL) {
		perror("pci_alloc");
		exit(1);
	}
	pci_filter_init(pacc, &filter);

	while ((ch = getopt_long(argc, argv, "W:w:Da:mb:d:s:qv", opts, NULL)) != -1) {
		switch (ch) {
		case 'w':
			lvalue = strtoll(optarg, NULL, 0);
			value = (u32)lvalue;
			do_write++;
			break;
		case 'W':
			lvalue = strtoll(optarg, NULL, 0);
			value = (u32)lvalue;
			do_write++;
			do_writeonly++;
			break;
		case 'D':
			pacc->debugging++;
			break;
		case 'a':
			address = strtol(optarg, NULL, 0);
			got_address++;
			break;
		case 'm':
			msix++;
			break;
		case 'b':
			lvalue = strtoll(optarg, NULL, 0);
			if (lvalue >= ARRAY_SIZE(dev->base_addr)) {
				printf("Invalid BAR requested!\n");
				exit(1);
			}
			bir = (u8)lvalue;
			break;
		case 'd':
			/* Show only selected devices */
			if ((errmsg = pci_filter_parse_id(&filter, optarg))) {
				printf("%s\n", errmsg);
				exit(1);
			}
			device_specified++;
			break;
		case 's':
			/* Show only devices in selected slots */
			if ((errmsg = pci_filter_parse_slot(&filter, optarg))) {
				printf("%s\n", errmsg);
				exit(1);
			}
			device_specified++;
			break;
		case 'q':
			/* don't print the banner */
			quiet = 1;
			break;
		case 'v':
			/* turn on extra debug prints */
			debug = 1;
			break;
		case '?':
		default:
			usage(argv[0], pacc->id_file_name);
			exit(1);
			break;
		}
	}

	if (!device_specified) {
		printf("No device given\n");
		usage(argv[0], pacc->id_file_name);
		exit(1);
	}

	if (!got_address) {
		printf("No address given\n");
		usage(argv[0], pacc->id_file_name);
		exit(1);
	}

	pci_init(pacc);			/* Initialize the PCI library */
	pci_scan_bus(pacc);		/* Get the list of devices */

	if (pacc->debugging)
		printf(	"filter: "
#ifdef HAVE_DOMAIN_SUPPORT
			"domain=0x%x "
#endif
			"bus=0x%x slot=0x%x func=0x%x\n"
			"\tvendor=0x%x device=0x%x\n\n",
#ifdef HAVE_DOMAIN_SUPPORT
			filter.domain,
#endif
			filter.bus, filter.slot, filter.func,
			filter.vendor, filter.device);

	/* Iterate over all devices to find the single one we want */
	for (dev = pacc->devices; dev; dev = dev->next) {

		if (!pci_filter_match(&filter, dev))
			continue;

		/* Fill in header info we need */
		pci_fill_info(dev, PCI_FILL_IDENT | PCI_FILL_BASES | PCI_FILL_SIZES);

#ifdef HAVE_DOMAIN_SUPPORT
		if (dev->domain) {
			if (!quiet)
				printf("%04x:", dev->domain);
		}
#endif
		if (!quiet) {
			printf("%02x:%02x.%d (%04x:%04x) - %s\n", dev->bus,
			       dev->dev, dev->func, dev->vendor_id,
			       dev->device_id, pci_lookup_name(pacc, buf,
							       sizeof(buf),
					PCI_LOOKUP_VENDOR|PCI_LOOKUP_DEVICE,
					dev->vendor_id, dev->device_id, 0, 0));
		}

		/* overwrite bir with offset of MSI-X BAR */
		if (msix) {
			ret = find_msix(dev, &bir);
			if (ret)
				break;
		}

		/* verify that the BAR requested is valid */
		if (!dev->base_addr[bir]) {
			printf("Invalid BAR requested!\n");
			break;
		}

		if (debug)
			printf("BAR%d: len 0x%08lX\n", bir, dev->size[bir]);

		if (do_write) {
			ret = write_register(dev, bir, address, value);
			if (ret || do_writeonly)
				break;
		}
		ret = print_register(dev, bir, address);

		/* we're done, we only write/print one device */
		break;
	}

	if (!dev)
		printf("no device found\n");

	pci_cleanup(pacc);		/* Close everything */
	return ret;
}

