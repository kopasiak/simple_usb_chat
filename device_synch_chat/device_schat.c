/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 - 2016 Samsung Electronics
 *	   Krzysztof Opasiak <k.opasiak@samsung.com>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software
 * is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
 * OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <malloc.h>
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/eventfd.h>


#include <linux/usb/functionfs.h>

#define EP_IN_IDX 1
#define EP_OUT_IDX 2

#define MAX(a, b) ((a) > (b) ? (a) : (b))

/******************** Descriptors and Strings *******************************/

static const struct {
	struct usb_functionfs_descs_head_v2 header;
	__le32 fs_count;
	__le32 hs_count;
	struct {
		struct usb_interface_descriptor intf;
		struct usb_endpoint_descriptor_no_audio bulk_in;
		struct usb_endpoint_descriptor_no_audio bulk_out;
	} __attribute__ ((__packed__)) fs_descs, hs_descs;
} __attribute__ ((__packed__)) descriptors = {
	.header = {
		.magic = htole32(FUNCTIONFS_DESCRIPTORS_MAGIC_V2),
		.flags = htole32(FUNCTIONFS_HAS_FS_DESC |
				     FUNCTIONFS_HAS_HS_DESC),
		.length = htole32(sizeof(descriptors)),
	},
	.fs_count = htole32(3),
	.fs_descs = {
		.intf = {
			.bLength = sizeof(descriptors.fs_descs.intf),
			.bDescriptorType = USB_DT_INTERFACE,
			.bNumEndpoints = 2,
			.bInterfaceClass = USB_CLASS_VENDOR_SPEC,
			.iInterface = 1,
		},
		.bulk_in = {
			.bLength = sizeof(descriptors.fs_descs.bulk_in),
			.bDescriptorType = USB_DT_ENDPOINT,
			.bEndpointAddress = 1 | USB_DIR_IN,
			.bmAttributes = USB_ENDPOINT_XFER_BULK,
		},
		.bulk_out = {
			.bLength = sizeof(descriptors.fs_descs.bulk_out),
			.bDescriptorType = USB_DT_ENDPOINT,
			.bEndpointAddress = 2 | USB_DIR_OUT,
			.bmAttributes = USB_ENDPOINT_XFER_BULK,
		},
	},
	.hs_count = htole32(3),
	.hs_descs = {
		.intf = {
			.bLength = sizeof(descriptors.hs_descs.intf),
			.bDescriptorType = USB_DT_INTERFACE,
			.bNumEndpoints = 2,
			.bInterfaceClass = USB_CLASS_VENDOR_SPEC,
			.iInterface = 1,
		},
		.bulk_in = {
			.bLength = sizeof(descriptors.hs_descs.bulk_in),
			.bDescriptorType = USB_DT_ENDPOINT,
			.bEndpointAddress = 1 | USB_DIR_IN,
			.bmAttributes = USB_ENDPOINT_XFER_BULK,
			.wMaxPacketSize = htole16(512),
		},
		.bulk_out = {
			.bLength = sizeof(descriptors.hs_descs.bulk_out),
			.bDescriptorType = USB_DT_ENDPOINT,
			.bEndpointAddress = 2 | USB_DIR_OUT,
			.bmAttributes = USB_ENDPOINT_XFER_BULK,
			.wMaxPacketSize = htole16(512),
		},
	},
};

#define STR_INTERFACE "loop input to output"

static const struct {
	struct usb_functionfs_strings_head header;
	struct {
		__le16 code;
		const char str1[sizeof(STR_INTERFACE)];
	} __attribute__ ((__packed__)) lang0;
} __attribute__ ((__packed__)) strings = {
	.header = {
		.magic = htole32(FUNCTIONFS_STRINGS_MAGIC),
		.length = htole32(sizeof(strings)),
		.str_count = htole32(1),
		.lang_count = htole32(1),
	},
	.lang0 = {
		htole16(0x0409), /* en-us */
		STR_INTERFACE,
	},
};

#define EXIT_COMMAND "\\exit"
#define MAX_LINE_LENGTH 1024*8 /* 8 KB should be enough for single line */

#define report_error(...) do {			\
		fprintf(stderr, __VA_ARGS__);	\
		putchar('\n');			\
	} while (0)

/* Data structure for our message */
struct message {
	uint16_t length;
	char line_buf[MAX_LINE_LENGTH];
} __attribute((packed));

/* One global buffer for sending and receiving */
struct message M;

/* Prepare fresh ffs instance to communicate using our chat protocol */
int prepare_ffs(char *ffs_path, int *ep)
{
	char *ep_path;
	int i;
	int ret = 0;

	ep_path = malloc(strlen(ffs_path) + 4 /* "/ep#" */ + 1 /* '\0' */);
	if (!ep_path) {
		report_error("malloc");
		return -EINVAL;
	}

	/* open endpoint 0 */
	sprintf(ep_path, "%s/ep0", ffs_path);
	ep[0] = open(ep_path, O_RDWR);
	if (ep[0] < 0) {
		report_error("unable to open ep0");
		ret = -errno;
		goto out;
	}

	/* Provide descriptors and strings */
	if (write(ep[0], &descriptors, sizeof(descriptors)) < 0) {
		report_error("unable do write descriptors");
		ret = -errno;
		goto out;
	}
	if (write(ep[0], &strings, sizeof(strings)) < 0) {
		report_error("unable to write strings");
		ret = -errno;
		goto out;
	}

	/* Open other ep files */
	for (i = 1; i < 3; ++i) {
		sprintf(ep_path, "%s/ep%d", ffs_path, i);
		ep[i] = open(ep_path, O_RDWR);
		if (ep[i] < 0) {
			report_error("unable to open ep%d: %s\n", i,
			       strerror(errno));
			ret = -errno;
			goto out;
		}
	}

out:
	free(ep_path);
	return ret;
}

/* Close all ep files */
void cleanup_ffs(int *ep)
{
	int i;

	for (i = 0; i < 3; ++i)
		close(ep[i]);
}

/* Send chat message from device to host*/
int send_message(int ep, struct message *message)
{
	int len;
	int ret;

	len = strlen(message->line_buf) + 1;
	message->length = htole16(len + 2);

	ret = write(ep, &message->length, sizeof(message->length));
	if (ret < 0) {
		report_error("Unable to send length");
		goto out;
	}

	ret = write(ep, message->line_buf, len);
	if (ret < 0)
		report_error("Unable to send content");
out:
	return ret;
}

/* Receive message from host to device */
int recv_message(int ep, struct message *message)
{
	int ret;
	int len;

	ret = read(ep, &message->length, sizeof(message->length));
	if (ret < sizeof(message->length)) {
		report_error("Unable to receive length");
		goto out;
	}

	len = le16toh(message->length) - 2;

	ret = read(ep, message->line_buf, len);
	if (ret < len)
		report_error("Unable to receive length");

	return ret;
}

/* Handle events generated by kernel and provided via ep0 */
int handle_ep0(int ep0, int *connected)
{
	struct usb_functionfs_event event;
	int ret;

	ret = read(ep0, &event, sizeof(event));
	if (!ret) {
		report_error("unable to read event from ep0");
		return -EIO;
	}

	switch (event.type) {
	case FUNCTIONFS_SETUP:
		/* stall for all setuo requests */
		if (event.u.setup.bRequestType & USB_DIR_IN)
			(void) write(ep0, NULL, 0);
		else
			(void) read(ep0, NULL, 0);
		break;

	case FUNCTIONFS_ENABLE:
		*connected = 1;
		break;

	case FUNCTIONFS_DISABLE:
		*connected = 0;
		break;

	default:
		break;
	}

	return 0;
}

/* main chat function */
void do_chat(int *ep)
{
	int connected = 0;
	int len;
	char *buf;
	int ret;

	printf("Waiting for connection...\n");

	while (1) {
		printf("Waiting for connection...\n");

		while (!connected) {
			ret = handle_ep0(ep[0]);
			if (ret < 0)
				return ret;
		}
		printf("Chat started.\n");
		while (connected) {
			ret = recv_message(ep[EP_OUT_IDX], &M);
			if (ret < 0) {
				if (ret == -ECONNRESET) {
					printf("Connection lost.");
					break;
				}
				return;
			}

			printf("host> %s\n", M.line_buf);

			printf("device> ");
			buf = fgets(M.line_buf, sizeof(M.line_buf), stdin);
			if (!buf) {
				report_error("I/O error in fgets");
				return;
			}

			len = strlen(buf);
			if (buf[len - 1] == '\n')
				buf[len - 1] = '\0';

			if (!strcmp(EXIT_COMMAND, M.line_buf))
				break;

			ret = send_message(ep[EP_IN_IDX], &M);
			if (ret < 0) {
				if (ret == -ECONNRESET) {
					printf("Connection lost.");
					break;
				}
				return;
			}

		}

	}
}

int main(int argc, char **argv)
{
	int ep[3];
	int event_fd;
	io_context_t ctx;
	int ret;

	/* Check if we received ffs mount point */
	if (argc != 2) {
		printf("ffs directory not specified!\n");
		return 1;
	}

	ret = prepare_ffs(argv[1], ep);
	if (ret < 0) {
		report_error("Unable to prepare ffs: %d", ret);
		goto out;
	}

	/*
	 * Now we have all required endpoints
	 * so we can start our communication
	 */
	do_chat(ep, &ctx, event_fd);

	cleanup_ffs(ep);
out:
	return ret;
}
