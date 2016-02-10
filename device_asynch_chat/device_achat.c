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


#include <libaio.h>
#include <linux/usb/functionfs.h>

#define EP_IN_IDX 1
#define EP_OUT_IDX 2

#define MAX(a, b) ((a) > (b) ? (a) : (b))

#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})

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

/*
 * In previous workshops we used Loopback function
 * which has exactly this string. To make this
 * workshop compatible with all previous workshops
 * we declare the same string as Loopback function
 */
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

/*
 * As there is no fully-functional equivalent of libusb for the device
 * side we define some helper structures to make our life easier and
 * use them as some minimal equivalent of such library
 */
struct ffs_request;

typedef void (*ffs_complete_t)(struct ffs_request *);

/* Possible states of ffs request */
enum {
	FFS_REQ_COMPLETED = 0,
	FFS_REQ_IN_PROGRESS = 1,
	FFS_REQ_ERROR = 2,
	FFS_REQ_CANCELLED = 3,
};

/* Represents single usb request which can be transfered using ffs */
struct ffs_request {
	struct iocb iocb;
	unsigned char *buf;
	ssize_t length;
	void *context;
	int status;
	int actual;
	ffs_complete_t complete;
};

/* Use container_of() to get ffs_request from iocb */
static inline struct ffs_request *to_ffs_request(struct iocb *_iocb)
{
	return container_of(_iocb, struct ffs_request, iocb);
}

/*
 * helper structure which represents transfer
 * of single message in our chat protocol
 */
struct transfer {
	struct ffs_request *length_request;
	struct ffs_request *buf_request;
	struct message message;
	int in_progress;
	io_context_t *ctx;
};

/* Indicates if device prompt is currently present */
int device_prompt;

/******************** Basic implementation of our library *********************/

/* allocates single ffs_request */
struct ffs_request *alloc_ffs_request()
{
	struct ffs_request *req;

	req = malloc(sizeof(*req));
	if (!req)
		goto out;

	memset(req, 0, sizeof(*req));
out:
	return req;
}

void free_ffs_request(struct ffs_request *req)
{
	free(req);
}

/*
 * Schedules ffs request to be asynchronously transfered.
 * A little bit device side equivalent to libusb_submit_transfer()
 */
int submit_ffs_request(io_context_t *ctx, struct ffs_request *req)
{
	int ret;
	struct iocb *iocb = &req->iocb;

	iocb->u.c.nbytes = req->length;

	ret = io_submit(*ctx, 1, &iocb);
	if (ret < 0)
		return ret;

	req->status = FFS_REQ_IN_PROGRESS;
	return 0;
}

/*
 * Fill given ffs request using provided data
 * A little bit device side equivalent of libusb_fill_bulk_transfer()
 */
void fill_ffs_request(struct ffs_request *req, int dir, int ep, int event_fd,
		      unsigned char *buf, int length, ffs_complete_t complete,
		      void *context)
{
	struct iocb *iocb = &req->iocb;

	req->buf = buf;
	req->length = length;

	/*
	 * TODO: prepare read/write operation
	 *
	 * Hints:
	 * - Use dir param to determine type of operation
	 * - Remember that we are on the device side
	 * - USB_DIR_IN - transfer data from device to host (write())
	 * - USB_DIR_OUT - transfer data from host to device (read())
	 *
	 * int io_prep_pwrite()
	 * int io_prep_pread()
	 */
	if (dir == USB_DIR_IN)
		io_prep_pwrite(iocb, ep, buf, length, 0);
	else
		io_prep_pread(iocb, ep, buf, length, 0);


	io_set_eventfd(iocb, event_fd);

	req->complete = complete;
	req->status = 0;
	req->actual = 0;
	req->context = context;
}

/* Cancel choosen ffs_request */
void cancel_ffs_request(io_context_t *ctx, struct ffs_request *req)
{
	struct io_event e;
	if (req->status != FFS_REQ_IN_PROGRESS)
		return;

	io_cancel(*ctx, &req->iocb, &e);
	req->status = FFS_REQ_CANCELLED;
	req->actual = 0;
	if (req->complete)
		req->complete(req);
}

/* Handle all pending aio events */
int handle_events(io_context_t *ctx, int event_fd)
{
	int ret;
	int i;
	uint64_t ev_cnt;
	struct io_event e[2];
	struct ffs_request *req;

	ret = read(event_fd, &ev_cnt, sizeof(ev_cnt));
	if (ret < 0) {
		report_error("unable to read eventfd");
		return -errno;
	}

	ret = io_getevents(*ctx, 1, ev_cnt, e, NULL);
	if (ret < 0)
		return ret;

	for (i = 0; i < ret; ++i) {
		long res = (long)e[i].res;

		req = to_ffs_request(e[i].obj);
		if (res >= 0)
			req->status = FFS_REQ_COMPLETED;
		else
			req->status = FFS_REQ_ERROR;

		req->actual = res;

		if (req->complete)
			req->complete(req);
	}

	return 0;
}

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

	/*
	 * TODO: Provide descriptors and strings
	 *
	 * Hints:
	 * - Descriptors and strings are defined on the top of this file
	 * - You should simply two time call write() function using ep[0] fd
	 *
	 * ssize_t write(int fd, const void *buf, size_t count)
	 * sizeof()
	 */
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

/* Initialize aio context and create event fd */
int init_aio(int n_requests, io_context_t *ctx, int *event_fd)
{
	int ret;

	memset(ctx, 0, sizeof(*ctx));

	ret = io_setup(n_requests, ctx);
	if (ret < 0) {
		report_error("Unable to setup aio context");
		return ret;
	}

	*event_fd = eventfd(0, 0);
	if (*event_fd < 0) {
		report_error("Unable to open event fd");
		io_destroy(*ctx);
		ret = -errno;
	}

	return ret;
}

/* Cleanup aio context and close event fd */
void cleanup_aio(io_context_t *ctx, int event_fd)
{
	close(event_fd);
	io_destroy(*ctx);
}

/******************** Protocol specific implementation **********************/

/* Alloc single message transfer (2 ffs requests) */
struct transfer *alloc_transfer()
{
	struct transfer *t;

	t = malloc(sizeof(*t));
	if (!t)
		goto out;

	t->length_request = alloc_ffs_request();
	if (!t->length_request)
		goto free_t;

	t->buf_request = alloc_ffs_request();
	if (!t->length_request)
		goto free_length_request;

	t->in_progress = 0;
	return t;

free_length_request:
	free_ffs_request(t->length_request);
free_t:
	free(t);
out:
	return NULL;
}

/* Free the memory allocated for requests */
static void free_transfer(struct transfer *t)
{
	if (!t)
		return;

	if (t->length_request)
		free_ffs_request(t->length_request);

	if (t->buf_request)
		free_ffs_request(t->buf_request);

	free(t);
}

/* Send chat message from device to host*/
int send_message(struct transfer *out_transfer)
{
	int len;
	int ret;

	len = strlen(out_transfer->message.line_buf) + 1;
	out_transfer->message.length = htole16(len + 2);
	out_transfer->in_progress = 1;

	ret = submit_ffs_request(out_transfer->ctx,
				 out_transfer->length_request);
	if (ret)
		report_error("Unable send message");

	return ret;
}

/* Receive message from host to device */
int recv_message(struct transfer *in_transfer)
{
	int ret;

	in_transfer->in_progress = 1;

	ret = submit_ffs_request(in_transfer->ctx,
				 in_transfer->length_request);
	if (ret)
		report_error("Unable to receive message");

	return ret;
}

/* Called when message has been received  */
void in_complete(struct ffs_request *req)
{
	int ret;
	struct transfer *in_transfer = req->context;

	switch (req->status) {
	case FFS_REQ_COMPLETED:
		break;
	case FFS_REQ_CANCELLED:
		/* This means that we are closing our program */
		return;
	default:
		report_error("Failed to receive data");
		/* Just die to keep things simple */
		exit(-1);
	}

	if (in_transfer->length_request == req) {
		/*
		 * We have correctly received length of message
		 * lets wait for rest of data.
		 */
		int len;

		len = le16toh(in_transfer->message.length) - 2;

		/*
		 * TODO: Set the correct request length and submit it
		 *
		 * Hints:
		 * - In case of error, just exit(-1) to keep things simple
		 * - Use in_transfer->buf_request to receive message content
		 *
		 * struct ffs_request {
		 *  (...)
		 *  ssize_t length;
		 *  (...)
		 * };
		 *
		 * int submit_ffs_request()
		 */
		in_transfer->buf_request->length = len;

		ret = submit_ffs_request(in_transfer->ctx,
					 in_transfer->buf_request);
		if (ret < 0) {
			report_error("Failed to submit transfer");
			/* Just die to keep things simple */
			exit(-1);
		}
	} else {
		/*
		 * We have the whole message so let's print it
		 * and wait for another one
		 */
		in_transfer->in_progress = 0;
		if (device_prompt)
			printf("<skip>\n");

		printf("host> %s\n", in_transfer->message.line_buf);

		if (device_prompt)
			printf("device> ");

		fflush(stdout);

		ret = recv_message(in_transfer);
		if (ret < 0) {
			report_error("Failed to receive message");
			/* Just die to keep things simple */
			exit(-1);
		}

	}
}

/* Called when we successfully send any message to host */
void out_complete(struct ffs_request *req)
{
	int ret;
	struct transfer *out_transfer = req->context;

	switch (req->status) {
	case FFS_REQ_COMPLETED:
		break;
	case FFS_REQ_CANCELLED:
		/* This means that we are closing our program */
		return;
	default:
		report_error("Failed to send data");
		/* Just die to keep things simple */
		exit(-1);
	}

	if (out_transfer->length_request == req) {
		/*
		 * We have correctly send the length,
		 * so let's send now the data.
		 */
		int len;

		len = le16toh(out_transfer->message.length) - 2;
		/*
		 * TODO: Set the correct request length and submit it
		 *
		 * Hints:
		 * - In case of error, just exit(-1) to keep things simple
		 * - Use out_transfer->buf_request to send the data
		 *
		 * struct ffs_request {
		 *  (...)
		 *  ssize_t length;
		 *  (...)
		 * };
		 *
		 * int submit_ffs_request()
		 */
		out_transfer->buf_request->length = len;
		ret = submit_ffs_request(out_transfer->ctx,
					 out_transfer->buf_request);
		if (ret < 0) {
			report_error("Failed submit transfer");
			/* Just die to keep things simple */
			exit(-1);
		}
	} else {
		/*
		 * We have the whole message so let's print
		 * the prompt once again.
		 */
		out_transfer->in_progress = 0;
		device_prompt = 1;
		printf("device> ");
		fflush(stdout);
		/* Rest of the work will be done in do_chat() */
	}
}

/* prepare one in and one out chat transfers */
int prepare_transfers(int *ep, io_context_t *ctx, int event_fd,
		      struct transfer **in_transfer,
		      struct transfer **out_transfer)
{
	struct transfer *it, *ot;

	/* In our chat protocol we understand IN transfer
	 *  as receiving data, but on USB level that's are OUT
	 *  requests as data is being transfered from host to device
	 */
	it = alloc_transfer();
	if (!it)
		goto out;

	ot = alloc_transfer();
	if (!ot)
		goto free_it;

	/*
	 * TODO: Fill the USB OUT requests (for chat IN transfer)
	 *
	 * Hints:
	 * - We are on device side so we receives the data when
	 * USB request direction is OUT (from host to device)
	 * - use ep[EP_OUT_IDX] as endpoint file descriptor
	 * - use it->message as buffer for receiving data
	 * - use 2 as length for first request
	 * - no matter what you will use as length in second request
	 * as it will be overwritten in in_complete()
	 * - use in_complete() as completion callback
	 * - use it as user data as it will be needed later
	 *
	 * void fill_ffs_request()
	 */
	fill_ffs_request(it->length_request, USB_DIR_OUT, ep[EP_OUT_IDX],
			 event_fd, (unsigned char *)&it->message.length, 2,
			 in_complete, it);

	fill_ffs_request(it->buf_request, USB_DIR_OUT, ep[EP_OUT_IDX],
			 /*
			  * Actual length will be filled after
			  * receiving it from host
			  */
			 event_fd, (unsigned char *)&it->message.line_buf, 0,
			 in_complete, it);

	/*
	 * TODO: Fill the USB IN requests (for chat OUT transfer)
	 *
	 * Hints:
	 * - We are on device side so we send the data when
	 * USB request direction is IN (from device to host)
	 * - use ep[EP_IN_IDX] as endpoint file descriptor
	 * - use ot->message as buffer for receiving data
	 * - use 2 as length for first request
	 * - no matter what you will use as length in second request
	 * as it will be overwritten in out_complete()
	 * - use in_complete() as completion callback
	 * - use ot as user data as it will be needed later
	 *
	 * void fill_ffs_request()
	 */
	fill_ffs_request(ot->length_request, USB_DIR_IN, ep[EP_IN_IDX],
			 event_fd, (unsigned char *)&ot->message.length, 2,
			 out_complete, ot);

	fill_ffs_request(ot->buf_request, USB_DIR_IN, ep[EP_IN_IDX],
			 /*
			  * Actual length will be filled after
			  * reading user input
			  */
			 event_fd, (unsigned char *)&ot->message.line_buf, 0,
			 out_complete, ot);


	it->ctx = ctx;
	ot->ctx = ctx;
	*in_transfer = it;
	*out_transfer = ot;
	return 0;

free_it:
	free_transfer(it);
out:
	return -EINVAL;
}

/* Handle events generated by kernel and provided via ep0 */
int handle_ep0(int *ep, struct transfer *in_transfer, int *connected)
{
	struct usb_functionfs_event event;
	int ret;

	ret = read(ep[0], &event, sizeof(event));
	if (!ret) {
		report_error("unable to read event from ep0");
		return -EIO;
	}

	switch (event.type) {
	case FUNCTIONFS_SETUP:
		/* stall for all setuo requests */
		if (event.u.setup.bRequestType & USB_DIR_IN)
			(void) write(ep[0], NULL, 0);
		else
			(void) read(ep[0], NULL, 0);
		break;

	case FUNCTIONFS_ENABLE:
		*connected = 1;
		printf("Chat started. You may say something or type " EXIT_COMMAND
		       " to exit...\n");
		device_prompt = 1;
		printf("device> ");
		fflush(stdout);

		/*
		 * TODO: Start receiving messages from host
		 *
		 * int recv_message()
		 */
		ret = recv_message(in_transfer);
		if (ret < 0) {
			report_error("Unable to receive message");
			return ret;
		}
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
void do_chat(int *ep, io_context_t *ctx, int event_fd)
{
	struct transfer *out_transfer;
	struct transfer *in_transfer;
	char *buf;
	int buf_size;
	fd_set rfds;
	int max_fd;
	int ret;
	int len;
	int wait_for_input = 1;
	int connected = 0;

	/* prepare our chat transfers */
	ret = prepare_transfers(ep, ctx, event_fd, &in_transfer, &out_transfer);
	if (ret) {
		report_error("Unable to prepare transfers");
		return;
	}

	/*
	 * We are on the device side so we use IN requests for sending
	 * data from device to host but still it is out transfer in our
	 * chat protocol
	 */
	buf = out_transfer->message.line_buf;
	buf_size = sizeof(out_transfer->message.line_buf);

	printf("Waiting for connection...\n");
	fflush(stdout);

	/* We cannot submit any transfer here as we may be not connected */

	/* our main program loop */
	while (1) {
		FD_ZERO(&rfds);
		/* we wait for input only if we have free out transfer */
		if (wait_for_input)
			FD_SET(STDIN_FILENO, &rfds);
		max_fd = STDIN_FILENO;

		/*
		 * We should wait for events only on ep0 and eventfd
		 * DON'T add epX (x != 0) to poll()!
		 */
		FD_SET(ep[0], &rfds);
		max_fd = MAX(ep[0], max_fd);

		FD_SET(event_fd, &rfds);
		max_fd = MAX(event_fd, max_fd);

		/* we block here and wait for some events */
		ret = select(max_fd + 1, &rfds, NULL, NULL, NULL);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			report_error("Unable to use select");
			goto cleanup;;
		}

		/* first of all we check if we have some ep0 events */
		if (FD_ISSET(ep[0], &rfds)) {
			ret = handle_ep0(ep, in_transfer, &connected);
			if (ret)
				goto cleanup;
		}

		/*
		 * TODO: handle aio events if event_fd
		 * is ready for reading
		 *
		 * FD_ISSET()
		 * int handle_events()
		 */
		if (FD_ISSET(event_fd, &rfds)) {
			ret = handle_events(ctx, event_fd);
			if (ret)
				goto cleanup;
		}

		if (!connected)
			continue;

		if (!out_transfer->in_progress) {
			wait_for_input = 1;

			/* We are connected and all ffs events are handled */
			if (FD_ISSET(STDIN_FILENO, &rfds)) {
				device_prompt = 0;
				/*
				 * we have free out transfer and
				 * user entered some input
				 */
				buf = fgets(buf, buf_size, stdin);
				if (!buf) {
					report_error("I/O error in fgets");
					goto cleanup;
				}

				len = strlen(buf);
				if (buf[len - 1] == '\n')
					buf[len - 1] = '\0';

				if (!strcmp(EXIT_COMMAND, buf))
					goto cleanup;

				ret = send_message(out_transfer);
				if (ret < 0) {
					report_error("Unable to send message");
					goto cleanup;
				}
				wait_for_input = 0;
			}
		}
	}

cleanup:
	/* we don't care if any of them is active, just cancel them */
	cancel_ffs_request(ctx, in_transfer->length_request);
	cancel_ffs_request(ctx, in_transfer->buf_request);
	cancel_ffs_request(ctx, out_transfer->length_request);
	cancel_ffs_request(ctx, out_transfer->buf_request);

	free_transfer(in_transfer);
	free_transfer(out_transfer);
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

	ret = init_aio(2, &ctx, &event_fd);
	if (ret < 0) {
		report_error("Unable to init aio: %d", ret);
		goto close_desc;
	}

	/*
	 * On this line we have all required endpoints
	 * so we can start our communication
	 */
	do_chat(ep, &ctx, event_fd);

	/* Cleanup the context */
	cleanup_aio(&ctx, event_fd);

close_desc:
	cleanup_ffs(ep);
out:
	return ret;
}
