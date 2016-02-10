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

#include <libusb.h>

#define EXIT_COMMAND "\\exit"
#define MAX_LINE_LENGTH 1024*8 /* 8 KB should be enough for single line */

#define report_error(...) do {			\
		fprintf(stderr, __VA_ARGS__);	\
		fputc('\n', stderr);		\
	} while (0)

/* Data structure for our message */
struct message {
	uint16_t length;
	char line_buf[MAX_LINE_LENGTH];
} __attribute((packed));

/*
 * helper structure which represents transfer
 * of single message in our chat protocol
 */
struct transfer {
	struct libusb_transfer *length_transfer;
	struct libusb_transfer *buf_transfer;
	struct message message;
	int in_progress;
};

/* Indicates if host_prompt is currently present */
int host_prompt;

/*************** A set functions implemented in other file ***************/

/* Find suitable device along all devices in system and open it */
libusb_device_handle *find_suitable_device(libusb_device **devices);

/* Check if given interface match our needs */
int interface_match(libusb_device_handle *dh,
		    const struct libusb_interface_descriptor *desc);

/* Fill interface id and in and out endpoint addresses */
void fill_values(const struct libusb_interface_descriptor *desc,
		 unsigned char *interface,
		 unsigned char *ep_in,
		 unsigned char *ep_out);

/*************** This is where the real code starts ***************/


/* Find suitable interface, claim it and fill interface id, and endpoints */
int prepare_chat(libusb_device_handle *dh,
		 unsigned char *interface,
		 unsigned char *ep_in,
		 unsigned char *ep_out)
{
	struct libusb_config_descriptor *desc;
	const struct libusb_interface_descriptor *idesc;
	libusb_device *dev = libusb_get_device(dh);
	int i;
	int ret;

	ret = libusb_get_config_descriptor(dev, 0, &desc);
	if (ret < 0) {
		report_error("Unable to get config desc");
		goto out;
	}

	ret = -EINVAL;
	/*
	 * Let's iterate over all interfaces in first configuration
	 * and check if this interface fits our needs
	 */
	for (i = 0; i < desc->bNumInterfaces && ret; ++i) {
		idesc = desc->interface[i].altsetting;
		if (!interface_match(dh, idesc))
			continue;

		fill_values(idesc, interface, ep_in, ep_out);
		ret = libusb_claim_interface(dh, *interface);
		if (ret) {
			report_error("Unable to claim interface");
			goto out;
		}

		break;
	}

out:
	return ret;
}

/* Alloc single message transfer (2 usb transfers) */
struct transfer *alloc_transfer()
{
	struct transfer *t;

	t = malloc(sizeof(*t));
	if (!t)
		goto out;

	t->length_transfer = libusb_alloc_transfer(0);
	if (!t->length_transfer)
		goto free_t;

	t->buf_transfer = libusb_alloc_transfer(0);
	if (!t->length_transfer)
		goto free_length_transfer;

	t->in_progress = 0;
	return t;

free_length_transfer:
	libusb_free_transfer(t->length_transfer);
free_t:
	free(t);
out:
	return NULL;
}

static void free_transfer(struct transfer *t)
{
	if (!t)
		return;

	if (t->length_transfer)
		libusb_free_transfer(t->length_transfer);

	if (t->buf_transfer)
		libusb_free_transfer(t->buf_transfer);

	free(t);
}

/* Send chat message from host to device */
int send_message(struct transfer *out_transfer)
{
	int len;
	int ret;

	len = strlen(out_transfer->message.line_buf) + 1;
	out_transfer->message.length = libusb_cpu_to_le16(len + 2);
	out_transfer->in_progress = 1;

	ret = libusb_submit_transfer(out_transfer->length_transfer);
	if (ret)
		report_error("Unable send message");

	return ret;
}

/* Receive message from device to host */
int recv_message(struct transfer *in_transfer)
{
	int ret;

	in_transfer->in_progress = 1;

	ret = libusb_submit_transfer(in_transfer->length_transfer);
	if (ret) {
		in_transfer->in_progress = 0;
		report_error("Unable to receive message");
	}

	return ret;
}

/* Called when any IN transfer has been completed */
void in_complete(struct libusb_transfer *t)
{
	int ret;
	struct transfer *in_transfer = t->user_data;

	switch (t->status) {
	case LIBUSB_TRANSFER_COMPLETED:
		break;

	case LIBUSB_TRANSFER_CANCELLED:
		/* This means that we are closing our program */
		return;
	default:
		report_error("Failed to receive data");
		exit(-1);
	}

	if (in_transfer->length_transfer == t) {
		/*
		 * We have correctly received length of message
		 * so lets wait for the rest of data.
		 */
		int len;

		len = libusb_le16_to_cpu(in_transfer->message.length) - 2;

		/*
		 * TODO: Set the correct transfer length and submit it
		 *
		 * Hints:
		 * - In case of error, just exit(-1) to keep things simple
		 * - Use in_transfer->buf_transfer to receive message content
		 *
		 * struct libusb_transfer {
		 *  (...)
		 *  int length;
		 *  (...)
		 * };
		 *
		 * int libusb_submit_transfer()
		 */

#warning TODO not implemented

	} else {
		/*
		 * We have the whole message so let's print it
		 * and wait for another one
		 */
		in_transfer->in_progress = 0;
		if (host_prompt)
			printf("<skip>\n");

		printf("device> %s\n", in_transfer->message.line_buf);

		if (host_prompt)
			printf("host> ");

		fflush(stdout);

		ret = recv_message(in_transfer);
		if (ret < 0) {
			report_error("Failed to receive message");
			/* Just die to keep things simple */
			exit(-1);
		}

	}
}

/* Called when any OUT transfer has been completed */
void out_complete(struct libusb_transfer *t)
{
	int ret;
	struct transfer *out_transfer = t->user_data;

	switch (t->status) {
	case LIBUSB_TRANSFER_COMPLETED:
		break;

	case LIBUSB_TRANSFER_CANCELLED:
		/* This means that we are closing our program */
		return;
	default:
		report_error("Failed to receive data");
		exit(-1);
	}

	if (out_transfer->length_transfer == t) {
		/*
		 * We have correctly sent the length,
		 * so let's send now the data.
		 */
		int len;

		len = libusb_le16_to_cpu(out_transfer->message.length) - 2;

		/*
		 * TODO: Set the correct transfer length and submit it
		 *
		 * Hints:
		 * - In case of error, just exit(-1) to keep things simple
		 * - Use out_transfer->buf_transfer to send the data
		 *
		 * struct libusb_transfer {
		 *  (...)
		 *  int length;
		 *  (...)
		 * };
		 *
		 * int libusb_submit_transfer()
		 */

#warning TODO not implemented

	} else {
		/*
		 * We have the whole message so let's print
		 * the prompt once again.
		 */
		out_transfer->in_progress = 0;
		host_prompt = 1;
		printf("host> ");
		fflush(stdout);
		/* Rest of the work will be done in do_chat() */
	}
}

/* prepare one in and one out transfer */
int prepare_transfers(libusb_device_handle *dh, unsigned char in_ep,
		      unsigned char out_ep, struct transfer **in_transfer,
		      struct transfer **out_transfer)
{
	struct transfer *it, *ot;

	/* incomming */
	it = alloc_transfer();
	if (!it)
		goto out;

	/* outgoing */
	ot = alloc_transfer();
	if (!ot)
		goto free_it;

	/*
	 * TODO: Fill the USB IN transfers
	 *
	 * Hints:
	 * - use in_ep as endpoint address
	 * - use it->message as buffer for receiving data
	 * - use 2 as length for first transfer
	 * - no matter what you will use as length in second transfer
	 * as it will be overwritten in in_complete()
	 * - use in_complete() as completion callback
	 * - use it as user data as it will be needed later
	 * - use 0 as timeout to wait forever
	 *
	 * void libusb_fill_bulk_transfer()
	 */

#warning TODO not implemented

	/*
	 * TODO: Fill the USB OUT transfers
	 *
	 * Hints:
	 * - use out_ep as endpoint address
	 * - use ot->message as buffer for sending data
	 * - use 2 as length for first transfer
	 * - no matter what you will use as length in second transfer
	 * as it will be overwritten in send_message()
	 * - use out_complete() as completion callback
	 * - use ot as user data as it will be needed later
	 * - use 0 as timeout to wait forever
	 *
	 * void libusb_fill_bulk_transfer()
	 */

#warning TODO not implemented

	*in_transfer = it;
	*out_transfer = ot;
	return 0;

free_it:
	free_transfer(it);
out:
	return -EINVAL;
}

/* main chat function */
void do_chat(libusb_context *ctx, libusb_device_handle *dh,
	     unsigned char ep_in, unsigned char ep_out)
{
	struct transfer *out_transfer;
	struct transfer *in_transfer;
	char *buf;
	int buf_size;
	fd_set rfds, wfds;
	int max_fd;
	const struct libusb_pollfd **pfds;
	int ret;
	int i;
	int len;
	int wait_for_input = 1;
	struct timeval tv = {0, 0};

	ret = prepare_transfers(dh, ep_in, ep_out, &in_transfer, &out_transfer);
	if (ret) {
		report_error("Unable to prepare transfers");
		return;
	}

	/* as input buffer we use the one allocated for out transfer */
	buf = out_transfer->message.line_buf;
	buf_size = sizeof(out_transfer->message.line_buf);

	printf("Chat started. You may say something or type " EXIT_COMMAND
	       " to exit...\n");
	host_prompt = 1;
	printf("host> ");
	fflush(stdout);

	ret = recv_message(in_transfer);
	if (ret < 0) {
		report_error("Unable to receive message");
		return;
	}

	/* our main program loop */
	while (1) {
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		/* we wait for input only if we have free out transfer */
		if (wait_for_input)
			FD_SET(STDIN_FILENO, &rfds);
		max_fd = STDIN_FILENO;

		/*
		 * This is just because it was simplier.
		 * Real code should use:
		 * libusb_set_pollfd_notifiers()
		 */
		pfds = libusb_get_pollfds(ctx);
		if (!pfds) {
			report_error("Unable to get libusb fds");
			goto cleanup;
		}

		/*
		 * Iterate over all fds received from libusb and add
		 * them to suitable fd set for later select()
		 */
		for (i = 0; pfds[i]; ++i) {
			if (pfds[i]->events & POLLIN)
				FD_SET(pfds[i]->fd, &rfds);

			if (pfds[i]->events & POLLOUT)
				FD_SET(pfds[i]->fd, &wfds);

			max_fd = pfds[i]->fd > max_fd ? pfds[i]->fd : max_fd;
		}

		/* we block here and wait for some events */
		ret = select(max_fd + 1, &rfds, &wfds, NULL, NULL);
		if (ret < 0) {
			if (errno == EINTR)
				goto next_iter;
			report_error("Unable to use select");
			goto cleanup;;
		}

		/* first of all we check if we have some libusb events */
		for (i = 0; pfds[i]; ++i) {
			if (!FD_ISSET(pfds[i]->fd, &rfds) &&
			    !FD_ISSET(pfds[i]->fd, &wfds))
				continue;

			/*
			 * TODO: tell libusb to handle some events now
			 *
			 * int libusb_handle_events_timeout_completed();
			 */

#warning TODO not implemented

			break;
		}

		if (!out_transfer->in_progress) {
			wait_for_input = 1;

			/* All libusb events are now handled */
			if (FD_ISSET(STDIN_FILENO, &rfds)) {
				host_prompt = 0;
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
	next_iter:
	/*	libusb_free_pollfds(pfds); should be used if available */
		free((void *)pfds);
	}

cleanup:
	/*	libusb_free_pollfds(pfds); should be used if available */
	free((void *)pfds);
	/* we don't care if any of them is active, just cancel them */
	libusb_cancel_transfer(in_transfer->length_transfer);
	libusb_cancel_transfer(in_transfer->buf_transfer);
	libusb_cancel_transfer(out_transfer->length_transfer);
	libusb_cancel_transfer(out_transfer->buf_transfer);
	/* To allow callbacks call */
	libusb_handle_events_timeout_completed(ctx, &tv, NULL);

	free_transfer(in_transfer);
	free_transfer(out_transfer);
}

void cleanup_chat(libusb_device_handle *dh, unsigned char interface)
{
	libusb_release_interface(dh, interface);
}

int main(int argc, char **argv)
{
	libusb_device **devices;
	libusb_device_handle *suitable_device;
	libusb_context *ctx;
	ssize_t ndevices;
	unsigned char interface;
	unsigned char ep_in;
	unsigned char ep_out;
	int ret;

	ret = libusb_init(&ctx);
	if (ret) {
		report_error("Unable to initialize libusb");
		ret = -EINVAL;
		goto out;
	}

	ndevices = libusb_get_device_list(ctx, &devices);
	if (ndevices < 0) {
		report_error("Unable to initialize libusb");
		ret = -EINVAL;
		goto cleanup;
	}

	/* Check if any of them fits our needs */
	suitable_device = find_suitable_device(devices);
	libusb_free_device_list(devices, 1);
	if (!suitable_device) {
		report_error("Suitable device not found!");
		goto cleanup;
	}

	/*
	 * At this line we have our device so let's
	 * prepare it for our chat.
	 * In interface we have bInterfaceNumber
	 * and in ep_in, ep_out we have suitable
	 * bEndpointAddress of IN and OUT endpoint respectively
	 */
	ret = prepare_chat(suitable_device, &interface, &ep_in, &ep_out);
	if (ret) {
		report_error("Unable to prepare a chat");
		goto close_device;
	}

	do_chat(ctx, suitable_device, ep_in, ep_out);

	cleanup_chat(suitable_device, interface);

close_device:
	libusb_close(suitable_device);
cleanup:
	libusb_exit(ctx);
out:
	return ret;
}
