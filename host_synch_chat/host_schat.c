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

/* One global buffer for sending and receiving */
struct message M;


/*************** A set functions implemented in other file ***************/


/* Finds a suitable device along all devices in system and opens it */
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
	 * and check if any of them fits our needs
	 */
	for (i = 0; i < desc->bNumInterfaces && ret; ++i) {
		idesc = desc->interface[i].altsetting;
		if (!interface_match(dh, idesc))
			continue;

		/* At this point we know that we have a match */

		fill_values(idesc, interface, ep_in, ep_out);

		/*
		 * TODO: claim interface before usage
		 *
		 * Hints:
		 * ep_in - bEndpointAddress of IN endpoint
		 * ep_out - bEndpointAddress of OUT endpoint
		 * interface - bInterfaceNumber of found interface
		 *
		 * int libusb_claim_interface()
		 */
#warning TODO not implemented

		if (ret < 0) {
			report_error("Unable to claim interface");
			goto out;
		}

		break;
	}

out:
	return ret;
}

/* sends both transfers of particular OUT message in blocking mode */
int send_message(libusb_device_handle *dh, struct message *message, unsigned char ep)
{
	int len;
	int transferred;
	int ret = 0;

	len = strlen(message->line_buf) + 1;
	message->length = libusb_cpu_to_le16(len + 2);

	/*
	 * TODO: Send message using 2 USB transfers:
	 * - first one which contains only length of message
	 * - second one which contains user input
	 *
	 * Hints:
	 * Use 0 as a timeout to wait forever
	 * As it's only tutorial you may ignore the value returned
	 * in &transferred, but remember to check it in commercial code
	 *
	 * int libusb_bulk_transfer()
	 */
#warning TODO not implemented

	return ret;
}

/* receives both transfers of particular IN message in blocking mode */
int recv_message(libusb_device_handle *dh, struct message *message, unsigned char ep)
{
	int len;
	int transferred;
	int ret = 0;

	/*
	 * TODO: Receive message using 2 USB transfers:
	 * - first which is only 2 bytes long to receive only the
	 * length of message
	 * - second one which contains text of incomming message
	 * Remember to pass suitable length of second transfer.
	 *
	 * Hints:
	 * - Remember to convert from litle endian to cpu
	 * - Use 0 as a timeout to wait forever
	 * - As it's only tutorial you may ignore the value returned
	 * in &transferred, but remember to check it in commercial code
	 * - Use message as buffer for receiving the data
	 *
	 * int libusb_bulk_transfer()
	 * uint16_t libusb_le16_to_cpu()
	 */
#warning TODO not implemented

	return ret;
}

/*
 * main chat function
 * ep_in - bEndpointAddreess of IN ep
 * ep_out - bEndpointAddreess of OUT ep
 * This function is called with suitable interface claimed.
 */
void do_chat(libusb_device_handle *dh, unsigned char ep_in, unsigned char ep_out)
{
	int ret;
	int len;
	char *buf;

	printf("Chat started. You may say something or type " EXIT_COMMAND
	       " to exit...\n");

	while (1) {
		printf("host> ");
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

		ret = send_message(dh, &M, ep_out);
		if (ret < 0) {
			report_error("Unable to send message");
			return;
		}

		/*
		 * TODO: Call recv_message() to wait for incomming message
		 * Hint: Use placed below error handling code
		 */
#warning TODO not implemented

		if (ret < 0) {
			report_error("Unable to receive message");
			return;
		}

		printf("device> %s\n", M.line_buf);

	}
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
	if (ret < 0) {
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
	if (ret < 0) {
		report_error("Unable to prepare a chat");
		goto close_device;
	}

	do_chat(suitable_device, ep_in, ep_out);

	cleanup_chat(suitable_device, interface);

close_device:
	libusb_close(suitable_device);
cleanup:
	libusb_exit(ctx);
out:
	return ret;
}
