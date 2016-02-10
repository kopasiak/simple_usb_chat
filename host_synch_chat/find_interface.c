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

#define DESIRED_VID 0x04e8 /* Samsung Electronics Co., Ltd */
#define DESIRED_PID 0xe1ce /* Non existing product */
#define DESIRED_MANUFACTURER "Samsung"
#define DESIRED_INTERFACE "loop input to output"
#define MAX_STR_LEN 100

#define report_error(...) do {			\
		fprintf(stderr, __VA_ARGS__);	\
		fputc('\n', stderr);			\
	} while (0)

/*
 * Simple wraper for opening a USB device
 * Returns device handle or NULL when unable to open
 */
libusb_device_handle *open_device(libusb_device *dev)
{
	libusb_device_handle *dh;
	int ret;

	/* Just open the device and check the result */
	ret = libusb_open(dev, &dh);
	if (ret) {
		report_error("Unable to open device");
		dh = NULL;
	}

	return dh;
}

void fill_values(const struct libusb_interface_descriptor *desc,
		 unsigned char *interface,
		 unsigned char *ep_in,
		 unsigned char *ep_out)
{
	int i;

	*interface = desc->bInterfaceNumber;

	for (i = 0; i < desc->bNumEndpoints; ++i) {
		if ((desc->endpoint[i].bEndpointAddress & (1 << 7))
		    == LIBUSB_ENDPOINT_IN)
			*ep_in = desc->endpoint[i].bEndpointAddress;
		else
			*ep_out = desc->endpoint[i].bEndpointAddress;
	}
}

/*
 * Check if this is the device we are looking for.
 * Return handle to opened device or NULL if device don't match
 */
libusb_device_handle *device_match(libusb_device *dev)
{
	struct libusb_device_descriptor desc;
	libusb_device_handle *dh;
	char str_buf[MAX_STR_LEN];
	int ret;

	/*
	 * Get device descriptor and check if device has
	 * suitable idVendor and idProduct
	 */
	ret = libusb_get_device_descriptor(dev, &desc);
	if (ret) {
		report_error("Unable to get device descriptor");
		goto out;
	}

	if (desc.idVendor != DESIRED_VID || desc.idProduct != DESIRED_PID)
		goto out;

	/*
	 * If VID and PID match let's open the device
	 * and check manufacturer string
	 */
	dh = open_device(dev);
	if (!dh)
		goto out;

	/* Just get the suitable string based on iManufacturer */
	ret = libusb_get_string_descriptor_ascii(dh, desc.iManufacturer,
						 (unsigned char*) str_buf, sizeof(str_buf));
	if (ret < 0) {
		report_error("Unable to get manufacturer string");
		goto out;
	}

	/* Check if this string match */
	if (strcmp(str_buf, DESIRED_MANUFACTURER))
		goto out;

	return dh;
out:
	return NULL;
}

/* Iterate over all devices and check if we have a suitable one */
libusb_device_handle *find_suitable_device(libusb_device **devices)
{
	libusb_device_handle *handle;

	for (; *devices; ++devices) {
		handle = device_match(*devices);
		if (handle)
			return handle;
	}

	return NULL;
}
 
int interface_match(libusb_device_handle *dh,
		    const struct libusb_interface_descriptor *desc)
{
	char str_buf[MAX_STR_LEN];
	int i;
	int ret;
	int in_found = 0;
	int out_found = 1;

	if (desc->bInterfaceClass != LIBUSB_CLASS_VENDOR_SPEC)
		goto out;

	if (desc->bNumEndpoints != 2)
		goto out;

	for (i = 0; i < desc->bNumEndpoints; ++i) {
		if ((desc->endpoint[i].bmAttributes & 0x3)
		    != LIBUSB_TRANSFER_TYPE_BULK)
			goto out;

		if ((desc->endpoint[i].bEndpointAddress & (1 << 7))
		    == LIBUSB_ENDPOINT_IN)
			in_found = 1;
		else
			out_found = 1;
	}

	if (!(in_found && out_found))
		goto out;

	ret = libusb_get_string_descriptor_ascii(dh, desc->iInterface,
						 (unsigned char *)str_buf,
						 sizeof(str_buf));
	if (ret < 0) {
		report_error("Unable to get interface string");
		goto out;
	}

	return !strcmp(str_buf, DESIRED_INTERFACE);
out:
	return 0;
}
