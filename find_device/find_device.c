#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <libusb.h>

#define MAX_STR_LEN 100
#define DESIRED_VID 0x04e8 /* Samsung Electronics Co., Ltd */
#define DESIRED_PID 0xe1ce /* Non existing product */
#define DESIRED_MANUFACTURER "Samsung"

#define report_error(...) do {			\
		fprintf(stderr, __VA_ARGS__);	\
		fputc('\n', stderr);			\
	} while (0)

/*
 * TODO: Implement this function
 *
 * Called for each device in the list, check if passed device is the
 * one we are looking for.
 *
 * Return handle to opened device or NULL
 * if device doesn't match
 */
libusb_device_handle *device_match(libusb_device *dev)
{
	struct libusb_device_descriptor desc;
	libusb_device_handle *dh = NULL;
	char str_buf[MAX_STR_LEN];
	int ret = -EINVAL;

	/*
	 * TODO: Get device descriptor and check if device has
	 * suitable idVendor and idProduct. Remember to handle
	 * error condition.
	 *
	 * int libusb_get_device_descriptor()
	 */
	ret = libusb_get_device_descriptor(dev, &desc);
	if (ret < 0)
		return NULL;

	if (desc.idVendor != DESIRED_VID || desc.idProduct != DESIRED_PID)
		return NULL;

	/*
	 * If VID and PID match let's open the device
	 * and check manufacturer string
	 */
	ret = libusb_open(dev, &dh);
	if (ret) {
		report_error("Unable to open device");
		return NULL;
	}

	/*
	 * TODO: Get manufacturer ASCII string and check if
	 * it matches DESIRED_MANUFACTURER
	 *
	 * Hint: Remember to use iManufacturer field from device
	 * descriptor
	 *
	 * int libusb_get_string_descriptor_ascii()
	 * int strcmp()
	 */
	ret = libusb_get_string_descriptor_ascii(dh, desc.iManufacturer, (unsigned char *)str_buf, sizeof(str_buf));
	if (ret < 0) {
		/*
		 * TODO: Remember that you have opened a device
		 *
		 * void libusb_close()
		 */
		goto close_handle;
	}

	if (strcmp(str_buf, DESIRED_MANUFACTURER) != 0)
		goto close_handle;

	return dh;
close_handle:
	libusb_close(dh);
	return NULL;
}

/* Already implemented; goto main */
void  print_configuration_string(libusb_device_handle *dh)
{
	struct libusb_config_descriptor *desc;
	char str_buf[MAX_STR_LEN];
	libusb_device *dev = libusb_get_device(dh);
	int string_id;
	int ret;

	ret = libusb_get_config_descriptor(dev, 0, &desc);
	if (ret < 0) {
		report_error("Unable to get config desc: %d", ret);
		return;
	}
	string_id = desc->iConfiguration;
	libusb_free_config_descriptor(desc);

	ret = libusb_get_string_descriptor_ascii(dh, string_id,
						 (unsigned char*)str_buf, sizeof(str_buf));
	if (ret < 0) {
		report_error("Unable to get config string");
		return;
	}

	printf("Configuration string: %s\n", str_buf);
}

int main(int argc, char **argv)
{
	libusb_context *ctx;
	libusb_device **devices;
	ssize_t ndevices;
	libusb_device_handle *suitable_device = NULL;
	int i;
	int ret;

	ret = libusb_init(&ctx);
	if (ret) {
		report_error("Unable to initialize libusb");
		ret = -EINVAL;
		goto out;
	}

	/*
	 * TODO: Get list of all devices in system
	 *
	 * ssize_t libusb_get_device_list()
	 */
	ndevices = libusb_get_device_list(ctx, &devices);
	if (ndevices < 0) {
		report_error("Unable to get device list");
		ret = -EINVAL;
		goto cleanup;
	}

	for (i = 0; i < ndevices; ++i) {
		suitable_device = device_match(devices[i]);
		if (suitable_device)
			break;
	}

	/* 1 to also unref devices */
	libusb_free_device_list(devices, 1);

	if (!suitable_device) {
		report_error("Suitable device not found!");
		goto cleanup;
	}

	print_configuration_string(suitable_device);

	libusb_close(suitable_device);
cleanup:
	libusb_exit(ctx);
out:
	return ret;
}
