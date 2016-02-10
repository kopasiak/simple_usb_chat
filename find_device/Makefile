
CFLAGS = -Wall -O2 -c
LDFLAGS = -laio -flto

CFLAGS += `pkg-config --cflags libusb-1.0`
LDFLAGS += `pkg-config --libs libusb-1.0`

all: find_device

find_device: find_device.o
	gcc find_device.o -o find_device $(LDFLAGS)

%.o : %.c
	gcc $(CFLAGS) -c $< -o $@

clean:
	rm -rf find_device *.o