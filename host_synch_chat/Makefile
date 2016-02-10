objs = host_schat.o find_interface.o

CFLAGS = -Wall -O2 -c
LDFLAGS = -laio -flto

CFLAGS += `pkg-config --cflags libusb-1.0`
LDFLAGS += `pkg-config --libs libusb-1.0`

all: host_schat

host_schat: $(objs)
	gcc $(objs) -o host_schat $(LDFLAGS)

%.o : %.c
	gcc $(CFLAGS) -c $< -o $@

clean:
	rm -rf host_schat *.o
