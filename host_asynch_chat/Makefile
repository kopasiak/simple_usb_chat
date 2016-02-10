objs = host_achat.o find_interface.o

CFLAGS = -Wall -O2 -c
LDFLAGS = -laio -flto

CFLAGS += `pkg-config --cflags libusb-1.0`
LDFLAGS += `pkg-config --libs libusb-1.0`

all: host_achat

host_achat: $(objs)
	gcc $(objs) -o host_achat $(LDFLAGS)

%.o : %.c
	gcc $(CFLAGS) -c $< -o $@

clean:
	rm -rf host_achat *.o
