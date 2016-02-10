objs = device_achat.o 

CFLAGS = -Wall -O2 -c
LDFLAGS = -laio -flto

LDFLAGS += '-laio'

all: device_achat

device_achat: $(objs)
	gcc $(objs) -o device_achat $(LDFLAGS)

%.o : %.c
	gcc $(CFLAGS) -c $< -o $@

clean:
	rm -rf device_achat *.o
