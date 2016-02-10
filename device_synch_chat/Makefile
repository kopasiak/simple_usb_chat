objs = device_schat.o 

CFLAGS = -Wall -O2 -c
LDFLAGS = -laio -flto

all: device_schat

device_schat: $(objs)
	gcc $(objs) -o device_schat $(LDFLAGS)

%.o : %.c
	gcc $(CFLAGS) -c $< -o $@

clean:
	rm -rf device_schat *.o
