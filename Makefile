# makefileё

TARGET = libcldap++
LIBS = -lldap -llber -lcrypto -lssl
CFLAGS = -O2 -Wall -I .

CC = g++

all: examples

examples: $(TARGET).so $(TARGET).a
	make -C examples

$(TARGET).so: $(patsubst %.cpp, %.o, $(wildcard *.cpp))
	$(CC) -shared -fPIC -o $@ $^ $(LIBS)

$(TARGET).a: $(patsubst %.cpp, %.o, $(wildcard *.cpp))
	ar crvs $@ $^

%.o: %.cpp
	$(CC) -c -MD $< $(CFLAGS)

include $(wildcard *.d)

.PHONY: clean

clean:
	rm -f *.a *.so *.d *.o
	make -C examples clean
