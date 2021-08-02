# makefileё

TARGET	:= libcldap++
CC	:= g++

LIBS	:= -lldap -llber
CFLAGS	:= -std=c++14 -fPIC -Wall -I .

ifdef DEBUG
CFLAGS	:= $(CFLAGS) -O0 -g -pedantic -DWITH_DEBUG
else
CFLAGS	:= -O2 $(CFLAGS)
endif

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
