# makefile

TARGETS	:= test ping groups group_ldap_acl cat
CC	:= g++

LIBS	:= -lldap -llber ../libcldap++.a
CFLAGS	:= -std=c++0x -Wall -I..


ifdef DEBUG
CFLAGS  := $(CFLAGS) -O0 -g -pedantic -DWITH_DEBUG
else
CFLAGS  := -O2 $(CFLAGS)
endif

all: $(TARGETS)

$(TARGETS): $(addsuffix .cpp, $(TARGETS)) ../libcldap++.a
	$(CC) -c $@.cpp $(CFLAGS)
	$(CC) -o $@ $@.o $(LIBS)

.PHONY: clean

clean:
	rm -f *.o $(TARGETS)
