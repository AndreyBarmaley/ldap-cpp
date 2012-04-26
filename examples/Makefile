# makefile

TARGETS = test ping groups group_ldap_acl
LIBS = -lldap -llber ../libcldap++.a
CFLAGS = -O2 -Wall -I..

CC = g++

all: $(TARGETS)

$(TARGETS): $(addsuffix .cpp, $(TARGETS)) ../libcldap++.a
	$(CC) -c $@.cpp $(CFLAGS)
	$(CC) -o $@ $@.o $(LIBS)

.PHONY: clean

clean:
	rm -f *.o $(TARGETS)
