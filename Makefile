VERSION=20110805
DIST=radns-$(VERSION)
DISTFILES=LICENSE Makefile NEWS README TODO.txt radns.c list.c list.h \
	radns.man dhclient-exit-hooks radns-script radns.sh
CFLAGS+=-Wall -Wextra -std=c99 -pedantic -g -DVERSION=\"$(VERSION)\" \
	-D _GNU_SOURCE
LDFLAGS+=
LDLIBS+=
TARGETS=radns
OBJS=radns.o list.o
RM=/bin/rm
PREFIX?=/usr/local

all: $(TARGETS)

radns: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

list.o: list.c list.h Makefile

install: $(TARGETS)
	install -m 755 radns $(PREFIX)/bin
	install -m 644 radns.man $(PREFIX)/man/man8/radns.8

deinstall:
	$(RM) -f $(PREFIX)/bin/radns
	$(RM) -f $(PREFIX)/man/man8/radns.8

$(DIST).tar.bz2:
	mkdir $(DIST)
	cp $(DISTFILES) $(DIST)/
	tar cf $(DIST).tar --exclude .git $(DIST)
	bzip2 -9 $(DIST).tar
	$(RM) -rf $(DIST)

dist: $(DIST).tar.bz2

TAGS: *.c *.h
	-etags *.[ch]

clean:
	$(RM) -f $(TARGETS) $(OBJS) $(DIST).tar.bz2

tag:
	git tag -a -m $(VERSION) $(VERSION)
