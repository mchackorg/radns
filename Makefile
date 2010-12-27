VERSION=20101227-3
DIST=radns-$(VERSION)
DISTFILES=LICENSE Makefile NEWS README TODO.txt radns.c radns.man \
	dhclient-exit-hooks radns-script radns.sh
CC=gcc
CFLAGS=-Wall -Wextra -std=c99 -pedantic -g -DVERSION=\"$(VERSION)\"
#CFLAGS=-Wall -W -g -DVERSION=\"$(VERSION)\" -DDMALLOC -DMALLOC_FUNC_CHECK -I/usr/local/include -L /usr/local/lib -ldmalloc
TARGETS=radns
RM=/bin/rm

all: $(TARGETS)

radns: radns.c
	$(CC) $(CFLAGS) -o $@ $<

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
	$(RM) -f $(TARGETS) *.o $(DIST).tar.bz2
