VERSION=0.6
DIST=radns-$(VERSION)
DISTFILES=LICENSE Makefile NEWS README TODO.txt radns.c
CFLAGS=-Wall -W -g -DVERSION=\"$(VERSION)\"
TARGETS=radns
RM=/bin/rm

all: $(TARGETS)

radns: radns.c
	$(CC) $(CFLAGS) -o $@ $<

$(DIST).tar.gz:
	mkdir $(DIST)
	cp $(DISTFILES) $(DIST)/
	tar cf $(DIST).tar $(DIST)
	gzip -9 $(DIST).tar
	$(RM) -rf $(DIST)

dist: $(DIST).tar.gz

TAGS: *.c *.h
	-etags *.[ch]

clean:
	rm -f $(TARGETS) *.o $(DIST).tar.gz
