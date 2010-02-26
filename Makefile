VERSION=0.9rc2
DIST=radns-$(VERSION)
DISTFILES=LICENSE Makefile NEWS README TODO.txt radns.c
CFLAGS=-Wall -W -g -DVERSION=\"$(VERSION)\"
#CFLAGS=-Wall -W -g -DVERSION=\"$(VERSION)\" -DDMALLOC -DMALLOC_FUNC_CHECK -I/usr/local/include -L /usr/local/lib -ldmalloc
TARGETS=radns
RM=/bin/rm

all: $(TARGETS)

radns: radns.c
	$(CC) $(CFLAGS) -o $@ $<

$(DIST).tar.gz:
	mkdir $(DIST)
	cp $(DISTFILES) $(DIST)/
	tar cf $(DIST).tar --exclude .git $(DIST)
	gzip -9 $(DIST).tar
	$(RM) -rf $(DIST)

dist: $(DIST).tar.gz

TAGS: *.c *.h
	-etags *.[ch]

clean:
	rm -f $(TARGETS) *.o $(DIST).tar.gz
