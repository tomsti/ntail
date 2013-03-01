##########################################
# Norse Corp IPViking API ntail install  #
# Yes messy but works, shaddap or fix it #
##########################################

LIBDIR=/usr/local/lib/ipviking
INSTALLDIR=/usr/local/bin/
CONFDIR=/usr/local/etc
PACKAGE=ntail
SRC=ntail.php
CONF=ntail.conf


# need php 5+
# need memcache/curl/

all: conf copy installlib install

installlib: $(LIBDIR)
	install -o root -m 700 lib/libntail.php $(LIBDIR)
	install -o root -m 700 lib/libipviking.php $(LIBDIR)

conf:
	install -o root -m 700 ntail.conf $(CONFDIR)

copy:
	cp $(SRC) $(PACKAGE)

install: installlib conf copy
	install -o root -m 700 ntail $(INSTALLDIR)

$(LIBDIR):
	mkdir $(LIBDIR)

clean: rmlibs
	rm -f *~

rmlibs:
	rm -rf $(LIBDIR)
