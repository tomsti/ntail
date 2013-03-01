##########################################
# Norse Corp IPViking API ntail install  #
# Yes messy but works, shaddap or fix it #
##########################################

LIBDIR=/usr/local/lib/ipviking
INSTALLDIR=/usr/local/bin/
CONFDIR=/usr/local/etc/

# need php 5+
# need memcache/curl/

all: conf copy installlib install

installlib: $(LIBDIR)
	install -o root -m 700 ${.CURDIR}/lib/libntail.php $(LIBDIR)
	install -o root -m 700 ${.CURDIR}/lib/libipviking.php $(LIBDIR)

conf:
	install -o root -m 700 ntail.conf $(CONFDIR)

copy:
	cp ntail.php ntail

install: installlib conf copy
	install -o root -m 755 ntail $(CONFDIR)

$(LIBDIR):
	mkdir $(LIBDIR)

clean: rmlibs
	rm -f *~

rmlibs:
	rm -rf $(LIBDIR)
