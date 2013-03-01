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

all: copy installlib install conf

copy: 
		cp $(SRC) $(PACKAGE)

installlib: $(LIBDIR)
        install -o root -m 700 libntail.php $(LIBDIR)
        install -o root -m 700 libipviking.php $(LIBDIR)

install: installlib
        install -o root -m 700 ntail $(INSTALLDIR)

conf: 
		install -o root -m 700 ntail.conf $(CONFDIR)

$(LIBDIR):
        mkdir $(LIBDIR)

clean: rmlibs
        rm -f *~

rmlibs:
        rm -rf $(LIBDIR)
