##########################################
# Norse Corp IPViking API ntail install  #
# Yes messy but works, shaddap or fix it #
##########################################

LIBDIR=/usr/local/lib/ipviking
INSTALLDIR=/usr/local/bin/
PACKAGE=ntail
SRC=ntail.php

# need php 5+
# need memcache/curl/

all: copy installlib install

copy: 
		cp $(SRC) $(PACKAGE)

installlib: $(LIBDIR)
        install -o root -m 700 libntail.php $(LIBDIR)
        install -o root -m 700 libipviking.php $(LIBDIR)

install: installlib
        install -o root -m 700 ntail $(INSTALLDIR)

$(LIBDIR):
        mkdir $(LIBDIR)

clean: rmlibs
        rm -f *~

rmlibs:
        rm -rf $(LIBDIR)
