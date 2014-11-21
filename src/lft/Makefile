#
# This file is part of LFT.
#
# The LFT software provided in this Distribution is
# Copyright 2007 VOSTROM Holdings, Inc.
#
# The full text of our legal notices is contained in the file called
# COPYING, included with this Distribution.

# Directories where LFT will be installed:

prefix=/usr/local
datarootdir = ${prefix}/share
datadir = ${datarootdir}
exec_prefix=${prefix}
bindir=${exec_prefix}/bin
libdir=${exec_prefix}/lib
mandir=${datarootdir}/man
INSTALL=/usr/bin/install -c
LN=ln -s

# Commands/References

CC=gcc
CFLAGS=-g -O2 -I/usr/include/pcap
LIBFLAGS=-fpic -shared
LIBS=-lpcap -lm -lresolv -lnsl 
LDFLAGS=

CAT=cat
CD=cd
MKDIR=mkdir -p
BUILDTYPE=build
RM=rm -rf
SH=sh
SYSTEM=unix
TOOLS=tools
TOUCH=touch


# Specifics

OBJS=lft.o lft_ifname.o whois.o lft_lib.o lft_icmptrace.o lft_btcptrace.o

all: lft whob libwhois

lft: $(OBJS)
	$(CC) $(CFLAGS) -o lft $(OBJS) $(LDFLAGS) $(LIBS)

whob: whois.o
	$(CC) $(CFLAGS) -o whob whois.c -DSTANDALONE $(LDFLAGS) $(LIBS)
	
libwhois: $(OBJS)
	$(CC) $(LIBFLAGS) $(CFLAGS) -o libwhois.so whois.c $(LDFLAGS) $(LIBS)

install: lft lft.8 whob whob.8
	@echo "LFT and WhoB"
	@echo "  \_Stripping binaries"
	@strip lft whob
	@echo "  \_Copying files to their intended destinations"
	@test -d $(DESTDIR)$(bindir)/. || $(MKDIR) $(DESTDIR)$(bindir)
	$(INSTALL) lft $(DESTDIR)$(bindir)/lft
	$(INSTALL) whob $(DESTDIR)$(bindir)/whob
	$(INSTALL) libwhois.so $(DESTDIR)$(libdir)/libwhois.so
	@ ( echo chown root $(DESTDIR)$(bindir)/lft && chown root $(DESTDIR)$(bindir)/lft && echo chmod u+s $(DESTDIR)$(bindir)/lft && chmod u+s $(DESTDIR)$(bindir)/lft ) || echo "***" WARNING: could not set $(bindir) suid to root
	@test -d $(DESTDIR)$(mandir)/man8/. || $(MKDIR) $(DESTDIR)$(mandir)/man8
	@echo "Installing manual pages"
	$(INSTALL) lft.8 $(DESTDIR)$(mandir)/man8/lft.8
	$(INSTALL) whob.8 $(DESTDIR)$(mandir)/man8/whob.8

clean:
	$(RM) *.o core* lft whob *.so *~ *.dSYM

distclean:
	$(RM) Makefile config.log config.status config/acconfig.h

better:
	@echo "Sorry, this is the best I can do."

work:
	@echo "Sorry, I didn't write this.  I'm only a Makefile."

love:
	@echo "What do you think I was doing before you bothered me?"

