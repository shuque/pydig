#
# Makefile for pydig, a DNS query tool written in Python
#
# $Id: Makefile,v 1.1 2007/03/08 22:14:28 shuque Exp $
#

PROGS		= pydig

PREFIX		= /usr/local
BINDIR		= $(PREFIX)/bin

MANSUFFIX	= 1
MANDIR		= $(PREFIX)/man/man$(MANSUFFIX)
all:
	@echo Run \"make install\" \(as root\).

install:
	@echo "Installing program and manpage."
	@for prog in $(PROGS); do \
		cp $$prog $(BINDIR); \
		chmod 755 $(BINDIR)/$$prog; \
		cp $$prog.$(MANSUFFIX) $(MANDIR); \
		chmod 755 $(MANDIR)/$$prog.$(MANSUFFIX); \
	done
