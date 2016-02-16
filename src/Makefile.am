libdir = $(PAMDIR)

lib_LTLIBRARIES = pam_hipchat.la

pam_hipchat_la_SOURCES = pam_hipchat.c
pam_hipchat_la_LDFLAGS = -module -avoid-version
pam_hipchat_la_LIBADD = -lpam -lcurl

AM_CFLAGS = -Wall
AM_CPPFLAGS = -Ilib

install-data-hook:
	-rm $(DESTDIR)$(libdir)/pam_hipchat.la
	-rm $(DESTDIR)$(libdir)/pam_hipchat.a