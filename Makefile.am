
bin_PROGRAMS = rtp2httpd

rtp2httpd_SOURCES = rtp2httpd.c httpclients.c configfile.c

noinst_HEADERS = rtp2httpd.h

AM_CFLAGS= -DSYSCONFDIR=\"@sysconfdir@\"
dist_sysconf_DATA = rtp2httpd.conf
