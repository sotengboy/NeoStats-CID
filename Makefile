# Makefile.in generated by automake 1.9.6 from Makefile.am.
# Makefile.  Generated from Makefile.in by configure.

# Copyright (C) 1994, 1995, 1996, 1997, 1998, 1999, 2000, 2001, 2002,
# 2003, 2004, 2005  Free Software Foundation, Inc.
# This Makefile.in is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY, to the extent permitted by law; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.




srcdir = .
top_srcdir = .

pkgdatadir = $(datadir)/NeoStats
pkgincludedir = $(includedir)/NeoStats
top_builddir = .
am__cd = CDPATH="$${ZSH_VERSION+.}$(PATH_SEPARATOR)" && cd
INSTALL = /bin/install -c
install_sh_DATA = $(install_sh) -c -m 644
install_sh_PROGRAM = $(install_sh) -c
install_sh_SCRIPT = $(install_sh) -c
INSTALL_HEADER = $(INSTALL_DATA)
transform = $(program_transform_name)
NORMAL_INSTALL = :
PRE_INSTALL = :
POST_INSTALL = :
NORMAL_UNINSTALL = :
PRE_UNINSTALL = :
POST_UNINSTALL = :
build_triplet = x86_64-unknown-linux-gnu
host_triplet = x86_64-unknown-linux-gnu
DIST_COMMON = README $(am__configure_deps) $(dist_bin_SCRIPTS) \
	$(dist_data_DATA) $(dist_doc_DATA) $(srcdir)/Makefile.am \
	$(srcdir)/Makefile.in $(srcdir)/neostats.in \
	$(top_srcdir)/autotools/rules.mk $(top_srcdir)/configure \
	AUTHORS COPYING ChangeLog INSTALL NEWS TODO autotools/compile \
	autotools/config.guess autotools/config.sub autotools/depcomp \
	autotools/install-sh autotools/ltmain.sh autotools/missing \
	autotools/mkinstalldirs autotools/ylwrap
subdir = .
ACLOCAL_M4 = $(top_srcdir)/aclocal.m4
am__aclocal_m4_deps = $(top_srcdir)/autotools/acinclude.m4 \
	$(top_srcdir)/autotools/ax_distversion.m4 \
	$(top_srcdir)/autotools/ax_maintainer_mode_auto_silent.m4 \
	$(top_srcdir)/autotools/ax_path_lib_curl.m4 \
	$(top_srcdir)/autotools/ax_path_lib_pcre.m4 \
	$(top_srcdir)/autotools/berkeley_db.m4 \
	$(top_srcdir)/autotools/ccdv.m4 \
	$(top_srcdir)/autotools/libevent.m4 $(top_srcdir)/configure.in
am__configure_deps = $(am__aclocal_m4_deps) $(CONFIGURE_DEPENDENCIES) \
	$(ACLOCAL_M4)
am__CONFIG_DISTCLEAN_FILES = config.status config.cache config.log \
 configure.lineno configure.status.lineno
mkinstalldirs = $(SHELL) $(top_srcdir)/autotools/mkinstalldirs
CONFIG_HEADER = $(top_builddir)/include/config.h
CONFIG_CLEAN_FILES = neostats
am__installdirs = "$(DESTDIR)$(bindir)" "$(DESTDIR)$(neodir)" \
	"$(DESTDIR)$(datadir)" "$(DESTDIR)$(docdir)"
dist_binSCRIPT_INSTALL = $(INSTALL_SCRIPT)
neoSCRIPT_INSTALL = $(INSTALL_SCRIPT)
SCRIPTS = $(dist_bin_SCRIPTS) $(neo_SCRIPTS)
SOURCES =
DIST_SOURCES =
RECURSIVE_TARGETS = all-recursive check-recursive dvi-recursive \
	html-recursive info-recursive install-data-recursive \
	install-exec-recursive install-info-recursive \
	install-recursive installcheck-recursive installdirs-recursive \
	pdf-recursive ps-recursive uninstall-info-recursive \
	uninstall-recursive
am__vpath_adj_setup = srcdirstrip=`echo "$(srcdir)" | sed 's|.|.|g'`;
am__vpath_adj = case $$p in \
    $(srcdir)/*) f=`echo "$$p" | sed "s|^$$srcdirstrip/||"`;; \
    *) f=$$p;; \
  esac;
am__strip_dir = `echo $$p | sed -e 's|^.*/||'`;
dist_dataDATA_INSTALL = $(INSTALL_DATA)
dist_docDATA_INSTALL = $(INSTALL_DATA)
DATA = $(dist_data_DATA) $(dist_doc_DATA)
ETAGS = etags
CTAGS = ctags
DIST_SUBDIRS = $(SUBDIRS)
DISTFILES = $(DIST_COMMON) $(DIST_SOURCES) $(TEXINFOS) $(EXTRA_DIST)
top_distdir = $(distdir)
am__remove_distdir = \
  { test ! -d $(distdir) \
    || { find $(distdir) -type d ! -perm -200 -exec chmod u+w {} ';' \
         && rm -fr $(distdir); }; }
DIST_ARCHIVES = $(distdir).tar.gz
GZIP_ENV = --best
distuninstallcheck_listfiles = find . -type f -print
distcleancheck_listfiles = find . -type f -print
pkglibdir = $(prefix)/modules
ACLOCAL = ${SHELL} /home/server/NeoStats-3.0.2-3348/autotools/missing --run aclocal-1.9
AMDEP_FALSE = #
AMDEP_TRUE = 
AMTAR = ${SHELL} /home/server/NeoStats-3.0.2-3348/autotools/missing --run tar
AR = ar
AUTOCONF = ${SHELL} /home/server/NeoStats-3.0.2-3348/autotools/missing --run autoconf
AUTOHEADER = ${SHELL} /home/server/NeoStats-3.0.2-3348/autotools/missing --run autoheader
AUTOMAKE = ${SHELL} /home/server/NeoStats-3.0.2-3348/autotools/missing --run automake-1.9
AWK = gawk
BLD_BDB = 
BLD_LIBEXEC = 
BUILD_CURL_FALSE = #
BUILD_CURL_TRUE = 
BUILD_PCRE_FALSE = #
BUILD_PCRE_TRUE = 
CABUNDLE_FALSE = #
CABUNDLE_TRUE = 
CC = /home/server/NeoStats-3.0.2-3348/ccdv gcc
CCDEPMODE = depmode=gcc3
CCDV = /home/server/NeoStats-3.0.2-3348/ccdv
CFLAGS = -g -O2 -g -rdynamic -DNDEBUG -fno-strict-aliasing -fno-strict-aliasing
CPP = gcc -E
CPPFLAGS =   
CURL_CA_BUNDLE = "/home/server/NeoStats3.0/share/curl/curl-ca-bundle.crt"
CURL_CFLAGS = -I${top_srcdir}/lib/curl
CURL_DISABLE_LDAP = 1
CURL_LIBS = ${top_srcdir}/lib/curl/libcurl.la
CYGPATH_W = echo
DB_CPPFLAGS = 
DB_LDFLAGS = 
DB_LIBS = 
DEFS = -DHAVE_CONFIG_H
DEPDIR = .deps
DISTDIRVERSION = NeoStats-3.0.2
DO_PERL_FALSE = 
DO_PERL_TRUE = #
ECHO = echo
ECHO_C = 
ECHO_N = -n
ECHO_T = 
EGREP = /bin/grep -E
EVNTLIBOBJS =  select.c poll.c epoll.c signal.c
EXEEXT = 
GREP = /bin/grep
HAVE_LIBZ = 1
HAVE_LIBZ_FALSE = #
HAVE_LIBZ_TRUE = 
INSTALL_DATA = ${INSTALL} -m 644
INSTALL_PROGRAM = ${INSTALL}
INSTALL_SCRIPT = ${INSTALL}
INSTALL_STRIP_PROGRAM = ${SHELL} $(install_sh) -c -s
IPV6_ENABLED = 1
LDFLAGS =  -g -rdynamic  
LEX = :
LEXLIB = 
LEX_OUTPUT_ROOT = 
LIBDB = 
LIBOBJS = 
LIBS = -lssl -lcrypto -g -lm -ldl  -lssl -lcrypto   -lz
LIBTOOL = $(SHELL) $(top_builddir)/libtool --quiet
LIBTOOL_DEPS = autotools/ltmain.sh
LNK_LIBEXEC = 
LN_S = ln -s
LTLIBOBJS = 
MAINT = #
MAINTAINER_MODE_FALSE = 
MAINTAINER_MODE_TRUE = #
MAKEINFO = ${SHELL} /home/server/NeoStats-3.0.2-3348/autotools/missing --run makeinfo
MODULES = connectserv hostserv statserv ircdauth extauth limitserv textserv quoteserv operlog dccpartyline perltest templateauth template update
OBJEXT = o
PACKAGE = NeoStats
PACKAGE_BUGREPORT = 
PACKAGE_NAME = 
PACKAGE_STRING = 
PACKAGE_TARNAME = 
PACKAGE_VERSION = 
PATH_SEPARATOR = :
PCRE_CFLAGS = -I${top_srcdir}/lib/pcre
PCRE_LIBS = ${top_srcdir}/lib/pcre/libpcre.la
PERL_CFLAGS = 
PERL_LDFLAGS = 
PKGCONFIG = /bin/pkg-config
POW_LIB = 
PROTOCOL = 
RANDOM_FILE = /dev/urandom
RANLIB = ranlib
SED = /bin/sed
SET_MAKE = 
SHELL = /bin/sh
STRIP = strip
USECCDV = #
USE_GNUTLS = 
USE_SSLEAY = 1
VERSION = 3.0.2
YACC = yacc
YFLAGS = 
ac_ct_CC = gcc
am__fastdepCC_FALSE = #
am__fastdepCC_TRUE = 
am__include = include
am__leading_dot = .
am__quote = 
am__tar = ${AMTAR} chof - "$$tardir"
am__untar = ${AMTAR} xf -
bindir = ${exec_prefix}/bin
build = x86_64-unknown-linux-gnu
build_alias = 
build_cpu = x86_64
build_os = linux-gnu
build_vendor = unknown
datadir = $(prefix)/data
datarootdir = ${prefix}/share
docdir = $(prefix)/doc
dvidir = ${docdir}
exec_prefix = ${prefix}
host = x86_64-unknown-linux-gnu
host_alias = 
host_cpu = x86_64
host_os = linux-gnu
host_vendor = unknown
htmldir = ${docdir}
includedir = ${prefix}/include
infodir = ${datarootdir}/info
install_sh = /home/server/NeoStats-3.0.2-3348/autotools/install-sh
libdir = ${exec_prefix}/lib
libexecdir = ${exec_prefix}/libexec
localedir = ${datarootdir}/locale
localstatedir = ${prefix}/var
mandir = ${datarootdir}/man
mkdir_p = mkdir -p --
oldincludedir = /usr/include
pdfdir = ${docdir}
perlpath = /bin/perl
prefix = /home/server/NeoStats3.0
program_transform_name = s,x,x,
psdir = ${docdir}
sbindir = ${exec_prefix}/sbin
sedpath = /bin/sed
sharedstatedir = ${prefix}/com
sysconfdir = ${prefix}/etc
target_alias = 
unamepath = /bin/uname
wi_PWD = /bin/pwd
AUTOMAKE_OPTIONS = foreign
SUBDIRS = include lib src modules
ACLOCAL_AMFLAGS = -I autotools
AM_MAKEFLAGS = -s
DISTCHECK_CONFIGURE_FLAGS = --cache-file=../config.cache
dist_bin_SCRIPTS = makeconf
dist_data_DATA = neostats.motd
#docdir			= /home/server/NeoStats3.0/doc
dist_doc_DATA = doc/README.dev ChangeLog.old doc/CODINGMODULES.txt RELNOTES CREDITS README
neodir = $(prefix)
neo_SCRIPTS = neostats
DISTCLEANFILES = autotools/ccdv
EXTRA_DIST = autotools/ccdv.c autotools/shtool INSTNOTES
LINK = $(LIBTOOL) --tag=CC --mode=link $(CCLD) $(AM_CFLAGS) $(CFLAGS) \
        $(AM_LDFLAGS) $(LDFLAGS) -o $@

distdir = NeoStats-3.0.2
all: all-recursive

.SUFFIXES:
.SUFFIXES: .c .lo .o .obj
am--refresh:
	@:
$(srcdir)/Makefile.in: # $(srcdir)/Makefile.am $(top_srcdir)/autotools/rules.mk $(am__configure_deps)
	@for dep in $?; do \
	  case '$(am__configure_deps)' in \
	    *$$dep*) \
	      echo ' cd $(srcdir) && $(AUTOMAKE) --foreign '; \
	      cd $(srcdir) && $(AUTOMAKE) --foreign  \
		&& exit 0; \
	      exit 1;; \
	  esac; \
	done; \
	echo ' cd $(top_srcdir) && $(AUTOMAKE) --foreign  Makefile'; \
	cd $(top_srcdir) && \
	  $(AUTOMAKE) --foreign  Makefile
.PRECIOUS: Makefile
Makefile: $(srcdir)/Makefile.in $(top_builddir)/config.status
	@case '$?' in \
	  *config.status*) \
	    echo ' $(SHELL) ./config.status'; \
	    $(SHELL) ./config.status;; \
	  *) \
	    echo ' cd $(top_builddir) && $(SHELL) ./config.status $@ $(am__depfiles_maybe)'; \
	    cd $(top_builddir) && $(SHELL) ./config.status $@ $(am__depfiles_maybe);; \
	esac;

$(top_builddir)/config.status: $(top_srcdir)/configure $(CONFIG_STATUS_DEPENDENCIES)
	$(SHELL) ./config.status --recheck

$(top_srcdir)/configure: # $(am__configure_deps)
	cd $(srcdir) && $(AUTOCONF)
$(ACLOCAL_M4): # $(am__aclocal_m4_deps)
	cd $(srcdir) && $(ACLOCAL) $(ACLOCAL_AMFLAGS)
neostats: $(top_builddir)/config.status $(srcdir)/neostats.in
	cd $(top_builddir) && $(SHELL) ./config.status $@

uninstall-dist_binSCRIPTS:
	@$(NORMAL_UNINSTALL)
	@list='$(dist_bin_SCRIPTS)'; for p in $$list; do \
	  f=`echo "$$p" | sed 's|^.*/||;$(transform)'`; \
	  echo " rm -f '$(DESTDIR)$(bindir)/$$f'"; \
	  rm -f "$(DESTDIR)$(bindir)/$$f"; \
	done

uninstall-neoSCRIPTS:
	@$(NORMAL_UNINSTALL)
	@list='$(neo_SCRIPTS)'; for p in $$list; do \
	  f=`echo "$$p" | sed 's|^.*/||;$(transform)'`; \
	  echo " rm -f '$(DESTDIR)$(neodir)/$$f'"; \
	  rm -f "$(DESTDIR)$(neodir)/$$f"; \
	done

mostlyclean-libtool:
	-rm -f *.lo

clean-libtool:
	-rm -rf .libs _libs

distclean-libtool:
	-rm -f libtool
uninstall-info-am:

uninstall-dist_dataDATA:
	@$(NORMAL_UNINSTALL)
	@list='$(dist_data_DATA)'; for p in $$list; do \
	  f=$(am__strip_dir) \
	  echo " rm -f '$(DESTDIR)$(datadir)/$$f'"; \
	  rm -f "$(DESTDIR)$(datadir)/$$f"; \
	done

uninstall-dist_docDATA:
	@$(NORMAL_UNINSTALL)
	@list='$(dist_doc_DATA)'; for p in $$list; do \
	  f=$(am__strip_dir) \
	  echo " rm -f '$(DESTDIR)$(docdir)/$$f'"; \
	  rm -f "$(DESTDIR)$(docdir)/$$f"; \
	done

# This directory's subdirectories are mostly independent; you can cd
# into them and run `make' without going through this Makefile.
# To change the values of `make' variables: instead of editing Makefiles,
# (1) if the variable is set in `config.status', edit `config.status'
#     (which will cause the Makefiles to be regenerated when you run `make');
# (2) otherwise, pass the desired values on the `make' command line.
$(RECURSIVE_TARGETS):
	@failcom='exit 1'; \
	for f in x $$MAKEFLAGS; do \
	  case $$f in \
	    *=* | --[!k]*);; \
	    *k*) failcom='fail=yes';; \
	  esac; \
	done; \
	dot_seen=no; \
	target=`echo $@ | sed s/-recursive//`; \
	list='$(SUBDIRS)'; for subdir in $$list; do \
	  echo "Making $$target in $$subdir"; \
	  if test "$$subdir" = "."; then \
	    dot_seen=yes; \
	    local_target="$$target-am"; \
	  else \
	    local_target="$$target"; \
	  fi; \
	  (cd $$subdir && $(MAKE) $(AM_MAKEFLAGS) $$local_target) \
	  || eval $$failcom; \
	done; \
	if test "$$dot_seen" = "no"; then \
	  $(MAKE) $(AM_MAKEFLAGS) "$$target-am" || exit 1; \
	fi; test -z "$$fail"

mostlyclean-recursive clean-recursive distclean-recursive \
maintainer-clean-recursive:
	@failcom='exit 1'; \
	for f in x $$MAKEFLAGS; do \
	  case $$f in \
	    *=* | --[!k]*);; \
	    *k*) failcom='fail=yes';; \
	  esac; \
	done; \
	dot_seen=no; \
	case "$@" in \
	  distclean-* | maintainer-clean-*) list='$(DIST_SUBDIRS)' ;; \
	  *) list='$(SUBDIRS)' ;; \
	esac; \
	rev=''; for subdir in $$list; do \
	  if test "$$subdir" = "."; then :; else \
	    rev="$$subdir $$rev"; \
	  fi; \
	done; \
	rev="$$rev ."; \
	target=`echo $@ | sed s/-recursive//`; \
	for subdir in $$rev; do \
	  echo "Making $$target in $$subdir"; \
	  if test "$$subdir" = "."; then \
	    local_target="$$target-am"; \
	  else \
	    local_target="$$target"; \
	  fi; \
	  (cd $$subdir && $(MAKE) $(AM_MAKEFLAGS) $$local_target) \
	  || eval $$failcom; \
	done && test -z "$$fail"
tags-recursive:
	list='$(SUBDIRS)'; for subdir in $$list; do \
	  test "$$subdir" = . || (cd $$subdir && $(MAKE) $(AM_MAKEFLAGS) tags); \
	done
ctags-recursive:
	list='$(SUBDIRS)'; for subdir in $$list; do \
	  test "$$subdir" = . || (cd $$subdir && $(MAKE) $(AM_MAKEFLAGS) ctags); \
	done

ID: $(HEADERS) $(SOURCES) $(LISP) $(TAGS_FILES)
	list='$(SOURCES) $(HEADERS) $(LISP) $(TAGS_FILES)'; \
	unique=`for i in $$list; do \
	    if test -f "$$i"; then echo $$i; else echo $(srcdir)/$$i; fi; \
	  done | \
	  $(AWK) '    { files[$$0] = 1; } \
	       END { for (i in files) print i; }'`; \
	mkid -fID $$unique
tags: TAGS

TAGS: tags-recursive $(HEADERS) $(SOURCES)  $(TAGS_DEPENDENCIES) \
		$(TAGS_FILES) $(LISP)
	tags=; \
	here=`pwd`; \
	if ($(ETAGS) --etags-include --version) >/dev/null 2>&1; then \
	  include_option=--etags-include; \
	  empty_fix=.; \
	else \
	  include_option=--include; \
	  empty_fix=; \
	fi; \
	list='$(SUBDIRS)'; for subdir in $$list; do \
	  if test "$$subdir" = .; then :; else \
	    test ! -f $$subdir/TAGS || \
	      tags="$$tags $$include_option=$$here/$$subdir/TAGS"; \
	  fi; \
	done; \
	list='$(SOURCES) $(HEADERS)  $(LISP) $(TAGS_FILES)'; \
	unique=`for i in $$list; do \
	    if test -f "$$i"; then echo $$i; else echo $(srcdir)/$$i; fi; \
	  done | \
	  $(AWK) '    { files[$$0] = 1; } \
	       END { for (i in files) print i; }'`; \
	if test -z "$(ETAGS_ARGS)$$tags$$unique"; then :; else \
	  test -n "$$unique" || unique=$$empty_fix; \
	  $(ETAGS) $(ETAGSFLAGS) $(AM_ETAGSFLAGS) $(ETAGS_ARGS) \
	    $$tags $$unique; \
	fi
ctags: CTAGS
CTAGS: ctags-recursive $(HEADERS) $(SOURCES)  $(TAGS_DEPENDENCIES) \
		$(TAGS_FILES) $(LISP)
	tags=; \
	here=`pwd`; \
	list='$(SOURCES) $(HEADERS)  $(LISP) $(TAGS_FILES)'; \
	unique=`for i in $$list; do \
	    if test -f "$$i"; then echo $$i; else echo $(srcdir)/$$i; fi; \
	  done | \
	  $(AWK) '    { files[$$0] = 1; } \
	       END { for (i in files) print i; }'`; \
	test -z "$(CTAGS_ARGS)$$tags$$unique" \
	  || $(CTAGS) $(CTAGSFLAGS) $(AM_CTAGSFLAGS) $(CTAGS_ARGS) \
	     $$tags $$unique

GTAGS:
	here=`$(am__cd) $(top_builddir) && pwd` \
	  && cd $(top_srcdir) \
	  && gtags -i $(GTAGS_ARGS) $$here

distclean-tags:
	-rm -f TAGS ID GTAGS GRTAGS GSYMS GPATH tags

distdir: $(DISTFILES)
	$(am__remove_distdir)
	mkdir $(distdir)
	$(mkdir_p) $(distdir)/. $(distdir)/autotools $(distdir)/doc
	@srcdirstrip=`echo "$(srcdir)" | sed 's|.|.|g'`; \
	topsrcdirstrip=`echo "$(top_srcdir)" | sed 's|.|.|g'`; \
	list='$(DISTFILES)'; for file in $$list; do \
	  case $$file in \
	    $(srcdir)/*) file=`echo "$$file" | sed "s|^$$srcdirstrip/||"`;; \
	    $(top_srcdir)/*) file=`echo "$$file" | sed "s|^$$topsrcdirstrip/|$(top_builddir)/|"`;; \
	  esac; \
	  if test -f $$file || test -d $$file; then d=.; else d=$(srcdir); fi; \
	  dir=`echo "$$file" | sed -e 's,/[^/]*$$,,'`; \
	  if test "$$dir" != "$$file" && test "$$dir" != "."; then \
	    dir="/$$dir"; \
	    $(mkdir_p) "$(distdir)$$dir"; \
	  else \
	    dir=''; \
	  fi; \
	  if test -d $$d/$$file; then \
	    if test -d $(srcdir)/$$file && test $$d != $(srcdir); then \
	      cp -pR $(srcdir)/$$file $(distdir)$$dir || exit 1; \
	    fi; \
	    cp -pR $$d/$$file $(distdir)$$dir || exit 1; \
	  else \
	    test -f $(distdir)/$$file \
	    || cp -p $$d/$$file $(distdir)/$$file \
	    || exit 1; \
	  fi; \
	done
	list='$(DIST_SUBDIRS)'; for subdir in $$list; do \
	  if test "$$subdir" = .; then :; else \
	    test -d "$(distdir)/$$subdir" \
	    || $(mkdir_p) "$(distdir)/$$subdir" \
	    || exit 1; \
	    distdir=`$(am__cd) $(distdir) && pwd`; \
	    top_distdir=`$(am__cd) $(top_distdir) && pwd`; \
	    (cd $$subdir && \
	      $(MAKE) $(AM_MAKEFLAGS) \
	        top_distdir="$$top_distdir" \
	        distdir="$$distdir/$$subdir" \
	        distdir) \
	      || exit 1; \
	  fi; \
	done
	-find $(distdir) -type d ! -perm -777 -exec chmod a+rwx {} \; -o \
	  ! -type d ! -perm -444 -links 1 -exec chmod a+r {} \; -o \
	  ! -type d ! -perm -400 -exec chmod a+r {} \; -o \
	  ! -type d ! -perm -444 -exec $(SHELL) $(install_sh) -c -m a+r {} {} \; \
	|| chmod -R a+r $(distdir)
dist-gzip: distdir
	tardir=$(distdir) && $(am__tar) | GZIP=$(GZIP_ENV) gzip -c >$(distdir).tar.gz
	$(am__remove_distdir)

dist-bzip2: distdir
	tardir=$(distdir) && $(am__tar) | bzip2 -9 -c >$(distdir).tar.bz2
	$(am__remove_distdir)

dist-tarZ: distdir
	tardir=$(distdir) && $(am__tar) | compress -c >$(distdir).tar.Z
	$(am__remove_distdir)

dist-shar: distdir
	shar $(distdir) | GZIP=$(GZIP_ENV) gzip -c >$(distdir).shar.gz
	$(am__remove_distdir)

dist-zip: distdir
	-rm -f $(distdir).zip
	zip -rq $(distdir).zip $(distdir)
	$(am__remove_distdir)

dist dist-all: distdir
	tardir=$(distdir) && $(am__tar) | GZIP=$(GZIP_ENV) gzip -c >$(distdir).tar.gz
	$(am__remove_distdir)

# This target untars the dist file and tries a VPATH configuration.  Then
# it guarantees that the distribution is self-contained by making another
# tarfile.
distcheck: dist
	case '$(DIST_ARCHIVES)' in \
	*.tar.gz*) \
	  GZIP=$(GZIP_ENV) gunzip -c $(distdir).tar.gz | $(am__untar) ;;\
	*.tar.bz2*) \
	  bunzip2 -c $(distdir).tar.bz2 | $(am__untar) ;;\
	*.tar.Z*) \
	  uncompress -c $(distdir).tar.Z | $(am__untar) ;;\
	*.shar.gz*) \
	  GZIP=$(GZIP_ENV) gunzip -c $(distdir).shar.gz | unshar ;;\
	*.zip*) \
	  unzip $(distdir).zip ;;\
	esac
	chmod -R a-w $(distdir); chmod a+w $(distdir)
	mkdir $(distdir)/_build
	mkdir $(distdir)/_inst
	chmod a-w $(distdir)
	dc_install_base=`$(am__cd) $(distdir)/_inst && pwd | sed -e 's,^[^:\\/]:[\\/],/,'` \
	  && dc_destdir="$${TMPDIR-/tmp}/am-dc-$$$$/" \
	  && cd $(distdir)/_build \
	  && ../configure --srcdir=.. --prefix="$$dc_install_base" \
	    $(DISTCHECK_CONFIGURE_FLAGS) \
	  && $(MAKE) $(AM_MAKEFLAGS) \
	  && $(MAKE) $(AM_MAKEFLAGS) dvi \
	  && $(MAKE) $(AM_MAKEFLAGS) check \
	  && $(MAKE) $(AM_MAKEFLAGS) install \
	  && $(MAKE) $(AM_MAKEFLAGS) installcheck \
	  && $(MAKE) $(AM_MAKEFLAGS) uninstall \
	  && $(MAKE) $(AM_MAKEFLAGS) distuninstallcheck_dir="$$dc_install_base" \
	        distuninstallcheck \
	  && chmod -R a-w "$$dc_install_base" \
	  && ({ \
	       (cd ../.. && umask 077 && mkdir "$$dc_destdir") \
	       && $(MAKE) $(AM_MAKEFLAGS) DESTDIR="$$dc_destdir" install \
	       && $(MAKE) $(AM_MAKEFLAGS) DESTDIR="$$dc_destdir" uninstall \
	       && $(MAKE) $(AM_MAKEFLAGS) DESTDIR="$$dc_destdir" \
	            distuninstallcheck_dir="$$dc_destdir" distuninstallcheck; \
	      } || { rm -rf "$$dc_destdir"; exit 1; }) \
	  && rm -rf "$$dc_destdir" \
	  && $(MAKE) $(AM_MAKEFLAGS) dist \
	  && rm -rf $(DIST_ARCHIVES) \
	  && $(MAKE) $(AM_MAKEFLAGS) distcleancheck
	$(am__remove_distdir)
	@(echo "$(distdir) archives ready for distribution: "; \
	  list='$(DIST_ARCHIVES)'; for i in $$list; do echo $$i; done) | \
	  sed -e '1{h;s/./=/g;p;x;}' -e '$${p;x;}'
check-am: all-am
check: check-recursive
all-am: Makefile $(SCRIPTS) $(DATA) all-local
installdirs: installdirs-recursive
installdirs-am:
	for dir in "$(DESTDIR)$(bindir)" "$(DESTDIR)$(neodir)" "$(DESTDIR)$(datadir)" "$(DESTDIR)$(docdir)"; do \
	  test -z "$$dir" || $(mkdir_p) "$$dir"; \
	done
install: install-recursive
install-exec: install-exec-recursive
install-data: install-data-recursive
uninstall: uninstall-recursive

install-am: all-am
	@$(MAKE) $(AM_MAKEFLAGS) install-exec-am install-data-am

installcheck: installcheck-recursive
install-strip:
	$(MAKE) $(AM_MAKEFLAGS) INSTALL_PROGRAM="$(INSTALL_STRIP_PROGRAM)" \
	  install_sh_PROGRAM="$(INSTALL_STRIP_PROGRAM)" INSTALL_STRIP_FLAG=-s \
	  `test -z '$(STRIP)' || \
	    echo "INSTALL_PROGRAM_ENV=STRIPPROG='$(STRIP)'"` install
mostlyclean-generic:

clean-generic:

distclean-generic:
	-test -z "$(CONFIG_CLEAN_FILES)" || rm -f $(CONFIG_CLEAN_FILES)
	-test -z "$(DISTCLEANFILES)" || rm -f $(DISTCLEANFILES)

maintainer-clean-generic:
	@echo "This command is intended for maintainers to use"
	@echo "it deletes files that may require special tools to rebuild."
clean: clean-recursive

clean-am: clean-generic clean-libtool mostlyclean-am

distclean: distclean-recursive
	-rm -f $(am__CONFIG_DISTCLEAN_FILES)
	-rm -f Makefile
distclean-am: clean-am distclean-generic distclean-libtool \
	distclean-tags

dvi: dvi-recursive

dvi-am:

html: html-recursive

info: info-recursive

info-am:

install-data-am: install-dist_dataDATA install-dist_docDATA \
	install-neoSCRIPTS
	@$(NORMAL_INSTALL)
	$(MAKE) $(AM_MAKEFLAGS) install-data-hook

install-exec-am: install-dist_binSCRIPTS

install-info: install-info-recursive

install-man:

installcheck-am:

maintainer-clean: maintainer-clean-recursive
	-rm -f $(am__CONFIG_DISTCLEAN_FILES)
	-rm -rf $(top_srcdir)/autom4te.cache
	-rm -f Makefile
maintainer-clean-am: distclean-am maintainer-clean-generic

mostlyclean: mostlyclean-recursive

mostlyclean-am: mostlyclean-generic mostlyclean-libtool

pdf: pdf-recursive

pdf-am:

ps: ps-recursive

ps-am:

uninstall-am: uninstall-dist_binSCRIPTS uninstall-dist_dataDATA \
	uninstall-dist_docDATA uninstall-info-am uninstall-neoSCRIPTS

uninstall-info: uninstall-info-recursive

.PHONY: $(RECURSIVE_TARGETS) CTAGS GTAGS all all-am all-local \
	am--refresh check check-am clean clean-generic clean-libtool \
	clean-recursive ctags ctags-recursive dist dist-all dist-bzip2 \
	dist-gzip dist-shar dist-tarZ dist-zip distcheck distclean \
	distclean-generic distclean-libtool distclean-recursive \
	distclean-tags distcleancheck distdir distuninstallcheck dvi \
	dvi-am html html-am info info-am install install-am \
	install-data install-data-am install-data-hook \
	install-dist_binSCRIPTS install-dist_dataDATA \
	install-dist_docDATA install-exec install-exec-am install-info \
	install-info-am install-man install-neoSCRIPTS install-strip \
	installcheck installcheck-am installdirs installdirs-am \
	maintainer-clean maintainer-clean-generic \
	maintainer-clean-recursive mostlyclean mostlyclean-generic \
	mostlyclean-libtool mostlyclean-recursive pdf pdf-am ps ps-am \
	tags tags-recursive uninstall uninstall-am \
	uninstall-dist_binSCRIPTS uninstall-dist_dataDATA \
	uninstall-dist_docDATA uninstall-info-am uninstall-neoSCRIPTS


all-local:
		if test ! -f .message; then \
		echo ""; \
		$(top_srcdir)/autotools/shtool echo -e "%BCompilation complete.%b"; \
		echo ""; \
		echo "Run 'make install' (or 'gmake install' on some systems) to install NeoStats."; \
		echo "If you require support, see the README file."; \
		touch .message;\
		fi;

install-data-hook:
		test -z "$(prefix)/logs" || $(CCDV) $(mkdir_p) "$(prefix)/logs";
		echo ""
		$(top_srcdir)/autotools/shtool echo -e "%BInstallation complete.%b"
		echo ""
		echo "Change directory to '$(prefix)' then run './neostats'"
		echo "If you require support, see the README file."
		rm -f .message

.c.o:
#		@echo "Building $@"
	@if $(COMPILE) -MT $@ -MD -MP -MF "$(DEPDIR)/$*.Tpo" \
	  -c -o $@ `test -f '$<' || echo '$(srcdir)/'`$<; \
	then mv -f "$(DEPDIR)/$*.Tpo" "$(DEPDIR)/$*.Po"; \
	else rm -f "$(DEPDIR)/$*.Tpo"; exit 1; \
	fi
#	@source='$<' object='$@' libtool=no \
#	depfile='$(DEPDIR)/$*.Po' tmpdepfile='$(DEPDIR)/$*.TPo' \
#	$(CCDEPMODE) $(depcomp) \
#	$(COMPILE) -c `test -f '$<' || echo '$(srcdir)/'`$<

.c.obj:
#		@echo "Building $@"
	@if $(LTCOMPILE) -MT $@ -MD -MP -MF "$(DEPDIR)/$*.Tpo" \
	  -c -o $@ `if test -f '$<'; then $(CYGPATH_W) '$<'; else $(CYGPATH_W) '$(srcdir)/$<'; fi`; \
	then mv -f "$(DEPDIR)/$*.Tpo" "$(DEPDIR)/$*.Po"; \
	else rm -f "$(DEPDIR)/$*.Tpo"; exit 1; \
	fi
#	@source='$<' object='$@' libtool=no \
#	depfile='$(DEPDIR)/$*.Po' tmpdepfile='$(DEPDIR)/$*.TPo' \
#	$(CCDEPMODE) $(depcomp) \
#	$(LTCOMPILE) -c `if test -f '$<'; then $(CYGPATH_W) '$<'; else $(CYGPATH_W) '$(srcdir)/$<'; fi`

.c.lo:
#		@echo "Building $@"
	@if $(LTCOMPILE) -MT $@ -MD -MP -MF "$(DEPDIR)/$*.Tpo" \
	  -c -o $@ `test -f '$<' || echo '$(srcdir)/'`$<; \
	then mv -f "$(DEPDIR)/$*.Tpo" "$(DEPDIR)/$*.Plo"; \
	else rm -f "$(DEPDIR)/$*.Tpo"; exit 1; \
	fi
#	@source='$<' object='$@' libtool=yes \
#	depfile='$(DEPDIR)/$*.Plo' tmpdepfile='$(DEPDIR)/$*.TPlo' \
#	$(CCDEPMODE) $(depcomp) \
#	$(LTCOMPILE) -c -o $@ `test -f '$<' || echo '$(srcdir)/'`$<

install-pkglibLTLIBRARIES: $(pkglib_LTLIBRARIES)
	@$(NORMAL_INSTALL)
	$(mkinstalldirs) $(DESTDIR)$(pkglibdir)
	@list='ls .libs/*.so'; for p in $$list; do \
	  if test -f $$p; then \
	    f="`echo $$p | sed -e 's|^.*/||'`"; \
	    $(CCDV) $(LIBTOOL) --mode=install $(pkglibLTLIBRARIES_INSTALL) $(INSTALL_STRIP_FLAG) $$p $(DESTDIR)$(pkglibdir)/$$f; \
       	    if test "x#" != "x#"; then echo "Installing $$f"; fi; \
	  else :; fi; \
	done

install-binSCRIPTS: $(bin_SCRIPTS)
	@$(NORMAL_INSTALL)
	test -z "$(bindir)" || $(mkdir_p) "$(DESTDIR)$(bindir)"
	@list='$(bin_SCRIPTS)'; for p in $$list; do \
	  if test -f "$$p"; then d=; else d="$(srcdir)/"; fi; \
	  if test -f $$d$$p; then \
	    f=`echo "$$p" | sed 's|^.*/||;$(transform)'`; \
	    $(CCDV) $(binSCRIPT_INSTALL) "$$d$$p" "$(DESTDIR)$(bindir)/$$f"; \
   	if test "x#" != "x#"; then echo "Installing $$f"; fi; \
	  else :; fi; \
	done

install-dist_binSCRIPTS: $(dist_bin_SCRIPTS)
	@$(NORMAL_INSTALL)
	test -z "$(bindir)" || $(mkdir_p) "$(DESTDIR)$(bindir)"
	@list='$(dist_bin_SCRIPTS)'; for p in $$list; do \
	  if test -f "$$p"; then d=; else d="$(srcdir)/"; fi; \
	  if test -f $$d$$p; then \
	    f=`echo "$$p" | sed 's|^.*/||;$(transform)'`; \
	    $(CCDV) $(dist_binSCRIPT_INSTALL) "$$d$$p" "$(DESTDIR)$(bindir)/$$f"; \
   	if test "x#" != "x#"; then echo "Installing $$f"; fi; \
	  else :; fi; \
	done

install-dist_dataDATA: $(dist_data_DATA)
	@$(NORMAL_INSTALL)
	test -z "$(datadir)" || $(mkdir_p) "$(DESTDIR)$(datadir)"
	@list='$(dist_data_DATA)'; for p in $$list; do \
	  if test -f "$$p"; then d=; else d="$(srcdir)/"; fi; \
	  f=$(am__strip_dir) \
	  $(CCDV) $(dist_dataDATA_INSTALL) "$$d$$p" "$(DESTDIR)$(datadir)/$$f"; \
   	if test "x#" != "x#"; then echo "Installing $$f"; fi; \
	done

install-dist_docDATA: $(dist_doc_DATA)
	@$(NORMAL_INSTALL)
	test -z "$(docdir)" || $(mkdir_p) "$(DESTDIR)$(docdir)"
	@list='$(dist_doc_DATA)'; for p in $$list; do \
	  if test -f "$$p"; then d=; else d="$(srcdir)/"; fi; \
	  f=$(am__strip_dir) \
	  $(CCDV) $(dist_docDATA_INSTALL) "$$d$$p" "$(DESTDIR)$(docdir)/$$f"; \
   	if test "x#" != "x#"; then echo "Installing $$f"; fi; \
	done

install-includeHEADERS: $(include_HEADERS)
	@$(NORMAL_INSTALL)
	test -z "$(includedir)" || $(mkdir_p) "$(DESTDIR)$(includedir)"
	@list='$(include_HEADERS)'; for p in $$list; do \
	  if test -f "$$p"; then d=; else d="$(srcdir)/"; fi; \
	  f=$(am__strip_dir) \
	  $(CCDV) $(includeHEADERS_INSTALL) "$$d$$p" "$(DESTDIR)$(includedir)/$$f"; \
   	if test "x#" != "x#"; then echo "Installing $$f"; fi; \
	done

install-binPROGRAMS: $(bin_PROGRAMS)
	@$(NORMAL_INSTALL)
	test -z "$(bindir)" || $(mkdir_p) "$(DESTDIR)$(bindir)"
	@list='$(bin_PROGRAMS)'; for p in $$list; do \
	  p1=`echo $$p|sed 's/$(EXEEXT)$$//'`; \
	  if test -f $$p \
	     || test -f $$p1 \
	  ; then \
	    f=`echo "$$p1" | sed 's,^.*/,,;$(transform);s/$$/$(EXEEXT)/'`; \
	   $(CCDV) $(INSTALL_PROGRAM_ENV) $(LIBTOOL) --mode=install $(binPROGRAMS_INSTALL) "$$p" "$(DESTDIR)$(bindir)/$$f" || exit 1; \
   	if test "x#" != "x#"; then echo "Installing $$f"; fi; \
	  else :; fi; \
	done

install-libLTLIBRARIES: $(lib_LTLIBRARIES)
	@$(NORMAL_INSTALL)
	test -z "$(libdir)" || $(mkdir_p) "$(DESTDIR)$(libdir)"
	@list='$(lib_LTLIBRARIES)'; for p in $$list; do \
	  if test -f $$p; then \
	    f=$(am__strip_dir) \
	    $(CCDV) $(LIBTOOL) --mode=install $(libLTLIBRARIES_INSTALL) $(INSTALL_STRIP_FLAG) "$$p" "$(DESTDIR)$(libdir)/$$f"; \
   	if test "x#" != "x#"; then echo "Installing $$f"; fi; \
	  else :; fi; \
	done

install-neoSCRIPTS: $(neo_SCRIPTS)
	@$(NORMAL_INSTALL)
	test -z "$(neodir)" || $(mkdir_p) "$(DESTDIR)$(neodir)"
	@list='$(neo_SCRIPTS)'; for p in $$list; do \
	  if test -f "$$p"; then d=; else d="$(srcdir)/"; fi; \
	  if test -f $$d$$p; then \
	    f=`echo "$$p" | sed 's|^.*/||;$(transform)'`; \
	    $(CCDV) $(neoSCRIPT_INSTALL) "$$d$$p" "$(DESTDIR)$(neodir)/$$f"; \
	  else :; fi; \
	done
distcleancheck:
		@:
distuninstallcheck:
		@:
# Tell versions [3.59,3.63) of GNU make to not export all variables.
# Otherwise a system limit (for SysV at least) may be exceeded.
.NOEXPORT:
