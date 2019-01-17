bin_PROGRAMS = passmanager

passmanager_SOURCES = src/passmanager.c

bin_SCRIPTS =

man_MANS = man/passmanager.1

docdir = $(datadir)/doc/@PACKAGE@
doc_DATA =

exampledir = $(datarootdir)/doc/@PACKAGE@
example_DATA =

install-exec-hook:
	chmod 4755 "$(DESTDIR)$(bindir)/passmanager$(EXEEXT)" && \
	ln -s /usr/local/share/man/man1/passmanager.1 /usr/share/man/man1/passmanager.1

