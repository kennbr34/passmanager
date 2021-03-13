bin_PROGRAMS = passmanager

passmanager_SOURCES = src/printdbinfo.c src/evpencrypt.c src/evpdecrypt.c src/configevp.c src/sendwithclipboard.c src/derivekeys.c src/addentry.c src/disableptrace.c src/misc.c src/deleteentry.c src/allocatebuffers.c src/genevpsalt.c src/signciphertext.c src/main.c src/writedatabase.c src/verifyciphertext.c src/printmacerrmessage.c src/updateentry.c src/parseoptions.c src/printentry.c src/opendatabase.c src/backupdatabase.c src/updatedbenc.c src/genpassword.c src/printsyntax.c src/lockmemory.c src/printclipboardmessage.c src/cleanupbuffers.c src/getpass.c

bin_SCRIPTS =

man_MANS = man/passmanager.1

docdir = $(datadir)/doc/@PACKAGE@
doc_DATA =

exampledir = $(datarootdir)/doc/@PACKAGE@
example_DATA =

install-exec-hook:
	chmod 4755 "$(DESTDIR)$(bindir)/passmanager$(EXEEXT)"
