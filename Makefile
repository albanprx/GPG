CFLAGS = -std=c11 -Wall -Wextra -Werror
CPPFLAGS = -I../include/
LDFLAGS = -lm

all: 
	(cd src; make all; mv GPG ..)

clean: 
	(rm GPG; cd src; make clean)

debug: 
	(rm GPG; cd src; make debug)

help:
	(cd src; make help)
	

.PHONY: all clean help