#
#Autor: Sara Skutova, xskuto00@stuf.fit.vutbr.cz
#Projekt: Projekt do predmetu ISA - FTP/SSH Honeypot
#Pouzito z meho projektu do IPK
#Datum: 15.10.2015
#

CC = g++
CFLAGS = -Wall -Wextra -pedantic
LDFLAGS = -lpthread -lssh -lssh_threads

all: fakesrv

fakesrv: fakesrv.cpp
	$(CC) $(CFLAGS) fakesrv.cpp -o fakesrv $(LDFLAGS)

clean:
	rm -f *.o *.out fakesrv *~
