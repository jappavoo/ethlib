CFLAGS:=-g -O0
LDFLAGS:=-g
LIBS=-lpcap

TARGETS:=ethlibtest

.PHONY: clean

all: ${TARGETS}

ethlibtest: ethlibtest.o ethlib.o
	gcc ${LDFLAGS} -o $@ $^ ${LIBS}

ethlib.o: ethlib.c ethlib.h
	gcc ${CFLAGS} -c $< -o $@

ethlibtest.o: ethlibtest.c
	gcc ${CFLAGS} -c $< -o $@


clean:
	-${RM} -rf $(wildcard *.o ${TARGETS})
