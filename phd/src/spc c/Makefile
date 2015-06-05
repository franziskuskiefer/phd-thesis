CFLAGS = -g -w -Os -std=c99 -I/usr/local/ssl/include  -I./headers -I/usr/local/lib  -I/usr/local/include -pthread -fno-stack-protector  #-arch x86_64 
LD=-L /usr/lib  -lssl -lcrypto  -L /usr/local/lib/ -lm
CC = gcc
CLEANFILES = ./*.o
PROGS= spc
OFS=AESRandom.o GarbledBF.o MessageDigest.o RandomSource.o RangeHash.o regProtocol.o Policy.o Shamir.o BF.o # 

all: struc spc

struc:./PSI/*.c  ./password/*.c
	${CC} ${CFLAGS} -c $^ 

spcMain.o: ./main.c 
	${CC} ${CFLAGS} -c -o $@ $^ 

spc:spcMain.o ${OFS}
	${CC} ${CFLAGS} -o $@ $^ $(LD)


clean:
	rm -f ${CLEANFILES}
	rm -f ${PROGS}
	rm -f *~
