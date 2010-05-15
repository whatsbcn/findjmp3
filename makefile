all: findjmp3

findjmp3: findjmp3.h opcodes_x86.h findjmp3.c
	cc -o findjmp3 findjmp3.c

run:
	cc -o findjmp3 findjmp3.c
	cp findjmp3 a.out
	./findjmp3 -f a.out

debug:
	cc -o findjmp3 findjmp3.c
	cp findjmp3 a.out
	gdb -q ./findjmp3 

tarball:
	make clean
	rm -rf findjmp3.tar.gz
	tar -czf findjmp3.tar.gz *

clean:
	rm -rf findjmp3 test a.out

