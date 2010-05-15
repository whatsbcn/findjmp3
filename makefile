all: findjmp3

findjmp3: findjmp3.h opcodes_x86.h findjmp3.c
	cc -o findjmp3 findjmp3.c

run:
	cc -o test test.c
	./findjmp3 -a -d test

debug:
	cc -o test test.c
	gdb -q ./findjmp3 

clean:
	rm -rf findjmp3 test

