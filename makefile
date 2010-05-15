all: findjmp3

findjmp3: findjmp3.h opcodes_x86.h findjmp3.c
	cc -o findjmp3 findjmp3.c

clean:
	rm -rf findjmp3

