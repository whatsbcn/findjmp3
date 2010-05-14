/////////////////////////////////////////////////////////////////////////////
//
// findjmp3.h - justin sunwoo kim
// t1g3r @t sapheads d.t org
//
/////////////////////////////////////////////////////////////////////////////

#ifndef _FINDJMP3_H_
#define _FINDJMP3_H_

#include "typedefs.h"

/* Opcode Type */
#define OPTYPE_JMP    0x1
#define OPTYPE_CALL   0x2
#define OPTYPE_PUSH   0x3
#define OPTYPE_POP    0x4
#define OPTYPE_RET    0x5
#define OPTYPE_MOV    0x6
#define OPTYPE_ADD    0x7
#define OPTYPE_SUB    0x8
#define OPTYPE_LEA    0x9
#define OPTYPE_XOR    0xa

#define OPTYPE_REG_EAX    0x1000
#define OPTYPE_REG_EBX    0x1001
#define OPTYPE_REG_ECX    0x1002
#define OPTYPE_REG_EDX    0x1003
#define OPTYPE_REG_ESI    0x1004
#define OPTYPE_REG_EDI    0x1005
#define OPTYPE_REG_ESP    0x1006
#define OPTYPE_REG_EBP    0x1007

#define MAX_OFFSET_SIZE 0x10

struct op
{
  uchar optype; // OPTYPE
  uchar *opbytes; // opcode bytes
  uint oplen;    // OPCODE lenth
  uchar *opname; // OPCODE name
  uchar *operbytes; // operand bytes
  uint operlen; // operand length
};

/* couldn't find the right header file :/ */
struct dl_phdr_info
{
    Elf32_Addr dlpi_addr;
    const char *dlpi_name;
    const Elf32_Phdr *dlpi_phdr;
    Elf32_Half dlpi_phnum;
};

#include "opcodes_x86.h"
//#include "opcodes_x64.h"
//#include "opcodes_arm7.h"
//#include "opcodes_mips.h"

#define HEAP_BASEADDR  0x8048000
#define LIBC_SIZE 0x13E000

/* Search modes */
#define MODE_STACKJUG  0x1
#define MODE_JMPCALL   0x2
#define MODE_REGS      0x4
#define MODE_CHUNKS    0x8
;

/* Mini-helper functions */
int matchWild(uchar *pData, struct op *stOp, uchar **a_operbytes);
int getOpcode(uint uiOptype, uchar *pData, struct op **stOp);
int getOpcodeR(uint uiOptype, uchar *pData, struct op **stOp);

bool isWild(struct op* a_stOp);
struct op* copyStOp(struct op *a_stOp);
void delStOp(struct op *a_stOp);

/* Function prototypes */
void putHelp();
void getCPUInfo(uint *uiCPUID, char *szCPUID);

int findJug(uchar *pData, uint uiLen);
int findJmpCall(uchar *pData, uint uiLen);
int findReg(uchar *pData, uint uiLen);
int findChunk();
int findJmpCall(uchar *pData, uint uiLen);

uint opcount = sizeof(opcodes) / sizeof(struct op);

uchar *g_pLibAddr;
char *g_szLibPath;

#endif
