/////////////////////////////////////////////////////////////////////////////
//
// findjmp3.h - justin sunwoo kim
// t1g3r @t sapheads d.t org
// jskim @t sapheads d.t org
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

#define OPTYPE_REG_EAX    0x6
#define OPTYPE_REG_EBX    0x7
#define OPTYPE_REG_ECX    0x8
#define OPTYPE_REG_EDX    0x9
#define OPTYPE_REG_ESI    0xa
#define OPTYPE_REG_EDI    0xb
#define OPTYPE_REG_ESP    0xc
#define OPTYPE_REG_EBP    0xd

struct op
{
  uchar optype; // OPTYPE
  uchar *codes; // OPCODE
  uint size;    // OPCODE lenth
  uchar *label; // OPCODE name
  uchar *operand; // OPCODE offset (operand)
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
int match(uchar *pData, struct op *stOp, uchar *offset);
int getOpcode(uint uiOptype, uchar *pData, struct op **stOp);
int getOpcodeR(uint uiOptype, uchar *pData, struct op **stOp);

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
