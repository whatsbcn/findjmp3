/////////////////////////////////////////////////////////////////////////////
//
// findjmp3.c - justin sunwoo kim
// t1g3r @t sapheads d.t org
// jskim @t sapheads d.t org
//
/////////////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "findjmp3.h"

//opcode check

// returns cpu info
void getCPUInfo(uint *uiCPUID, char *szCPUID)
{
  uint b,c,d;

  __asm__ __volatile__(
    "mov $0, %%eax\n\t"
	  "cpuid\n\t"
    :"=a"(*uiCPUID), "=b"(b), "=c"(c), "=d"(d));

  sprintf(szCPUID, "%c%c%c%c%c%c%c%c%c%c%c%c",
    0xff & b, 0xff & b >> 8, 0xff & b >> 16, 0xff & b >> 24,
    0xff & d, 0xff & d >> 8, 0xff & d >> 16, 0xff & d >> 24,
    0xff & c, 0xff & c >> 8, 0xff & c >> 16, 0xff & c >> 24);
}

void putHelp()
{
  printf("[=] findjmp3.c - Help\n");
  printf("[=]\t-s : Stack jugglers\n");
  printf("[=]\t-j : Find jumps\n");
  printf("[=]\t-c : Find chunks\n");
  printf("[=]\t-a : All of the above\n");
  printf("[=]\t-r [reg] : Register specific\n");
  printf("------------------------------------------\n");
  printf("[=] Usage: ./findjmp3 -s -j -r esp kernel32.dll\n");
  printf("[=] Usage: ./findjmp3 [target bin] -a -r esp\n");
}

/* Mini-helper functions */

// isValidOpcode();
// Returns true if pData ptr is at ret instruction
// Iterates to see if current data ptr is at ret-equivalent instructions
uint getOpcode(uint uiOptype, const char *pData, struct op** stOp)
{
  uint i;

  for(i = 0; i < opcount; i++)
  {
    if(uiOptype == opcodes[i].optype)
    {
      if(0 == memcmp(pData, opcodes[i].codes, opcodes[i].size))
      {
        *stOp = &opcodes[i];
        return opcodes[i].size;
      }
    }
  }
  stOp = 0;
  return 0;
}

// isValidOpcodeR();
// Returns true if pData ptr is at end of the intruction
// Iterates backwards to see if current data ptr is at the end of
// valid instruction opcodes
uint getOpcodeR(uint uiOptype, const char *pData, struct op** stOp)
{
  uint i;
  uint uiLen;

  for(i = 0; i < opcount; i++)
  {
    if(uiOptype == opcodes[i].optype)
    {
      uiLen = opcodes[i].size;
      if(0 == memcmp(pData-(uiLen-1), opcodes[i].codes, uiLen))
      {
        *stOp = &opcodes[i];
        return opcodes[i].size;
      }
    }
  }
  stOp = 0;
  return 0;
}

/* Search functions */
// Search Stack Jugglers
// * stack jugglers are to be defined to be any (pop || push)* && ret
// * better to find c3 first (then backward) than to find (pop || push) first
uint findJug(void *pData, uint uiLen)
{
  uint uiCount = 0;
  uint i;
  uint r;
  
  char **jugs;
  bool bIsUseful;
  void *pAddr;

  struct op *stOpPrev;
  struct op *stOpRet;


  for(i = 0; i < uiLen; i++)
  {
    if(getOpcode(OPTYPE_RET, pData+i, &stOpRet))
    {
      // save the addr for being ret
      pAddr = pData + i;
      //printf("[*] %p: ", HEAP_BASEADDR + i);

      printf(" - ");

      // look for repeated pop || ret (later + more add, sub, pushad, ..)
      while(1)
      {
        if(getOpcodeR(OPTYPE_POP, pAddr-1, &stOpPrev))
        {
          pAddr -= stOpPrev->size;
          printf("[%s] ", stOpPrev->label);
        }
        else if(getOpcodeR(OPTYPE_PUSH, pAddr-1, &stOpPrev))
        {
          pAddr -= stOpPrev->size;
          printf("[%s] ", stOpPrev->label);
        }
        else
          break;
      }
      printf("[%s] @ %p\n", stOpRet->label, HEAP_BASEADDR + (pAddr - pData));
    }
  }

  return uiCount;
}

// Search jmp & call
uint findJmpCall(void *pData, uint uiLen)
{
  uint uiCount = 0;
  uint i;
  uint r;

  void *pAddr;

  struct op* stOp;

  for(i = 0; i < uiLen; i++)
  {
    if(getOpcode(OPTYPE_JMP, pData+i, &stOp))
    {
      pAddr = pData + i;
      printf(" - [%s] @ %p\n", stOp->label, HEAP_BASEADDR + i);
    }
    else if(getOpcode(OPTYPE_CALL, pData+i, &stOp))
    {
      pAddr = pData + i;
      printf(" - [%s] @ %p\n", stOp->label, HEAP_BASEADDR + i);
    }
  }

  return uiCount;
}

uint findReg(void *pData, uint uiLen);
uint findChunk(void *pData, uint uiLen);

// entry point of findjmp3
int main(int argc, char *argv[])
{
  // numeros
  uint opt;
  uint mode = 0;
  uint uiCPUID = 0;
  uint uiFileSize = 0;
  uint r;
  
  // strings
  char *szTargetFilePath = 0;
  char *szTargetReg = 0;
  char szCPUName[13] = {0,};
  
  // memory
  void *pFileData = 0;
  char **ppList = 0;
  
  // file
  FILE *fp = 0;
  struct stat stFile;

  printf("------------------------------------------\n");
  printf("[*] findjmp3.c - t1g3r @t sapheads d.t org\n");
  printf("------------------------------------------\n");

  //arg check
  if(2 > argc)
  {
    putHelp();
	  return -1;
  }

//  printf("[+] Num of opcodes: jmp=%d, call=%d, push=%d, pop=%d, ret=%d\n",
 //   g_jmp_count, g_call_count, g_push_count, g_pop_count, g_ret_count);

  printf("[+] Num of opcodes registered: %d\n", opcount);
  
  getCPUInfo(&uiCPUID, (char*)&szCPUName);
  printf("[+] CPU: %s (type:0x%x)\n", szCPUName, uiCPUID);

  //parse cmdline options
  while((opt = getopt(argc,argv,"asjcr:h")) != -1)
  {
    switch(opt)
    {
      case 's':
      mode |= MODE_STACKJUG;
      break;

      case 'j':
      mode |= MODE_JMPCALL;
      break;

      case 'r':
      mode |= MODE_REGS;
      if(0 != optarg)
        szTargetReg = optarg;
      break;

      case 'c':
      mode |= MODE_CHUNKS;
      break;

      case 'a':
      mode |= MODE_STACKJUG | MODE_JMPCALL | MODE_CHUNKS;
      break;

      case 'h':
      default:
      putHelp();
      return 0;
    }
  }

  // if there is any more arg left, take it as file name
  if(optind < argc)
    szTargetFilePath = argv[optind];
  else
  {
	  printf("[-] Error: File name not specifid.\n");
	  return -2;
  }

  printf("[+] Target file: %s\n", szTargetFilePath);

  // get file stat
  memset(&stFile, 0, sizeof(struct stat));

  r = stat(szTargetFilePath, &stFile);
  if(0 != r)
    return -3;

  // store file size
  uiFileSize = stFile.st_size;
    
  // open file
  fp = fopen(szTargetFilePath, "r+");
  if(0 == fp)
    return -4;
    
  // alloc file mem
  pFileData = malloc(uiFileSize);
  if(0 == pFileData)
    // low mem
    return -5;

  // read in file
  r = fread(pFileData, uiFileSize, 1, fp);
  if(0 == r)
    // if file data none read
    return -6;
  
  printf("[+] File size: %d bytes\n", uiFileSize);

  //printf("[+] Mode: 0x%x\n", mode);
  printf("------------------------------------------\n");

  //STACK JUGGLERS
  if(mode & MODE_STACKJUG)
  {
    printf("[+] Searching for stack jugglers.. (pop,add,ret)\n");
    printf("------------------------------------------\n");
    findJug(pFileData, uiFileSize);
    printf("------------------------------------------\n");
  }

  //JMP & CALL s
  if(mode & MODE_JMPCALL)
  {
    printf("[+] Searching for jmp & call..\n");
    printf("------------------------------------------\n");
    findJmpCall(pFileData, uiFileSize);
    printf("------------------------------------------\n");
  }

  //Register-specific instructions
  if(mode & MODE_REGS)
  {
    printf("[+] Searching for '%s' instructions..\n", szTargetReg);
    printf("------------------------------------------\n");
    printf("------------------------------------------\n");
  }

  //Chunks for ROP
  if(mode & MODE_CHUNKS)
  {
    printf("[+] Searching for chunks for ROP.. c3 c3 c3\n");
    printf("------------------------------------------\n");
    printf("------------------------------------------\n");
  }

  printf("[v] Thank you, come again! r0ar!\n");	 
  return 0;
}