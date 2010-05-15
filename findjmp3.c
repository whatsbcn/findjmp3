/////////////////////////////////////////////////////////////////////////////
//
// findjmp3.c - justin sunwoo kim
// t1g3r @t sapheads d.t org
//
/////////////////////////////////////////////////////////////////////////////

//TODO
// 1. custom byte search
// 2. split searching mode to: file mode & library mode
// 3. fuse getOpcode() with getOpcodeR() - only ptr difference
// 4. ROP chunks, show only unique instruction
// 5. libc process segment information and search only on valid segments
// (check exec permission if possible)
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <getopt.h>
#include <link.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "findjmp3.h"

// returns cpu info
// this one looks fanciest so comes on top
// later to be used to detect CPU and use right opcode set
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

// matchWild();
// findjmp3 ver of memcmp with wild card support
// it will work with non-wildcard opcodes also tho
// returns num of wild cards detected
// return 0 if matching (w/o wild card): shouldn't really be the case
//  as checked by previous function with memcmp()
// returns 0 < r; when in error
// @in: uchar *pData
// @in: struct op *stOp
// @out: uchar *a_operbytes
//
int matchWild(uchar *pData, struct op *stOp, uchar **a_operbytes)
{
  // printf("-- matchWild()-ing\n");
  uint uiWildCount = 0;
  uint uiWildOffset = 0;
  uint uiCount = 0;
  uint i;
  bool bState = false;

  // operand save space
  uchar offs[MAX_OFFSET_SIZE];

  memset(&offs, 0, MAX_OFFSET_SIZE);

  for(i = 0; i < stOp->oplen; i++)
  {
    if('*' == stOp->opbytes[i])
    {
      uiCount++;
      uiWildCount++;
      offs[uiWildOffset++] = pData[i];
      continue;
    }

    // if not wild card, and match, increase count
    if(stOp->opbytes[i] == pData[i])
    {
      uiCount++;
    }
    // if byte != byte (does not match)
    else
    {
      return -1;
    }
  }

  if(0 < uiWildCount)
  {
    // save operand bytes
    *a_operbytes = malloc(MAX_OFFSET_SIZE);
    if(0 == *a_operbytes)
      return -2;
    memset(*a_operbytes, 0, MAX_OFFSET_SIZE);
    memcpy(*a_operbytes, &offs, MAX_OFFSET_SIZE);
  }
  else
  {
    printf("regular no operbytes\n");
    *a_operbytes = 0;
  }

  // printf("-- match with wild card!\n");
  return uiWildCount;
}

// partial copy
// opbytes,opname,.. stays same (same ptr)
// but operbytes will be 
struct op* copyStOp(struct op *a_stOp)
{
  uint uiSize = sizeof(struct op);
  struct op *stOp = malloc(uiSize);
  if(0 == stOp)
    return -2;

  memset(stOp, 0, uiSize);
  memcpy(stOp, a_stOp, uiSize);

  return stOp;
}

void delStOp(struct op *a_stOp)
{
  if(0 != a_stOp)
  {
    if(0 != a_stOp->operbytes)
    {
      free(a_stOp->operbytes);
    }
    free(a_stOp);
  }
}


// getOpcode();
// Returns true if pData ptr is at some instruction
// Iterates to see if current data ptr is at ret-equivalent instructions
int getOpcode(uint uiOptype, uchar *pData, struct op** a_stOp)
{
  // printf("- getOpcode\n");
  uint i;
  int r;
  uchar *oper;
  bool bFound = false;
    bool bWild = false;  // dep on bFound

  struct op *stOp;

  for(i = 0; i < opcount; i++)
  {
    if(uiOptype == opcodes[i].optype)
    {
      if(0 == memcmp(pData, opcodes[i].opbytes, opcodes[i].oplen))
      {
        bFound = true;
        //printf("- *memcmp match\n");
      }
      // if memcmp failed, try using wild card compare
      else if(0 <= (r = matchWild(pData, &opcodes[i], &oper)) )
      {
          bFound = bWild = true;
        //printf("- *wild card match\n");
      }

      // if opcode found, copy it
      if(bFound)
      {
        stOp = copyStOp(&opcodes[i]);
        // if it was wild card matching, save operand bytes
        if(bWild)
        {
          stOp->operlen = r;
          stOp->operbytes = oper;
        }
        *a_stOp = stOp;
        return stOp->oplen;        
      }
      
    }
  }

  //printf("- getOpcode exit\n");
  // if none found, return 0
  a_stOp = 0;
  return 0;
}

// getOpcodeR();
// Returns >0 if pData ptr is at end of the intruction
// Iterates backwards to see if current data ptr is at the end of
// valid instruction opcodes
int getOpcodeR(uint uiOptype, uchar *pData, struct op** a_stOp)
{
  //printf("- getOpcodeR start: %d---\n", uiOptype);
  uint i;
  int r;
  uint uiLen;
  uchar *oper = 0;
  bool bFound = false;
    bool bWild = false;

  struct op *stOp;

  for(i = 0; i < opcount; i++)
  {
    if(uiOptype == opcodes[i].optype)
    {
      uiLen = opcodes[i].oplen;
      if(0 == memcmp(pData-(uiLen-1), opcodes[i].opbytes, uiLen))
      {
        bFound = true;
        //printf("opcodeR bFound = true\n");
      }

      // if it's wild card match
      else if( 0 < (r = matchWild(pData-(uiLen-1), &opcodes[i], &oper)) )
      {
        bFound = bWild = true;
        //printf("opcodeR bWild = true (r=%d)\n",r);
      }

      // if found, copy stOp
      if(bFound)
      {
        stOp = copyStOp(&opcodes[i]);

        // unfortunate initialization
        stOp->operlen = 0;
        stOp->operbytes = 0;

        if(bWild)
        {
          stOp->operlen = r;
          stOp->operbytes = oper;
        }
        *a_stOp = stOp;
        // rintf("Found [%s] in getOpcodeR\n", stOp->opname);
        return stOp->oplen;
      }
    }
  }
  // printf("- getOpcodeR exit\n");
  a_stOp = 0;
  return 0;
}

// a function to determine if this opcode has wild card in it
bool isWild(struct op* a_stOp)
{
  uint i;
  for(i=0;i<a_stOp->oplen;i++)
    if('*' == a_stOp->opbytes[i])
      return true;
  return false;
}



// getLibAddr();
// Aux func to find address of libc lib
int getLibAddr(struct dl_phdr_info *info, size_t size, void *data)
{
  uint j;
  struct memseg *stMemSeg = g_pLibSegList;

  if(strstr(info->dlpi_name, "libc"))
  {
    g_pLibAddr = (void*)info->dlpi_addr;
    g_szLibPath = malloc(strlen(info->dlpi_name) + 1);
    strcpy(g_szLibPath, info->dlpi_name);

    for(j=0; j<info->dlpi_phnum; j++)
    {
      // lib segment size check
      if(MIN_SEG_SIZE > info->dlpi_phdr[j].p_memsz)
        continue;

      if(0 == stMemSeg)
      {
        g_pLibSegList = malloc(sizeof(struct memseg));
        memset(g_pLibSegList, 0, sizeof(struct memseg));
        stMemSeg = g_pLibSegList;
      }
      else
      {
        stMemSeg->next = malloc(sizeof(struct memseg));
        memset(stMemSeg->next, 0, sizeof(struct memseg));
        stMemSeg = stMemSeg->next;
        memset(stMemSeg, 0, sizeof(struct memseg));
      }

      //save segment addr and size
      stMemSeg->ptr = g_pLibAddr + info->dlpi_phdr[j].p_vaddr;
      stMemSeg->size = info->dlpi_phdr[j].p_memsz;

    }

    return 1;
  }
  return 0;
}

/* Search functions */
// Search Stack Jugglers
// * stack jugglers are to be defined to be any (pop || push)* && ret
// * better to find c3 first (then backward) than to find (pop || push) first
int findJug(uchar *pData, uint uiLen)
{
  uint uiCount = 0;
  uint i;
  uint r;
  
  char **jugs;
  bool bIsUseful;
  uchar *pAddr;

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
          pAddr -= stOpPrev->oplen;
          printf("[%s] ", stOpPrev->opname);
          delStOp(stOpPrev);
        }
        else if(getOpcodeR(OPTYPE_PUSH, pAddr-1, &stOpPrev))
        {
          pAddr -= stOpPrev->oplen;
          printf("[%s] ", stOpPrev->opname);
          delStOp(stOpPrev);
        }
        else
          break;
      }

      printf("[%s] @ %p\n", stOpRet->opname, HEAP_BASEADDR + (pAddr - pData));
      delStOp(stOpRet);
      uiCount++;
    }
  }

  return uiCount;
}

// Search jmp & call
int findJmpCall(uchar *pData, uint uiLen)
{
  uint uiCount = 0;
  uint i, j;
  uint r;

  uchar *pAddr;

  struct op* stOp;

  for(i = 0; i < uiLen; i++)
  {
    if(getOpcode(OPTYPE_JMP, pData+i, &stOp))
    {
      pAddr = pData + i;
      if(0 < stOp->operlen)
      {
        printf(" - [%s] @ %p (oper: ", stOp->opname, HEAP_BASEADDR + i);
        for(j = 0; j < stOp->operlen; j++)
        {
          printf("%02x ", stOp->operbytes[j]);
        }
        printf(")\n");
      }
      else
      {
        printf(" - [%s] @ %p\n", stOp->opname, HEAP_BASEADDR + i);
      }

      delStOp(stOp);
      uiCount++;
    }
    else if(getOpcode(OPTYPE_CALL, pData+i, &stOp))
    {
      pAddr = pData + i;
      printf(" - [%s] @ %p\n", stOp->opname, HEAP_BASEADDR + i);
      delStOp(stOp);
      uiCount++;
    }
  }

  return uiCount;
}

// Search c3 chunks for ROP
int findChunk(uchar *pAddr, uint uiLen)
{
  uint uiCount = 0;
  uint i;

  bool bFound;

  struct op* stOpRet;
  struct op* stOpPrev;

  struct memseg *stMemSeg;
  struct memseg *stMemSegTmp;

  printf("[+] Segment: %p (0x%x)\n", pAddr, uiLen);

  for(i = 0; i < uiLen; i++)
  {
    pAddr = g_pLibAddr + i;
    if(pAddr+i > g_pLibSegList->ptr + g_pLibSegList->size)
    {
      // printf("something's wrong\n");
      // printf("%p + %d\n", pAddr, i);
      break;
    }

    bFound = false;

    if(getOpcode(OPTYPE_RET, pAddr+i, &stOpRet))
    {
      pAddr -= stOpRet->oplen;
      while(1)
      {
        // search for the chunks in front of ret
        if(getOpcodeR(OPTYPE_CALL, pAddr-1, &stOpPrev)
          || getOpcodeR(OPTYPE_PUSH, pAddr-1, &stOpPrev)
          || getOpcodeR(OPTYPE_POP, pAddr-1, &stOpPrev)
          || getOpcodeR(OPTYPE_MOV, pAddr-1, &stOpPrev)
          || getOpcodeR(OPTYPE_ADD, pAddr-1, &stOpPrev)
          || getOpcodeR(OPTYPE_SUB, pAddr-1, &stOpPrev)
          || getOpcodeR(OPTYPE_LEA, pAddr-1, &stOpPrev)
          || getOpcodeR(OPTYPE_XOR, pAddr-1, &stOpPrev)
          || getOpcodeR(OPTYPE_CMP, pAddr-1, &stOpPrev)
          || getOpcodeR(OPTYPE_TEST, pAddr-1, &stOpPrev))
        {
          if(!bFound)
          {
            bFound = true;
            printf(" - ");
          }

          printf("[%s] ", stOpPrev->opname);
          pAddr -= stOpPrev->oplen;
          delStOp(stOpPrev);
        }
        else
          break;
       }

      if(bFound)
        printf("[%s] @ %p\n", stOpRet->opname, pAddr);

      uiCount++;
      delStOp(stOpRet);
    }

  } // end of for

  return uiCount;
}


int findReg(uchar *pData, uint uiLen);

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
  uchar *pFileData = 0;
  //char **ppList = 0; <- where was i gon use it?

  struct memseg *stMemSeg;
  struct memseg *stMemSegTmp;
  
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

  //printf("[+] Num of opcodes: jmp=%d, call=%d, push=%d, pop=%d, ret=%d\n",
  //  g_jmp_count, g_call_count, g_push_count, g_pop_count, g_ret_count);

  //printf("[+] Num of opcodes registered: %d\n", opcount);
  
  getCPUInfo(&uiCPUID, (char*)&szCPUName);
  printf("[+] CPU: %s (type:0x%x)\n", szCPUName, uiCPUID);

  //parse cmdline options
  while((opt = getopt(argc,argv,"asjcdr:h")) != -1)
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

      case 'd':
      g_bDebug = true;
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
    if(0 > dl_iterate_phdr(getLibAddr, NULL))
    {
      printf("[-] Could not locate libc library!\n");
    }
    else
    {

      printf("[+] LIBC lib @ %p\n", g_pLibAddr);
      printf("[+] LIBC path: %s\n", g_szLibPath);

      stMemSeg = g_pLibSegList;
      // iterate on lib segment to find chunks
      while(stMemSeg)
      {
        findChunk(stMemSeg->ptr, stMemSeg->size);
        stMemSeg = stMemSeg->next;
      }

      // free lib segment list
      stMemSeg = g_pLibSegList;
      while(stMemSeg)
      {
        stMemSegTmp = stMemSeg->next;
        free(stMemSeg);
        stMemSeg = stMemSegTmp;
      }

    }
    printf("------------------------------------------\n");
  }

  printf("[v] Thank you, come again! uh-heung! r0ar!\n");	 
  return 0;
}
