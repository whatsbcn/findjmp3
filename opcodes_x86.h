/////////////////////////////////////////////////////////////////////////////
//
// findjmp3.c - justin sunwoo kim
// t1g3r @t sapheads d.t org
//
/////////////////////////////////////////////////////////////////////////////

#ifndef _FINDJMP3_OPCODES_X86_H_
#define _FINDJMP3_OPCODES_X86_H_

struct op opcodes[300] =
{
  /// JMP: 15
  
  { OPTYPE_JMP, "\xff\xe0", 2, "jmp eax" },
  { OPTYPE_JMP, "\xff\xe3", 2, "jmp ebx" },
  { OPTYPE_JMP, "\xff\xe1", 2, "jmp ecx" },
  { OPTYPE_JMP, "\xff\xe2", 2, "jmp edx" },
  { OPTYPE_JMP, "\xff\xe7", 2, "jmp edi" },
  { OPTYPE_JMP, "\xff\xe6", 2, "jmp esi" },
  { OPTYPE_JMP, "\xff\xe4", 2, "jmp esp" },
  { OPTYPE_JMP, "\xff\xe5", 2, "jmp ebp" },
  
  { OPTYPE_JMP, "\xff\x20", 2, "jmp *eax" },
  { OPTYPE_JMP, "\xff\x23", 2, "jmp *ebx" },
  { OPTYPE_JMP, "\xff\x21", 2, "jmp *ecx" },
  { OPTYPE_JMP, "\xff\x22", 2, "jmp *edx" },
  { OPTYPE_JMP, "\xff\x27", 2, "jmp *edi" },
  { OPTYPE_JMP, "\xff\x26", 2, "jmp *esi" },
  { OPTYPE_JMP, "\xff\x24\x24", 3, "jmp *esp" },
  { OPTYPE_JMP, "\xff\x65\x00", 3, "jmp *ebp" },

  { OPTYPE_JMP, "\xff\x25****", 6, "jmp ****" },
  { OPTYPE_JMP, "\xe9****", 5, "jmp (-) ****" },

  /// CALL: 15
  
  { OPTYPE_CALL, "\xff\xd0", 2, "call eax" },
  { OPTYPE_CALL, "\xff\xd3", 2, "call ebx" },
  { OPTYPE_CALL, "\xff\xd1", 2, "call ecx" },
  { OPTYPE_CALL, "\xff\xd2", 2, "call edx" },
  { OPTYPE_CALL, "\xff\xd7", 2, "call edi" },
  { OPTYPE_CALL, "\xff\xd6", 2, "call esi" },
  { OPTYPE_CALL, "\xff\xd4", 2, "call esp" },
  { OPTYPE_CALL, "\xff\xd5", 2, "call ebp" },
  
  { OPTYPE_CALL, "\xff\x10", 2, "call *eax" },
  { OPTYPE_CALL, "\xff\x13", 2, "call *ebx" },
  { OPTYPE_CALL, "\xff\x11", 2, "call *ecx" },
  { OPTYPE_CALL, "\xff\x12", 2, "call *edx" },
  { OPTYPE_CALL, "\xff\x17", 2, "call *edi" },
  { OPTYPE_CALL, "\xff\x16", 2, "call *esi" },
  { OPTYPE_CALL, "\xff\x14\x24", 3, "call *esp" },
  { OPTYPE_CALL, "\xff\x55\x00", 3, "call *ebp" },
  
  /// PUSH: 15
  
  { OPTYPE_PUSH, "\x50", 1, "push eax" },
  { OPTYPE_PUSH, "\x53", 1, "push ebx" },
  { OPTYPE_PUSH, "\x51", 1, "push ecx" },
  { OPTYPE_PUSH, "\x52", 1, "push edx" },
  { OPTYPE_PUSH, "\x57", 1, "push edi" },
  { OPTYPE_PUSH, "\x56", 1, "push esi" },
  { OPTYPE_PUSH, "\x54", 1, "push esp" },
  { OPTYPE_PUSH, "\x55", 1, "push ebp" },
  
  { OPTYPE_PUSH, "\xff\x30", 2, "push *eax" },
  { OPTYPE_PUSH, "\xff\x33", 2, "push *ebx" },
  { OPTYPE_PUSH, "\xff\x31", 2, "push *ecx" },
  { OPTYPE_PUSH, "\xff\x32", 2, "push *edx" },
  { OPTYPE_PUSH, "\xff\x37", 2, "push *edi" },
  { OPTYPE_PUSH, "\xff\x36", 2, "push *esi" },
  { OPTYPE_PUSH, "\xff\x34\x24", 3, "push *esp" },
  { OPTYPE_PUSH, "\xff\x75\x00", 3, "push *ebp" },

  { OPTYPE_PUSH, "\x68****", 4, "push ****" },
  
  /// POP: 8
  
  { OPTYPE_POP, "\x58", 1, "pop eax" },
  { OPTYPE_POP, "\x5b", 1, "pop ebx" },
  { OPTYPE_POP, "\x59", 1, "pop ecx" },
  { OPTYPE_POP, "\x5a", 1, "pop edx" },
  { OPTYPE_POP, "\x5f", 1, "pop edi" },
  { OPTYPE_POP, "\x5e", 1, "pop esi" },
  { OPTYPE_POP, "\x5c", 1, "pop esp" },
  { OPTYPE_POP, "\x5d", 1, "pop ebp" },

  /// RET: 2
  
  { OPTYPE_RET, "\xc3", 1, "ret" },

  /// MOV
  { OPTYPE_MOV, "\x89\xe5", 2, "mov esp ebp" },
  { OPTYPE_MOV, "\x89\xe1", 2, "mov esp ecx" },

  { OPTYPE_MOV, "\x89\xc7", 2, "mov eax edi" },
  { OPTYPE_MOV, "\x89\xc2", 2, "mov eax edx" },
  { OPTYPE_MOV, "\x89\xd0", 2, "mov edx eax" },
  { OPTYPE_MOV, "\x89\xc6", 2, "mov eax esi" },

  { OPTYPE_MOV, "\x8b\x36", 2, "mov (esi) esi" },
  { OPTYPE_MOV, "\x8b\x00", 2, "mov (eax) eax" },


  { OPTYPE_MOV, "\xbf****", 5, "mov [ ] edi" },
  { OPTYPE_MOV, "\xa1****", 5, "mov [ ] eax" },
  { OPTYPE_MOV, "\xbb****", 5, "mov [ ] ebx" },

  { OPTYPE_MOV, "\x89\x5c\x24*", 4, "mov ebx, [ ](esp)" },
  { OPTYPE_MOV, "\x89\x14\x24", 3, "mov edx (esp)" },
  { OPTYPE_MOV, "\x89\x04\x24", 3, "mov eax (esp)" },

  { OPTYPE_MOV, "\xc6\x05*****", 7, "mov [] *[]" },
  { OPTYPE_MOV, "\x89\x44\x24\x08", 4, "mov eax, 0x8(esp)" },
  { OPTYPE_MOV, "\x8b\x45\x08", 3, "mov 0x8(ebp) eax" },
  { OPTYPE_MOV, "\x8b\x40\x08", 3, "mov 0x8(eax) eax" },

  /// ADD
  { OPTYPE_ADD, "\x01\xc0", 2, "add eax eax" },
  { OPTYPE_ADD, "\x01\xd0", 2, "add edx eax" },
  { OPTYPE_ADD, "\x83\xc0*", 3, "add [] eax" },
  { OPTYPE_ADD, "\x81\xc3****", 6, "add [] ebx" },
  { OPTYPE_ADD, "\x05****", 5, "add [] eax" },

  /// SUB
  { OPTYPE_SUB, "\x83\xec*", 3, "sub * esp" },
  { OPTYPE_SUB, "\x83\xeb*", 3, "sub * ebx" },

  /// LEAVE

  /// XOR
  { OPTYPE_XOR, "\x31\xed", 2, "xor ebp ebp" },
  { OPTYPE_XOR, "\x31\xc0", 2, "xor eax eax" },
  { OPTYPE_XOR, "\x31\xf6", 2, "xor esi esi" },


  /// AND

  /// NOT

  /// COND- JMP (jz, jnz, jae, jne, ..)
  

  /// CMP
  { OPTYPE_CMP, "\x39\xd8", 2, "cmp ebx eax" },
  { OPTYPE_CMP, "\x39\xc1", 2, "cmp eax ecx" },
  { OPTYPE_CMP, "\x38\xc2", 2, "cmp al dl" },
  { OPTYPE_CMP, "\x39\xfe", 2, "cmp edi esi" },


  { OPTYPE_CMP, "\x3c*", 2, "cmp * al" },
  { OPTYPE_CMP, "\x3d****", 5, "cmp **** al" },
  { OPTYPE_CMP, "\x3b\x45*", 3, "cmp [](ebp) eax" }

  /// TEST


  /// LEA

  
}
#endif
