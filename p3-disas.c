/*
 * CS 261 PA3: Mini-ELF disassembler
 *
 * Name: Adrien Ponce
 */

#include "p3-disas.h"

/**********************************************************************
 *                         REQUIRED FUNCTIONS
 *********************************************************************/

y86_inst_t fetch (y86_t *cpu, byte_t *memory)
{
    y86_inst_t ins;

    ins.icode = memory[cpu->pc] >> 4;       // retrieve opcode  (low order)
    ins.ifun.b = memory[cpu->pc] & 0xf;     // ... high order

    uint64_t *pc_offset_two = (uint64_t*)&memory[cpu->pc + 2];  // pointer to pc offset val (for 2 byte)
    uint64_t *pc_offset_one = (uint64_t*)&memory[cpu->pc + 1];  // pointer to pc offset val (for 1 byte)

    // calculate next instruction address
    switch (ins.icode) {
        // start of one byte instructions
        case HALT:
        case NOP:
        case RET:
            ins.valP = cpu->pc + 1;
            if (ins.ifun.b != 0) {              // invalid b value
                ins.icode = INVALID;
                cpu->stat = INS;
            }
            break;
        // start of two byte instructions
        case CMOV:
            ins.valP = cpu->pc + 2;
            ins.ra = memory[cpu->pc + 1] >> 4;  // update opcode (left then right)
            ins.rb = memory[cpu->pc + 1] & 0xf;
            if (ins.ifun.cmov > 6) {            // greater than # instructions
                ins.icode = INVALID;
                cpu->stat = INS;
            }
            break;
        case OPQ:
            ins.valP = cpu->pc + 2;
            ins.ra = memory[cpu->pc + 1] >> 4;
            ins.rb = memory[cpu->pc + 1] & 0xf;
            if (ins.ifun.op > 3) {              // greater than # instructions
                ins.icode = INVALID;
                cpu->stat = INS;
            }
            break;
        case PUSHQ:
        case POPQ:
            ins.valP = cpu->pc + 2;
            ins.ra = memory[cpu->pc + 1] >> 4;
            ins.rb = memory[cpu->pc + 1] & 0xf;
            if (ins.rb != 0xf || ins.ifun.b != 0) { // rb must = f, b invalid
                ins.icode = INVALID;
                cpu->stat = INS;
            }
            break;
        // start of 10 byte instructions
        case IRMOVQ:
            ins.valP = cpu->pc + 10;
            ins.ra = memory[cpu->pc + 1] >> 4;
            ins.rb = memory[cpu->pc + 1] & 0xf;
            if (ins.ifun.b != 0 || ins.ra != 0xf) { // ra must = f, b invalid
                ins.icode = INVALID;
                cpu->stat = INS;
            }
            // dereference offset
            ins.valC.v = *pc_offset_two;
            break;
        case RMMOVQ:
            ins.valP = cpu->pc + 10;
            ins.ra = memory[cpu->pc + 1] >> 4;
            ins.rb = memory[cpu->pc + 1] & 0xf;
            if (ins.ifun.b != 0) {  // invalid b value
                ins.icode = INVALID;
                cpu->stat = INS;
            }
            // dereference offset
            ins.valC.d = *pc_offset_two;
            break;
        case MRMOVQ:
            ins.valP = cpu->pc + 10;
            ins.ra = memory[cpu->pc + 1] >> 4;
            ins.rb = memory[cpu->pc + 1] & 0xf;
            if (ins.ifun.b != 0) {  // invalid b value
                ins.icode = INVALID;
                cpu->stat = INS;
            }
            // dereference offset
            ins.valC.d = *pc_offset_two;
            break;
        case JUMP:
            ins.valP = cpu->pc + 9;
            if (ins.ifun.b > 6) {   // greater than # instructions
                ins.icode = INVALID;
                cpu->stat = INS;
            }
            // dereference offset
            ins.valC.dest = *pc_offset_one;
            break;
        case CALL:
            ins.valP = cpu->pc + 9;
            if (ins.ifun.b != 0) {  // invalid b value
                ins.icode = INVALID;
                cpu->stat = INS;
            }
            // dereference offset
            ins.valC.dest = *pc_offset_one;
            break;
        case IOTRAP:
            ins.valP = cpu->pc + 1;
            if (ins.ifun.b > 5) {   // greater than # instructions
                ins.icode = INVALID;
                cpu->stat = INS;
            }
            break;
        case INVALID:
            break;
    }
    return ins;
}

/**********************************************************************
 *                         OPTIONAL FUNCTIONS
 *********************************************************************/

void usage_p3 (char **argv)
{
    printf("Usage: %s <option(s)> mini-elf-file\n", argv[0]);
    printf(" Options are:\n");
    printf("  -h      Display usage\n");
    printf("  -H      Show the Mini-ELF header\n");
    printf("  -a      Show all with brief memory\n");
    printf("  -f      Show all with full memory\n");
    printf("  -s      Show the program headers\n");
    printf("  -m      Show the memory contents (brief)\n");
    printf("  -M      Show the memory contents (full)\n");
    printf("  -d      Disassemble code contents\n");
    printf("  -D      Disassemble data contents\n");
}

bool parse_command_line_p3 (int argc, char **argv,
                            bool *print_header, bool *print_segments,
                            bool *print_membrief, bool *print_memfull,
                            bool *disas_code, bool *disas_data, char **filename)
{
    // brief error checking for NULL
    if (argv == NULL || print_header == NULL || print_segments == NULL
            || print_membrief == NULL || print_memfull == NULL
            || disas_code == NULL || disas_data == NULL || filename == NULL) {
        return false;
    }

    int c;
    while ((c = getopt(argc, argv, "hHafsmMdD")) != -1) {
        switch (c) {
            case 'h':                   // display usage
                usage_p3(argv);
                return true;
            case 'H':                   // display Mini-Elf header
                *print_header = true;
                break;
            case 'a':                   // display H, s, m flags
                *print_header = true;
                *print_segments = true;
                *print_membrief = true;
                break;
            case 'f':                   // display H, s, M flags
                *print_header = true;
                *print_segments = true;
                *print_memfull = true;
                break;
            case 's':                   // display program headers
                *print_segments = true;
                break;
            case 'm':                   // display brief memory contents
                *print_membrief = true;
                break;
            case 'M':                   // display full memory contents
                *print_memfull = true;
                break;
            case 'd':                   // dissasemble code
                *disas_code = true;
                break;
            case 'D':                   // dissasemble data
                *disas_data = true;
                break;
            default:                    // display usage (default)
                usage_p3(argv);
                return false;
        }
    }

    if (optind != argc-1) {
        // no filename (or extraneous input)
        usage_p3(argv);
        return false;
    }

    *filename = argv[optind];   // save filename

    return true;
}

void disassemble (y86_inst_t inst)
{
    switch (inst.icode) {
        case HALT:
            printf("halt");
            break;
        case NOP:
            printf("nop");
            break;
        case RET:
            printf("ret");
            break;
        // start of cmovXX instructions
        case CMOV:
            switch (inst.ifun.cmov) {
                case RRMOVQ:
                    printf("rrmovq ");
                    check_reg(inst.ra);
                    printf(", ");
                    check_reg(inst.rb);
                    break;
                case CMOVLE:
                    printf("cmovle ");
                    check_reg(inst.ra);
                    printf(", ");
                    check_reg(inst.rb);
                    break;
                case CMOVL:
                    printf("cmovl ");
                    check_reg(inst.ra);
                    printf(", ");
                    check_reg(inst.rb);
                    break;
                case CMOVE:
                    printf("cmove ");
                    check_reg(inst.ra);
                    printf(", ");
                    check_reg(inst.rb);
                    break;
                case CMOVNE:
                    printf("cmovne ");
                    check_reg(inst.ra);
                    printf(", ");
                    check_reg(inst.rb);
                    break;
                case CMOVGE:
                    printf("cmovge ");
                    check_reg(inst.ra);
                    printf(", ");
                    check_reg(inst.rb);
                    break;
                case CMOVG:
                    printf("cmovg ");
                    check_reg(inst.ra);
                    printf(", ");
                    check_reg(inst.rb);
                    break;
                case BADCMOV:
                    break;
            }
            break;
        // special cases
        case IRMOVQ:
            printf("irmovq");
            check_dest(inst);
            break;
        case RMMOVQ:
            printf("rmmovq ");
            check_dest(inst);
            break;
        case MRMOVQ:
            printf("mrmovq");
            check_dest(inst);
            break;
        case OPQ:
            // start of opX instructions
            switch (inst.ifun.op) {
                case ADD:
                    printf("addq ");
                    check_reg(inst.ra);
                    printf(", ");
                    check_reg(inst.rb);
                    break;
                case SUB:
                    printf("subq ");
                    check_reg(inst.ra);
                    printf(", ");
                    check_reg(inst.rb);
                    break;
                case AND:
                    printf("andq ");
                    check_reg(inst.ra);
                    printf(", ");
                    check_reg(inst.rb);
                    break;
                case XOR:
                    printf("xorq ");
                    check_reg(inst.ra);
                    printf(", ");
                    check_reg(inst.rb);
                    break;
                case BADOP:
                    break;
            }
            break;
        case PUSHQ:
            printf("pushq ");
            check_reg(inst.ra);
            break;
        case POPQ:
            printf("popq ");
            check_reg(inst.ra);
            break;
        // start of iotrap instructions
        case IOTRAP:
            switch (inst.ifun.trap) {
                case CHAROUT:
                    printf("iotrap %d", CHAROUT);
                    break;
                case CHARIN:
                    printf("iotrap %d", CHARIN);
                    break;
                case DECOUT:
                    printf("iotrap %d", DECOUT);
                    break;
                case DECIN:
                    printf("iotrap %d", DECIN);
                    break;
                case STROUT:
                    printf("iotrap %d", STROUT);
                    break;
                case FLUSH:
                    printf("iotrap %d", FLUSH);
                    break;
                case BADTRAP:
                    break;
            }
            break;
        // start of jXX instructions
        case JUMP:
            switch (inst.ifun.jump) {
                case JLE:
                    printf("jle");
                    check_dest(inst);
                    break;
                case JL:
                    printf("jl");
                    check_dest(inst);
                    break;
                case JE:
                    printf("je");
                    check_dest(inst);
                    break;
                case JNE:
                    printf("jne");
                    check_dest(inst);
                    break;
                case JGE:
                    printf("jge");
                    check_dest(inst);
                    break;
                case JG:
                    printf("jg");
                    check_dest(inst);
                    break;
                case JMP:
                    printf("jmp");
                    check_dest(inst);
                    break;
                case BADJUMP:
                    break;
            }
            break;
        case CALL:
            printf("call");
            check_dest(inst);
            break;
        case INVALID:
            break;
    }
}

void check_reg (y86_regnum_t reg)
{
    // checks what register an instruction uses
    // ... and prints them
    switch (reg) {
        case RAX:
            printf("%%rax");
            break;
        case RCX:
            printf("%%rcx");
            break;
        case RDX:
            printf("%%rdx");
            break;
        case RBX:
            printf("%%rbx");
            break;
        case RSP:
            printf("%%rsp");
            break;
        case RBP:
            printf("%%rbp");
            break;
        case RSI:
            printf("%%rsi");
            break;
        case RDI:
            printf("%%rdi");
            break;
        case R8:
            printf("%%r8");
            break;
        case R9:
            printf("%%r9");
            break;
        case R10:
            printf("%%r10");
            break;
        case R11:
            printf("%%r11");
            break;
        case R12:
            printf("%%r12");
            break;
        case R13:
            printf("%%r13");
            break;
        case R14:
            printf("%%r14");
            break;
        case NOREG:
            break;
    }
}

void check_dest (y86_inst_t inst)
{
    // dest prints
    if (inst.icode == JUMP) {
        printf(" 0x%lx", inst.valC.dest);
    }

    if (inst.icode == CALL) {
        printf(" 0x%lx", inst.valC.dest);
    }

    // special cases dest prints
    if (inst.icode == IRMOVQ) {
        printf(" 0x%lx, ", (uint64_t) inst.valC.v);
        check_reg(inst.rb);
    }

    if (inst.icode == RMMOVQ) {
        if (inst.rb == 0x2) {   // 2 register case
            check_reg(inst.ra);
            printf(", 0x%lx", (uint64_t) inst.valC.d);
            printf("(");
            check_reg(inst.rb);
            printf(")");
        } else {                // one register
            check_reg(inst.ra);
            printf(", 0x%lx", (uint64_t) inst.valC.d);
            check_reg(inst.rb);
        }

    }

    if (inst.icode == MRMOVQ) {
        if (inst.rb == 0x2) {   // 2 reg
            printf(" 0x%lx", (uint64_t) inst.valC.d);
            printf("(");
            check_reg(inst.rb);
            printf("), ");
            check_reg(inst.ra);
        } else {            // one reg
            printf(" 0x%lx, ", (uint64_t) inst.valC.d);
            check_reg(inst.ra);
        }

    }

}

void disassemble_code (byte_t *memory, elf_phdr_t *phdr, elf_hdr_t *hdr)
{
    y86_t cpu;          // CPU struct to store "fake" PC
    y86_inst_t ins;     // struct to hold fetched instruction

    // start at beginning of the segment
    cpu.pc = phdr->p_vaddr;

    printf("  0x%03lx:                      | .pos 0x%03lx code\n", cpu.pc, cpu.pc);
    // iterate through the segment one instruction at a time
    while (cpu.pc < phdr->p_vaddr + phdr->p_filesz) {

        // go to elf entry and print start
        if (cpu.pc == hdr->e_entry) {
            printf("  0x%03lx:                      | _start:\n", cpu.pc);
        }

        ins = fetch (&cpu, memory);         // stage 1: fetch instruction

        // abort with error if instruction was invalid
        if (ins.icode == INVALID) {
        }

        // cmov, opq, pushq, and popq prints
        if (ins.icode == CMOV || ins.icode == OPQ
                || ins.icode == PUSHQ || ins.icode == POPQ) {
            printf("  0x%03lx: %x%x%x%x                 |   ",
                   cpu.pc, ins.icode, ins.ifun.b, ins.ra, ins.rb);
        }

        // all one byte instructions
        if (ins.icode == HALT || ins.icode == RET ||ins.icode == NOP) {
            printf("  0x%03lx: %02x                   |   ", cpu.pc, memory[cpu.pc]);
        }

        if (ins.icode == IOTRAP) {
            printf("  0x%03lx: %02x                   |   ", cpu.pc, memory[cpu.pc]);
        }

        if (ins.icode == JUMP || ins.icode == CALL) {
            printf("  0x%03lx: ", cpu.pc);
            int counter = 0;
            // counts & prints byte length for pc
            while (counter < 9) {
                printf("%02x", memory[cpu.pc + counter]);
                counter++;
            }
            printf("   |   ");
        }

        if (ins.icode == IRMOVQ || ins.icode == RMMOVQ
                || ins.icode == MRMOVQ) {
            printf("  0x%03lx: ", (uint64_t) cpu.pc);
            int counter = 0;
            // counts & prints byte length for pc
            while (counter < 10) {
                printf("%02x", memory[cpu.pc + counter]);
                counter++;
            }
            printf(" |   ");
        }
        disassemble (ins);                  // stage 2: print disassembly
        printf("\n");
        cpu.pc = ins.valP;                  // stage 3: update PC (go to next instruction)
    }
    printf("\n");
}

void disassemble_data (byte_t *memory, elf_phdr_t *phdr)
{
}

void disassemble_rodata (byte_t *memory, elf_phdr_t *phdr)
{
}

