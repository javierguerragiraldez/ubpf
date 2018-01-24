

#include <stdbool.h>
#include "ubpf_int.h"

enum reachtype {
	kUnseen = 0,
	kFollowthrough = 0x01,
	kCondBranch = 0x02,
	kJump = 0x03,
};


#define BPF_CLASS(opcode)	((opcode) & EBPF_CLS_MASK)


static bool linear_checks(const struct ubpf_vm *vm, const struct ebpf_inst *insts, uint32_t num_insts, char **errmsg)
{
	enum reachtype reaches[num_insts+1];
	reaches[0] = kFollowthrough;

	int i;
	for (i = 0; i < num_insts; i++) {
		struct ebpf_inst inst = insts[i];
		bool store = false;

		switch (BPF_CLASS(inst.opcode)) {
			case EBPF_CLS_ALU:
			case EBPF_CLS_ALU64:
				switch (inst.opcode) {
					case EBPF_OP_LE:
					case EBPF_OP_BE:
						if (inst.imm != 16 && inst.imm != 32 && inst.imm != 64) {
							*errmsg = ubpf_error("invalid endian immediate at PC %d", i);
							return false;
						}

					case EBPF_OP_DIV_IMM:
					case EBPF_OP_MOD_IMM:
					case EBPF_OP_DIV64_IMM:
					case EBPF_OP_MOD64_IMM:
						if (inst.imm == 0) {
							*errmsg = ubpf_error("division by zero at PC %d", i);
							return false;
						}
						break;
				}
				reaches[i+1] |= kFollowthrough;
				break;

			case EBPF_CLS_LDX:
				reaches[i+1] |= kFollowthrough;
				break;

			case EBPF_CLS_LD:
				if (inst.opcode == EBPF_OP_LDDW) {
					if (i + 1 >= num_insts || insts[i+1].opcode != 0) {
						*errmsg = ubpf_error("incomplete lddw at PC %d", i);
						return false;
					}
					reaches[i+1] |= kFollowthrough;
					i++; /* Skip next instruction */
					reaches[i+1] |= kFollowthrough;
				}
				break;

			case EBPF_CLS_ST:
			case EBPF_CLS_STX:
				reaches[i+1] |= kFollowthrough;
				store = true;
				break;

			case EBPF_CLS_JMP:
				switch (inst.opcode) {
					case EBPF_OP_CALL:
						if (inst.imm < 0 || inst.imm >= MAX_EXT_FUNCS) {
							*errmsg = ubpf_error("invalid call immediate at PC %d", i);
							return false;
						}
						if (!vm->ext_funcs[inst.imm]) {
							*errmsg = ubpf_error("call to nonexistent function %u at PC %d", inst.imm, i);
							return false;
						}
						reaches[i+1] |= kFollowthrough;
						break;

					case EBPF_OP_EXIT:
						break;

					case EBPF_OP_JA:
					default:
						if (inst.offset == -1) {
							*errmsg = ubpf_error("infinite loop at PC %d", i);
							return false;
						}
						int new_pc = i + 1 + inst.offset;
						if (new_pc < 0 || new_pc >= num_insts) {
							*errmsg = ubpf_error("jump out of bounds at PC %d", i);
							return false;
						} else if (insts[new_pc].opcode == 0) {
							*errmsg = ubpf_error("jump to middle of lddw at PC %d", i);
							return false;
						}
						if (inst.opcode == EBPF_OP_JA) {
							reaches[new_pc] |= kJump;
						} else {
							reaches[new_pc] |= kCondBranch;
							reaches[i+1] |= kFollowthrough;
						}
						break;
				}
				break;

			default:
				*errmsg = ubpf_error("unknown opcode 0x%02x at PC %d", inst.opcode, i);
				return false;
		}

		if (inst.src > 10) {
			*errmsg = ubpf_error("invalid source register at PC %d", i);
			return false;
		}

		if (inst.dst > 9 && !(store && inst.dst == 10)) {
			*errmsg = ubpf_error("invalid destination register at PC %d", i);
			return false;
		}
	}

	for (i = 0; i < num_insts; i++) {
		if (reaches[i] == kUnseen) {
			*errmsg = ubpf_error("dead code at PC %d", i);
			return false;
		}
	}

	return true;
}

bool ubpf_check(const struct ubpf_vm *vm, const void *code, uint32_t code_len, char **errmsg)
{
	if (code_len % 8 != 0) {
		*errmsg = ubpf_error("Non integer number of instructions: %d\n", code_len);
		return false;
	}

	uint32_t num_insts = code_len / 8;

	if (num_insts >= MAX_INSTS) {
		*errmsg = ubpf_error("too many instructions (max %u)", MAX_INSTS);
		return false;
	}

	const struct ebpf_inst *insts = code;

	if (num_insts == 0 || insts[num_insts-1].opcode != EBPF_OP_EXIT) {
		*errmsg = ubpf_error("no exit at end of instructions");
		return false;
	}

	if (! linear_checks(vm, insts, num_insts, errmsg)) {
		return false;
	}

	return true;
}
