

#include <stdbool.h>
#include <string.h>
#include "ubpf_int.h"


enum reachtype {
	kUnseen = 0,
	kFollowthrough = 0x01,
	kCondBranch = 0x02,
	kJump = 0x03,
};

#define _unused_(x)	((void)(x))

#define EBPF_CLASS(opcode)	((opcode) & EBPF_CLS_MASK)
#define EBPF_SUB_OP(opcode)	((opcode) & EBPF_ALU_OP_MASK)
#define EBPF_OPSIZE(opcode)	((opcode) & 0x18)

void ubpf_set_checking(struct ubpf_vm *vm, const char *options)
{
	while (options && *options) {
		switch (*options) {
			case 'b':
				vm->check_flags.basic = true;
				break;
			case 'l':
				vm->check_flags.loopfree = true;
				break;
			case 'd':
				vm->check_flags.dead_code = true;
				break;
			case 'p':
				vm->check_flags.all_paths = true;
				break;
		}
		options++;
	}
}


static bool linear_checks(const struct ubpf_vm *vm, const struct ebpf_inst *insts, uint32_t num_insts, char **errmsg)
{
	enum reachtype reaches[num_insts+1];
	reaches[0] = kFollowthrough;

	int i;
	for (i = 0; i < num_insts; i++) {
		struct ebpf_inst inst = insts[i];
		bool store = false;

		switch (EBPF_CLASS(inst.opcode)) {
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

// 					case EBPF_OP_JA:
					default:
						if (inst.offset == -1) {
							*errmsg = ubpf_error("infinite loop at PC %d", i);
							return false;
						}
						int new_pc = i + 1 + inst.offset;
						if (inst.offset < 0 && vm->check_flags.loopfree) {
							*errmsg = ubpf_error("Loop detected between PCs %d and %d", new_pc, i, new_pc);
							return false;
						}
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

	if (vm->check_flags.dead_code) {
		for (i = 0; i < num_insts; i++) {
			if (reaches[i] == kUnseen) {
				*errmsg = ubpf_error("dead code at PC %d", i);
				return false;
			}
		}
	}

	return true;
}


enum reg_type {
	kUnset,				// Has not been set.
	kScalar,			// an integer value
	kStackPtr,			// Pointer within the stack
	kObjectPtr,			// Pointer to or within an object.
	kObjectPtrOrNull,	// Pointer to an object or NULL.
};

struct range {
	uint64_t lo, hi;
};

struct reg_status {
	enum reg_type type;
	int object_type;		// index on registered types array
	struct range range;
};
#define reg_stat(_t, _lo, _hi, _ot)	((struct reg_status){	\
	.type=(_t), .range.lo=(_lo), .range.hi=(_hi), .object_type=(_ot)})

struct full_state {
	int pc;
	struct reg_status reg[11];
};

const int kScanStackSize = 1024;

#define stack_top()			(stack[stackP])
#define stack_pc()			(stack_top().pc)
#define stack_reg(_r)		(stack_top().reg[(_r)])
#define stack_wipe_top()	do { memset(&stack_top(), 0, sizeof(struct full_state));} while(0)
#define stack_set_pc(_pc)	do {stack_top().pc = (_pc);} while (0)
#define stack_set_reg(_r, _t, _lo, _hi, _ot)			\
do {			\
	stack_reg(_r) = (struct reg_status) {	\
		.type = (_t),		\
		.range = {.lo=(_lo), .hi=(_hi)},	\
		.object_type = (_ot),		\
	};		\
} while (0)


struct object_type {
	size_t size;
};

// TODO: set these as a vm field
enum {
	kStackSize = 1024,
};

static struct object_type deftypes[] = {
	{.size = 10},		// context
	{.size = kStackSize},	// stack
};
static const int numdeftypes = (sizeof(deftypes) / sizeof(deftypes[0]));


static bool op_reg_src(uint8_t opcode) {
	switch(EBPF_CLASS(opcode)) {
		case EBPF_CLS_LDX:
			return true;

		case EBPF_CLS_ALU:
		case EBPF_CLS_ALU64:
		case EBPF_CLS_JMP:
			return (opcode & EBPF_SRC_REG) != 0;
	}
	return false;
}

static bool op_imm_src(uint8_t opcode) {
	switch(EBPF_CLASS(opcode)) {
		case EBPF_CLS_ALU:
		case EBPF_CLS_ALU64:
		case EBPF_CLS_JMP:
			return (opcode & EBPF_SRC_REG) == 0;
	}
	return false;
}

static int wordsize(uint8_t opsize)
{
	switch (opsize) {
		case EBPF_SIZE_W:
			return 4;
		case EBPF_SIZE_H:
			return 2;
		case EBPF_SIZE_B:
			return 1;
		case EBPF_SIZE_DW:
			return 8;
		default:
			return ~0;
	}
}

static inline bool within_range(struct range a, struct range b)
{
	return a.lo >= b.lo && a.hi <= b.hi;
}

static inline bool range_eq(struct range a, struct range b)
{
	return a.lo == b.lo && a.hi == b.hi;
}

static inline bool range_intersect(struct range a, struct range b)
{
	return a.lo <= b.hi && a.hi >= b.lo;
}

static bool check_mem_read(
	const struct ubpf_vm *vm,
	const struct reg_status *src_stat,
	int16_t offset, uint8_t opsize
) {
	_unused_(vm);

	struct range valid = {0, 0};

	switch(src_stat->type) {
		case kStackPtr:
			valid.lo = -kStackSize;
			valid.hi = -wordsize(opsize);
			break;

		case kObjectPtr:
			if (src_stat->object_type >= numdeftypes) {
				return false;
			}
			valid.hi = deftypes[src_stat->object_type].size - wordsize(opsize);
			break;

		default:
			return false;
	}
	valid.lo -= offset;
	valid.hi -= offset;
	return within_range(src_stat->range, valid);
}



static bool verify_helper_requirements(
	const struct ubpf_vm *vm,
	int helper,
	const struct full_state *state,
	char **errmsg)
{
	_unused_(vm);
	_unused_(helper);
	_unused_(state);
	_unused_(errmsg);
	return true;
}

static void set_helper_results(
	const struct ubpf_vm *vm,
	int helper,
	struct full_state *state)
{
	_unused_(vm);
	_unused_(helper);
	struct reg_status unsetreg = reg_stat(kUnset, 0, 0, 0);
	for (int r = 1; r <= 5; r++) {
		state->reg[r] = unsetreg;
	}
}


static bool codepaths_scan (const struct ubpf_vm *vm, const struct ebpf_inst *insts, uint32_t num_insts, char **errmsg)
{
	struct full_state stack[kScanStackSize];
	int stackP = 0;

	stack_wipe_top();
	stack_set_pc(0);
	stack_reg(1) = reg_stat(kObjectPtr, 0, 0, 0);	// R1: context pointer
	stack_reg(10) = reg_stat(kObjectPtr, 0, 0, 1);	// R10: stack frame pointer (TODO: make it RO)
	if (numdeftypes < 2) {
		*errmsg = ubpf_error("Undefined object type %d.", 0);
		return false;
	}

	while (stackP >= 0) {
		const struct ebpf_inst inst = insts[stack_pc()];

		struct reg_status src_datastatus = reg_stat(kUnset, 0, 0, 0);
		if (op_reg_src(inst.opcode)) {
			src_datastatus = stack_reg(inst.src);
		} else if (op_imm_src(inst.opcode)) {
			src_datastatus = reg_stat(kScalar, inst.imm, inst.imm, 0);
		}

		int nextpc = stack_pc() + 1;

		switch (EBPF_CLASS(inst.opcode)) {
			case EBPF_CLS_LD:
				// TODO: there's only LDDW
				break;

			case EBPF_CLS_LDX:
				// TODO: check source
				if (!check_mem_read(vm, &src_datastatus, inst.offset, EBPF_OPSIZE(inst.opcode))) {
					*errmsg = ubpf_error("Unsafe memory access at PC %d", stack_pc());
					return false;
				}

				stack_reg(inst.dst) = reg_stat(kScalar, 0, ~0, 0);
				break;

			case EBPF_CLS_ST:
			case EBPF_CLS_STX:
				break;

			case EBPF_CLS_ALU:
			case EBPF_CLS_ALU64:
				if (src_datastatus.type == kUnset) {
					*errmsg = ubpf_error("Operating on unset register at PC %d", stack_pc());
					return false;
				}
				// FIXME: assuming dst <= src (wrong)
				stack_reg(inst.dst) = src_datastatus;
				break;

			case EBPF_CLS_JMP: {
				int new_pc = stack_pc() + 1 + inst.offset;
				bool can_jump = true;
				bool can_not_jump = inst.opcode != EBPF_OP_JA;

				switch (inst.opcode) {
					case EBPF_OP_JA:
						can_jump = true;
						can_not_jump = false;
						break;

					case EBPF_OP_CALL:
						can_jump = false;
						can_not_jump = true;
						if (!verify_helper_requirements(vm, inst.imm, &stack_top(), errmsg)) {
							return false;
						}
						set_helper_results(vm, inst.imm, &stack_top());
						break;

					case EBPF_OP_EXIT:
						can_jump = false;
						can_not_jump = false;
						break;

					default: {
						struct reg_status dst_datastatus = stack_reg(inst.dst);
						if (src_datastatus.type == kUnset || dst_datastatus.type == kUnset) {
							*errmsg = ubpf_error("testing unset data at PC %d", stack_pc());
							return false;
						}
						switch (EBPF_SUB_OP(inst.opcode)) {
							case EBPF_SUB_OP(EBPF_OP_JEQ_REG):
								if (src_datastatus.type == kScalar && dst_datastatus.type == kScalar) {
									can_jump = range_intersect(src_datastatus.range, dst_datastatus.range);
									can_not_jump = !range_eq(src_datastatus.range, dst_datastatus.range);
								}
								break;

							case EBPF_SUB_OP(EBPF_OP_JNE_REG):
								if (src_datastatus.type == kScalar && dst_datastatus.type == kScalar) {
									can_jump = !range_eq(src_datastatus.range, dst_datastatus.range);
									can_not_jump = range_intersect(src_datastatus.range, dst_datastatus.range);
								}
								break;

							case EBPF_SUB_OP(EBPF_OP_JGT_REG):
								if (src_datastatus.type == kScalar && dst_datastatus.type == kScalar) {
									can_jump = dst_datastatus.range.hi > src_datastatus.range.lo;
									can_not_jump = dst_datastatus.range.lo <= src_datastatus.range.hi;
								}
								break;

							case EBPF_SUB_OP(EBPF_OP_JGE_REG):
								if (src_datastatus.type == kScalar && dst_datastatus.type == kScalar) {
									can_jump = dst_datastatus.range.hi >= src_datastatus.range.lo;
									can_not_jump = dst_datastatus.range.lo < src_datastatus.range.hi;
								}
								break;

							case EBPF_SUB_OP(EBPF_OP_JLT_REG):
								if (src_datastatus.type == kScalar && dst_datastatus.type == kScalar) {
									can_jump = dst_datastatus.range.lo < src_datastatus.range.hi;
									can_not_jump = dst_datastatus.range.hi >= src_datastatus.range.lo;
								}
								break;

							case EBPF_SUB_OP(EBPF_OP_JLE_REG):
								if (src_datastatus.type == kScalar && dst_datastatus.type == kScalar) {
									can_jump = dst_datastatus.range.lo <= src_datastatus.range.hi;
									can_not_jump = dst_datastatus.range.hi > src_datastatus.range.lo;
								}
								break;

							case EBPF_SUB_OP(EBPF_OP_JSGT_REG):		// TODO
							case EBPF_SUB_OP(EBPF_OP_JSGE_REG):		// TODO
							case EBPF_SUB_OP(EBPF_OP_JSLT_REG):		// TODO
							case EBPF_SUB_OP(EBPF_OP_JSLE_REG):		// TODO

							case EBPF_SUB_OP(EBPF_OP_JSET_REG):		// TODO
								break;
						}
						break;
					}
				}
				if (can_not_jump) {
					// TODO: register non-jump constraints
					if (can_jump) {
						// TODO add branch on new_pc
					}
				} else {
					if (can_jump) {
						nextpc = new_pc;
						// TODO: register jump constraints
					} else {
						// path end
						stackP--;
					}
				}
				break;
			}
		}
		stack_pc() = nextpc;
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

	if (vm->check_flags.basic) {
		if (! linear_checks(vm, insts, num_insts, errmsg)) {
			return false;
		}
	}

	if (vm->check_flags.all_paths) {
		if (! codepaths_scan(vm, insts, num_insts, errmsg)) {
			return false;
		}
	}

	return true;
}
