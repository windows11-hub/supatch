// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * kpm_host_re.c - aarch64 RELA relocation for KPM host loader.
 * Pure port of the KernelPatch relo.c logic, self-contained.
 */

#include <linux/elf.h>
#include <linux/errno.h>
#include <linux/printk.h>
#include <linux/uaccess.h>
#include <linux/types.h>

#include "kpm_host.h"
#include "kpm_insn.h"

static u64 kpm_do_reloc(enum kpm_aarch64_reloc_op reloc_op, void *place, u64 val)
{
	switch (reloc_op) {
	case KPM_RELOC_OP_ABS:
		return val;
	case KPM_RELOC_OP_PREL:
		return val - (u64)place;
	case KPM_RELOC_OP_PAGE:
		return (val & ~0xfff) - ((u64)place & ~0xfff);
	case KPM_RELOC_OP_NONE:
		return 0;
	}

	pr_err("kpm: do_reloc: unknown relocation operation %d\n", reloc_op);
	return 0;
}

static int kpm_reloc_data(enum kpm_aarch64_reloc_op op, void *place, u64 val, int len)
{
	u64 imm_mask = (1 << len) - 1;
	s64 sval = kpm_do_reloc(op, place, val);

	switch (len) {
	case 16:
		*(s16 *)place = sval;
		break;
	case 32:
		*(s32 *)place = sval;
		break;
	case 64:
		*(s64 *)place = sval;
		break;
	default:
		pr_err("kpm: invalid length (%d) for data relocation\n", len);
		return 0;
	}

	sval = (s64)(sval & ~(imm_mask >> 1)) >> (len - 1);

	if ((u64)(sval + 1) > 2)
		return -ERANGE;

	return 0;
}

static int kpm_reloc_insn_movw(enum kpm_aarch64_reloc_op op, void *place, u64 val, int lsb,
			       enum kpm_insn_imm_type imm_type)
{
	u64 imm, limit = 0;
	s64 sval;
	u32 insn = *(u32 *)place;

	sval = kpm_do_reloc(op, place, val);
	sval >>= lsb;
	imm = sval & 0xffff;

	if (imm_type == KPM_AARCH64_IMM_MOVNZ) {
		insn &= ~(3 << 29);
		if ((s64)imm >= 0) {
			insn |= 2 << 29;
		} else {
			imm = ~imm;
		}
		imm_type = KPM_AARCH64_IMM_MOVK;
	}

	insn = kpm_aarch64_insn_encode_immediate(imm_type, insn, imm);
	*(u32 *)place = insn;

	sval >>= 16;

	if (imm_type != KPM_INSN_IMM_16) {
		sval++;
		limit++;
	}

	if ((u64)sval > limit)
		return -ERANGE;

	return 0;
}

static int kpm_reloc_insn_imm(enum kpm_aarch64_reloc_op op, void *place, u64 val, int lsb, int len,
			      enum kpm_insn_imm_type imm_type)
{
	u64 imm, imm_mask;
	s64 sval;
	u32 insn = *(u32 *)place;

	sval = kpm_do_reloc(op, place, val);
	sval >>= lsb;
	imm_mask = (KPM_BIT(lsb + len) - 1) >> lsb;
	imm = sval & imm_mask;
	insn = kpm_aarch64_insn_encode_immediate(imm_type, insn, imm);
	*(u32 *)place = insn;

	sval = (s64)(sval & ~(imm_mask >> 1)) >> (len - 1);

	if ((u64)(sval + 1) >= 2)
		return -ERANGE;

	return 0;
}

int kpm_apply_relocate_add(Elf64_Shdr *sechdrs, const char *strtab, unsigned int symindex, unsigned int relsec,
			   struct kpm_image *img)
{
	unsigned int i;
	int ovf;
	bool overflow_check;
	Elf64_Sym *sym;
	void *loc;
	u64 val;
	Elf64_Rela *rel = (void *)sechdrs[relsec].sh_addr;

		 relsec, symindex, sechdrs[relsec].sh_info, sechdrs[relsec].sh_size,
		 sechdrs[relsec].sh_size / sizeof(*rel));
	for (i = 0; i < sechdrs[relsec].sh_size / sizeof(*rel); i++) {
		if (i < 8 || i % 128 == 0)
				 rel[i].r_offset, ELF64_R_TYPE(rel[i].r_info),
				 ELF64_R_SYM(rel[i].r_info));
		else if (i % 64 == 63)
				 sechdrs[relsec].sh_size / sizeof(*rel));
		loc = (void *)sechdrs[sechdrs[relsec].sh_info].sh_addr + rel[i].r_offset;
		if ((unsigned long)loc < (unsigned long)img->base ||
		    (unsigned long)loc + 8 > (unsigned long)img->base + img->size) {
			pr_err("kpm: reloc loc OOB: %px (base %px size %lu rel %u/%zu)\n",
			       loc, img->base, img->size, i,
			       sechdrs[relsec].sh_size / sizeof(*rel));
			return -ENOEXEC;
		}
		sym = (Elf64_Sym *)sechdrs[symindex].sh_addr + ELF64_R_SYM(rel[i].r_info);
		if ((unsigned long)sym < (unsigned long)img->base ||
		    (unsigned long)sym + sizeof(*sym) > (unsigned long)img->base + img->size) {
			pr_err("kpm: reloc sym OOB: %px\n", sym);
			return -ENOEXEC;
		}
		val = sym->st_value + rel[i].r_addend;

		overflow_check = true;

		switch (ELF64_R_TYPE(rel[i].r_info)) {
		case R_ARM_NONE:
		case R_AARCH64_NONE:
			ovf = 0;
			break;
		/* Data relocations. */
		case R_AARCH64_ABS64:
			overflow_check = false;
			ovf = kpm_reloc_data(KPM_RELOC_OP_ABS, loc, val, 64);
			break;
		case R_AARCH64_ABS32:
			ovf = kpm_reloc_data(KPM_RELOC_OP_ABS, loc, val, 32);
			break;
		case R_AARCH64_ABS16:
			ovf = kpm_reloc_data(KPM_RELOC_OP_ABS, loc, val, 16);
			break;
		case R_AARCH64_PREL64:
			overflow_check = false;
			ovf = kpm_reloc_data(KPM_RELOC_OP_PREL, loc, val, 64);
			break;
		case R_AARCH64_PREL32:
			ovf = kpm_reloc_data(KPM_RELOC_OP_PREL, loc, val, 32);
			break;
		case R_AARCH64_PREL16:
			ovf = kpm_reloc_data(KPM_RELOC_OP_PREL, loc, val, 16);
			break;

		/* MOVW instruction relocations. */
		case R_AARCH64_MOVW_UABS_G0_NC:
			overflow_check = false;
			fallthrough;
		case R_AARCH64_MOVW_UABS_G0:
			ovf = kpm_reloc_insn_movw(KPM_RELOC_OP_ABS, loc, val, 0, KPM_INSN_IMM_16);
			break;
		case R_AARCH64_MOVW_UABS_G1_NC:
			overflow_check = false;
			fallthrough;
		case R_AARCH64_MOVW_UABS_G1:
			ovf = kpm_reloc_insn_movw(KPM_RELOC_OP_ABS, loc, val, 16, KPM_INSN_IMM_16);
			break;
		case R_AARCH64_MOVW_UABS_G2_NC:
			overflow_check = false;
			fallthrough;
		case R_AARCH64_MOVW_UABS_G2:
			ovf = kpm_reloc_insn_movw(KPM_RELOC_OP_ABS, loc, val, 32, KPM_INSN_IMM_16);
			break;
		case R_AARCH64_MOVW_UABS_G3:
			overflow_check = false;
			ovf = kpm_reloc_insn_movw(KPM_RELOC_OP_ABS, loc, val, 48, KPM_INSN_IMM_16);
			break;
		case R_AARCH64_MOVW_SABS_G0:
			ovf = kpm_reloc_insn_movw(KPM_RELOC_OP_ABS, loc, val, 0, KPM_AARCH64_IMM_MOVNZ);
			break;
		case R_AARCH64_MOVW_SABS_G1:
			ovf = kpm_reloc_insn_movw(KPM_RELOC_OP_ABS, loc, val, 16, KPM_AARCH64_IMM_MOVNZ);
			break;
		case R_AARCH64_MOVW_SABS_G2:
			ovf = kpm_reloc_insn_movw(KPM_RELOC_OP_ABS, loc, val, 32, KPM_AARCH64_IMM_MOVNZ);
			break;
		case R_AARCH64_MOVW_PREL_G0_NC:
			overflow_check = false;
			ovf = kpm_reloc_insn_movw(KPM_RELOC_OP_PREL, loc, val, 0, KPM_AARCH64_IMM_MOVK);
			break;
		case R_AARCH64_MOVW_PREL_G0:
			ovf = kpm_reloc_insn_movw(KPM_RELOC_OP_PREL, loc, val, 0, KPM_AARCH64_IMM_MOVNZ);
			break;
		case R_AARCH64_MOVW_PREL_G1_NC:
			overflow_check = false;
			ovf = kpm_reloc_insn_movw(KPM_RELOC_OP_PREL, loc, val, 16, KPM_AARCH64_IMM_MOVK);
			break;
		case R_AARCH64_MOVW_PREL_G1:
			ovf = kpm_reloc_insn_movw(KPM_RELOC_OP_PREL, loc, val, 16, KPM_AARCH64_IMM_MOVNZ);
			break;
		case R_AARCH64_MOVW_PREL_G2_NC:
			overflow_check = false;
			ovf = kpm_reloc_insn_movw(KPM_RELOC_OP_PREL, loc, val, 32, KPM_AARCH64_IMM_MOVK);
			break;
		case R_AARCH64_MOVW_PREL_G2:
			ovf = kpm_reloc_insn_movw(KPM_RELOC_OP_PREL, loc, val, 32, KPM_AARCH64_IMM_MOVNZ);
			break;
		case R_AARCH64_MOVW_PREL_G3:
			overflow_check = false;
			ovf = kpm_reloc_insn_movw(KPM_RELOC_OP_PREL, loc, val, 48, KPM_AARCH64_IMM_MOVNZ);
			break;

		/* Immediate instruction relocations. */
		case R_AARCH64_LD_PREL_LO19:
			ovf = kpm_reloc_insn_imm(KPM_RELOC_OP_PREL, loc, val, 2, 19, KPM_INSN_IMM_19);
			break;
		case R_AARCH64_ADR_PREL_LO21:
			ovf = kpm_reloc_insn_imm(KPM_RELOC_OP_PREL, loc, val, 0, 21, KPM_INSN_IMM_ADR);
			break;
		case R_AARCH64_ADR_PREL_PG_HI21_NC:
			overflow_check = false;
			fallthrough;
		case R_AARCH64_ADR_PREL_PG_HI21:
			ovf = kpm_reloc_insn_imm(KPM_RELOC_OP_PAGE, loc, val, 12, 21, KPM_INSN_IMM_ADR);
			break;
		case R_AARCH64_ADD_ABS_LO12_NC:
		case R_AARCH64_LDST8_ABS_LO12_NC:
			overflow_check = false;
			ovf = kpm_reloc_insn_imm(KPM_RELOC_OP_ABS, loc, val, 0, 12, KPM_INSN_IMM_12);
			break;
		case R_AARCH64_LDST16_ABS_LO12_NC:
			overflow_check = false;
			ovf = kpm_reloc_insn_imm(KPM_RELOC_OP_ABS, loc, val, 1, 11, KPM_INSN_IMM_12);
			break;
		case R_AARCH64_LDST32_ABS_LO12_NC:
			overflow_check = false;
			ovf = kpm_reloc_insn_imm(KPM_RELOC_OP_ABS, loc, val, 2, 10, KPM_INSN_IMM_12);
			break;
		case R_AARCH64_LDST64_ABS_LO12_NC:
			overflow_check = false;
			ovf = kpm_reloc_insn_imm(KPM_RELOC_OP_ABS, loc, val, 3, 9, KPM_INSN_IMM_12);
			break;
		case R_AARCH64_LDST128_ABS_LO12_NC:
			overflow_check = false;
			ovf = kpm_reloc_insn_imm(KPM_RELOC_OP_ABS, loc, val, 4, 8, KPM_INSN_IMM_12);
			break;
		case R_AARCH64_TSTBR14:
			ovf = kpm_reloc_insn_imm(KPM_RELOC_OP_PREL, loc, val, 2, 14, KPM_INSN_IMM_14);
			break;
		case R_AARCH64_CONDBR19:
			ovf = kpm_reloc_insn_imm(KPM_RELOC_OP_PREL, loc, val, 2, 19, KPM_INSN_IMM_19);
			break;
		case R_AARCH64_JUMP26:
		case R_AARCH64_CALL26:
			ovf = kpm_reloc_insn_imm(KPM_RELOC_OP_PREL, loc, val, 2, 26, KPM_INSN_IMM_26);
			break;
		default:
			pr_err("kpm: unsupported RELA relocation: %llu\n", ELF64_R_TYPE(rel[i].r_info));
			return -ENOEXEC;
		}

		if (overflow_check && ovf == -ERANGE)
			goto overflow;
	}
	return 0;
overflow:
	pr_err("kpm: overflow in relocation type %d val %llx\n", (int)ELF64_R_TYPE(rel[i].r_info), val);
	return -ENOEXEC;
}
