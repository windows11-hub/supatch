// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * kpm_host_core.c - resident KPM loader agent (LKM) for pure Magisk / temp-root.
 * ALL kernel APIs resolved via kallsyms at runtime. ZERO compile-time dependencies.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <asm/cacheflush.h>
#include <linux/elf.h>
#include <linux/version.h>

#include "kpm_host.h"
#include "kpm_insn.h"

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("suzhi");
MODULE_DESCRIPTION("resident KPM loader agent for temp-root environments (dynamic-symbol edition)");

static char *kpm_syms = NULL;
module_param(kpm_syms, charp, 0644);

#define __kpm_nocfi __attribute__((no_sanitize("cfi")))

/* Fallback defines (kept here so the file still builds even if kpm_host.h
 * in the repo is not updated in lockstep). */
#ifndef KPM_LIVE_MAX
#define KPM_LIVE_MAX 64
#endif
#ifndef KPM_LIVE_NAME_MAX
#define KPM_LIVE_NAME_MAX 128
#endif


/* ============================================================
 * ALL kernel APIs resolved through kallsyms — ZERO direct calls
 * ============================================================ */

/* ALL kernel resolving now goes through the userspace-supplied live table
 * (kpm_syms module param).  ZERO direct kernel calls: even
 * kallsyms_lookup_name and flush_icache_range are resolved as pointers,
 * because on GKI (5.7+) these are NOT exported and a plain finit_module
 * cannot satisfy them — only a resolver kernel (KernelSU/APatch) could,
 * and this build targets bare magisk temp-root. */
static void (*host_flush_icache_range)(unsigned long, unsigned long) = NULL;
static void *(*host_vmalloc)(unsigned long) = NULL;
static void (*host_vfree)(const void *) = NULL;
static int (*host_set_memory_x)(unsigned long, int) = NULL;
static int (*host_set_memory_rw)(unsigned long, int) = NULL;
static int (*host_set_memory_ro)(unsigned long, int) = NULL;
static void (*host_kick_all_cpus_sync)(void) = NULL;
static int (*host_misc_register)(void *) = NULL;
static int (*host_misc_deregister)(void *) = NULL;
static unsigned long (*host_copy_to_user)(void *, const void *, unsigned long) = NULL;
static unsigned long (*host_copy_from_user)(void *, const void *, unsigned long) = NULL;
static int (*host_capable)(int) = NULL;
static char *(*host_strcpy)(char *, const char *) = NULL;
static int (*host_strcmp)(const char *, const char *) = NULL;
static int (*host_strncmp)(const char *, const char *, size_t) = NULL;
static char *(*host_strchr)(const char *, int) = NULL;
static size_t (*host_strlen)(const char *) = NULL;
static size_t (*host_strnlen)(const char *, size_t) = NULL;
static long (*host_strscpy)(char *, const char *, size_t) = NULL;
static char *(*host_strsep)(char **, const char *) = NULL;
static char *(*host_strncat)(char *, const char *, size_t) = NULL;
static int (*host_kstrtoull)(const char *, unsigned int, unsigned long long *) = NULL;
static int (*host_snprintf)(char *, size_t, const char *, ...) = NULL;
static int (*host_sscanf_fn)(const char *, const char *, ...) = NULL;
static void *(*host_memcpy)(void *, const void *, size_t) = NULL;
static void *(*host_memset)(void *, int, size_t) = NULL;
static int (*host_memcmp)(const void *, const void *, size_t) = NULL;
static char *(*host_kstrdup)(const char *, int) = NULL;
static void (*host_kfree)(const void *) = NULL;
static void *(*host_module_put)(void *) = NULL;
static int (*host_try_module_get)(void *) = NULL;
static int (*host_printk_fn)(const char *, ...) = NULL;

#define kpm_lock()   do { if (!host_capable) return -ENOSYS; } while (0)
#define kpm_unlock() do { } while (0)

/* layout globals expected by the KPM's current.h / ksyms.h */
int thread_size = 16384;
int thread_info_in_task = 1;
int sp_el0_is_current = 1;
int sp_el0_is_thread_info = 0;
int task_in_thread_info_offset = 0;
int stack_in_task_offset = 0;
int stack_end_offset = 0;
unsigned int kver = LINUX_VERSION_CODE;
unsigned int kpver = 0x00000001;

static struct {
	const char *name;
	void *addr;
} host_exports[] = {
	{ "kver", &kver },
	{ "kpver", &kpver },
	{ "thread_size", &thread_size },
	{ "thread_info_in_task", &thread_info_in_task },
	{ "sp_el0_is_current", &sp_el0_is_current },
	{ "sp_el0_is_thread_info", &sp_el0_is_thread_info },
	{ "task_in_thread_info_offset", &task_in_thread_info_offset },
	{ "stack_in_task_offset", &stack_in_task_offset },
	{ "stack_end_offset", &stack_end_offset },
};

/* CFI slowpath variables */
static unsigned long kpm_slowpath_diag;
static unsigned long kpm_slowpath_plain;
static u32 kpm_slowpath_diag_orig;
static u32 kpm_slowpath_plain_orig;
static bool kpm_slowpath_patched;

/* ---- live symbol table (bootstrap from userspace via kpm_syms param) ----
 * Fully self-contained: parsed and matched with hand-rolled helpers, so we
 * don't depend on ANY kernel/compiler string function or host_* pointer
 * (which would create a chicken-and-egg loop with resolve_all). The name is
 * stored inline (no kstrdup), so no kfree on teardown either. */

struct kpm_live_entry {
	char name[KPM_LIVE_NAME_MAX];
	unsigned long addr;
};

static struct kpm_live_entry kpm_live[KPM_LIVE_MAX];
static unsigned int kpm_live_n;

static int kpm_str_eq(const char *a, const char *b)
{
	while (*a && *b) { if (*a != *b) return 0; a++; b++; }
	return *a == *b;
}

/* parse one hex uint from 's' at the first token; returns 0 on bad char */
static unsigned long kpm_hex_parse(const char *s)
{
	unsigned long v = 0;
	if (s[0]=='0' && (s[1]=='x' || s[1]=='X')) s += 2;
	while (*s) {
		char c = *s;
		unsigned int d;
		if (c >= '0' && c <= '9') d = c - '0';
		else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
		else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
		else return 0;
		v = (v << 4) | d;
		s++;
	}
	return v;
}

static __kpm_nocfi unsigned long kpm_live_find(const char *name)
{
	for (unsigned int i = 0; i < kpm_live_n; i++)
		if (kpm_live[i].name[0] && kpm_str_eq(kpm_live[i].name, name))
			return kpm_live[i].addr;
	return 0;
}

/* format: name:0xHEX,name2:0xHEX2,... (addresses are the userspace-supplied
 * /proc/kallsyms values). Names are copied inline. */
static __kpm_nocfi void kpm_live_parse(char *str)
{
	kpm_live_n = 0;
	if (!str) return;

	char *p = str;
	unsigned int n = 0;

	while (p && *p && n < KPM_LIVE_MAX) {
		char *colon = p;
		while (*colon && (*colon != ':') && (*colon != ',')) colon++;
		if (*colon == ',') { p = colon + 1; continue; }
		if (*colon != ':') break;
		unsigned long namelen = colon - p;
		if (namelen == 0 || namelen >= KPM_LIVE_NAME_MAX) break;

		char *addr = colon + 1;
		char *comma = addr;
		while (*comma && *comma != ',') comma++;
		char saved = *comma;
		*comma = '\0';
		unsigned long av = kpm_hex_parse(addr);
		*comma = saved;
		if (!av) {
			if (!saved) break;
			p = comma + 1;
			continue;
		}

		for (unsigned int j = 0; j < namelen; j++)
			kpm_live[n].name[j] = p[j];
		kpm_live[n].name[namelen] = '\0';
		kpm_live[n].addr = av;
		n++;
		if (!saved) break;
		p = comma + 1;
	}
	kpm_live_n = n;
}

static void kpm_live_free(void)
{
	/* names stored inline — nothing to free */
	kpm_live_n = 0;
}


/* ---- kallsyms lookup ---- */

static __kpm_nocfi unsigned long klookup(const char *name)
{
	unsigned long addr = kpm_live_find(name);
	if (addr) return addr;
	/* live-table only; no kallsyms fallback (GKI does not export it) */
	return 0;
}

/* ---- resolve ALL needed symbols ---- */

static __kpm_nocfi void resolve_all(void)
{
#define RESOLVE(name) \
	do { unsigned long a = klookup(#name); if (a) host_##name = (void *)a; } while (0)

	RESOLVE(vmalloc);
	RESOLVE(vfree);
	RESOLVE(set_memory_x);
	RESOLVE(set_memory_rw);
	RESOLVE(set_memory_ro);
	RESOLVE(kick_all_cpus_sync);
	RESOLVE(flush_icache_range);
	RESOLVE(misc_register);
	RESOLVE(misc_deregister);
	RESOLVE(copy_to_user);
	RESOLVE(copy_from_user);
	RESOLVE(capable);
	RESOLVE(strcpy);
	RESOLVE(strcmp);
	RESOLVE(strncmp);
	RESOLVE(strchr);
	RESOLVE(strlen);
	RESOLVE(strnlen);
	RESOLVE(strscpy);
	RESOLVE(strsep);
	RESOLVE(strncat);
	RESOLVE(kstrtoull);
	RESOLVE(snprintf);
	RESOLVE(memcpy);
	RESOLVE(memset);
	RESOLVE(memcmp);
	RESOLVE(kstrdup);
	RESOLVE(kfree);
	RESOLVE(module_put);
	RESOLVE(try_module_get);

	host_sscanf_fn = (typeof(host_sscanf_fn))klookup("sscanf");
	host_printk_fn = (typeof(host_printk_fn))klookup("printk");

#undef RESOLVE
}

#define kpm_pr_alert(fmt, ...) do { if (host_snprintf) { char _b[256]; int _n = host_snprintf(_b, 256, fmt, ##__VA_ARGS__); if (_n > 0 && host_printk_fn) host_printk_fn("%s", _b); } } while (0)

/* ---- CFI slowpath patch/reset ---- */

static __kpm_nocfi bool kpm_cfi_patch_ret(unsigned long *addr, u32 *orig)
{
	if (!addr || !*addr || !host_set_memory_rw) return false;
	u32 word = *(u32 *)*addr;
	int rc = host_set_memory_rw(*addr & PAGE_MASK, 1);
	if (rc) { kpm_pr_alert("kpm: cfi rw fail %px rc=%d\n", (void *)*addr, rc); return false; }
	*orig = word;
	WRITE_ONCE(*(u32 *)*addr, 0xd65f03c0);
	host_flush_icache_range(*addr, *addr + 4);
	if (host_kick_all_cpus_sync) host_kick_all_cpus_sync();
	if (host_set_memory_ro) host_set_memory_ro(*addr & PAGE_MASK, 1);
	kpm_pr_alert("kpm: cfi neutered %px\n", (void *)*addr);
	return true;
}

static __kpm_nocfi void kpm_cfi_restore_one(unsigned long addr, u32 orig)
{
	if (!addr || !orig || !host_set_memory_rw) return;
	int rc = host_set_memory_rw(addr & PAGE_MASK, 1);
	if (rc) return;
	WRITE_ONCE(*(u32 *)addr, orig);
	host_flush_icache_range(addr, addr + 4);
	if (host_kick_all_cpus_sync) host_kick_all_cpus_sync();
	if (host_set_memory_ro) host_set_memory_ro(addr & PAGE_MASK, 1);
}

static __kpm_nocfi void kpm_cfi_neuter_slowpath(void)
{
	unsigned long a = klookup("__cfi_slowpath_diag");
	if (a) { u32 o = 0; if (kpm_cfi_patch_ret(&a, &o)) { kpm_slowpath_diag = a; kpm_slowpath_diag_orig = o; kpm_slowpath_patched = true; } }
	a = klookup("__cfi_slowpath");
	if (a && a != kpm_slowpath_diag) { u32 o = 0; if (kpm_cfi_patch_ret(&a, &o)) { kpm_slowpath_plain = a; kpm_slowpath_plain_orig = o; kpm_slowpath_patched = true; } }
}

static __kpm_nocfi void kpm_cfi_restore_slowpath(void)
{
	if (!kpm_slowpath_patched) return;
	kpm_cfi_restore_one(kpm_slowpath_diag, kpm_slowpath_diag_orig);
	kpm_cfi_restore_one(kpm_slowpath_plain, kpm_slowpath_plain_orig);
	kpm_slowpath_diag = kpm_slowpath_plain = 0;
	kpm_slowpath_diag_orig = kpm_slowpath_plain_orig = 0;
	kpm_slowpath_patched = false;
}

/* ---- symbol resolution ---- */

u64 kpm_get_symbol(const char *name)
{
	if (!name || name[0] == '\0') return 0;
	for (int i = 0; i < ARRAY_SIZE(host_exports); i++)
		if (host_strcmp && host_strcmp(name, host_exports[i].name) == 0)
			return (u64)(unsigned long)host_exports[i].addr;
	unsigned long addr = klookup(name);
	return addr ? (u64)addr : 0;
}

/* ---- ELF loader (same logic, uses host_* wrappers) ---- */

static long kpm_get_offset(unsigned long *size, Elf64_Shdr *sechdr)
{
	long ret = ALIGN(*size, sechdr->sh_addralign ?: 1);
	*size = ret + sechdr->sh_size;
	return ret;
}

static void kpm_layout_sections(struct kpm_image *img, struct kpm_load_info *info)
{
	static const unsigned long masks[][2] = {
		{ SHF_EXECINSTR | SHF_ALLOC, 0 },
		{ SHF_ALLOC, SHF_WRITE },
		{ SHF_WRITE | SHF_ALLOC, 0 },
		{ SHF_ALLOC, 0 },
	};

	for (int i = 0; i < info->hdr->e_shnum; i++)
		info->sechdrs[i].sh_entsize = ~0UL;

	for (int m = 0; m < 4; ++m) {
		for (int i = 0; i < info->hdr->e_shnum; ++i) {
			Elf64_Shdr *s = &info->sechdrs[i];
			if ((s->sh_flags & masks[m][0]) != masks[m][0] ||
			    (s->sh_flags & masks[m][1]) || s->sh_entsize != ~0UL)
				continue;
			s->sh_entsize = kpm_get_offset(&img->size, s);
		}
		switch (m) {
		case 0: img->size = ALIGN(img->size, PAGE_SIZE); img->text_size = img->size; break;
		case 1: img->size = ALIGN(img->size, PAGE_SIZE); img->ro_size = img->size; break;
		case 2: break;
		case 3: img->size = ALIGN(img->size, PAGE_SIZE); break;
		}
	}
}

static bool kpm_is_core_symbol(const Elf64_Sym *src, const Elf64_Shdr *sechdrs, unsigned int shnum)
{
	if (src->st_shndx == SHN_UNDEF || src->st_shndx >= shnum || !src->st_name)
		return false;
	const Elf64_Shdr *sec = sechdrs + src->st_shndx;
	return (sec->sh_flags & SHF_ALLOC) && (sec->sh_flags & SHF_EXECINSTR);
}

static int kpm_simplify_symbols(struct kpm_image *img, const struct kpm_load_info *info)
{
	Elf64_Shdr *symsec = &info->sechdrs[info->symtab];
	Elf64_Sym *sym = (Elf64_Sym *)symsec->sh_addr;
	int ret = 0;

	for (unsigned int i = 1; i < symsec->sh_size / sizeof(Elf64_Sym); i++) {
		const char *name = info->strtab_data + sym[i].st_name;
		switch (sym[i].st_shndx) {
		case SHN_COMMON:
		case SHN_ABS:
			break;
		case SHN_UNDEF: {
			unsigned long addr = kpm_get_symbol(name);
			if (!addr) { kpm_pr_alert("kpm: unknown sym: %s\n", name); ret = -ENOENT; break; }
			sym[i].st_value = addr;
			break;
		}
		default:
			sym[i].st_value += info->sechdrs[sym[i].st_shndx].sh_addr;
			break;
		}
	}
	return ret;
}

static int kpm_apply_relocations(struct kpm_image *img, const struct kpm_load_info *info)
{
	for (unsigned int i = 1; i < info->hdr->e_shnum; i++) {
		unsigned int infosec = info->sechdrs[i].sh_info;
		if (infosec >= info->hdr->e_shnum) continue;
		if (!(info->sechdrs[infosec].sh_flags & SHF_ALLOC)) continue;
		if (info->sechdrs[i].sh_type == SHT_RELA) {
			int rc = kpm_apply_relocate_add(info->sechdrs, info->strtab_data, info->symtab, i, img);
			if (rc < 0) return rc;
		}
	}
	return 0;
}

static void kpm_layout_symtab(struct kpm_image *img, struct kpm_load_info *info)
{
	Elf64_Shdr *symsect = info->sechdrs + info->symtab;
	Elf64_Shdr *strsect = info->sechdrs + info->sechdrs[info->symtab].sh_link;

	symsect->sh_flags |= SHF_ALLOC;
	symsect->sh_entsize = kpm_get_offset(&img->size, symsect);

	const Elf64_Sym *src = (const Elf64_Sym *)((const char *)info->hdr + symsect->sh_offset);
	unsigned int nsrc = symsect->sh_size / sizeof(*src);
	unsigned int strtab_size = 1, ndst = 0;

	for (unsigned int i = 0; i < nsrc; i++) {
		if (i == 0 || kpm_is_core_symbol(src + i, info->sechdrs, info->hdr->e_shnum)) {
			strtab_size += host_strlen ? (host_strlen(&info->strtab_data[src[i].st_name]) + 1) : 1;
			ndst++;
		}
	}

	img->size = ALIGN(img->size, symsect->sh_addralign ?: 1);
	img->size += ndst * sizeof(Elf64_Sym);
	img->size += strtab_size;

	strsect->sh_flags |= SHF_ALLOC;
	strsect->sh_entsize = kpm_get_offset(&img->size, strsect);
}

static int kpm_rewrite_section_headers(struct kpm_load_info *info)
{
	info->sechdrs[0].sh_addr = 0;
	for (int i = 1; i < info->hdr->e_shnum; i++) {
		Elf64_Shdr *shdr = &info->sechdrs[i];
		if (shdr->sh_type != SHT_NOBITS && info->len < shdr->sh_offset + shdr->sh_size)
			return -ENOEXEC;
		shdr->sh_addr = (unsigned long)((const char *)info->hdr + shdr->sh_offset);
	}
	return 0;
}

static char *kpm_next_string(char *string, unsigned long *secsize)
{
	while (string[0]) { string++; if ((*secsize)-- <= 1) return NULL; }
	while (!string[0]) { string++; if ((*secsize)-- <= 1) return NULL; }
	return string;
}

static char *kpm_get_next_modinfo(const struct kpm_load_info *info, const char *tag, char *prev)
{
	unsigned int taglen = host_strlen ? host_strlen(tag) : 0;
	Elf64_Shdr *infosec = &info->sechdrs[info->modinfo_secobj];
	unsigned long size = infosec->sh_size;
	char *modinfo = (char *)info->hdr + infosec->sh_offset;

	if (prev) { size -= prev - modinfo; modinfo = kpm_next_string(prev, &size); }
	for (char *p = modinfo; p; p = kpm_next_string(p, &size)) {
		if (host_strncmp && host_strncmp(p, tag, taglen) == 0 && p[taglen] == '=')
			return p + taglen + 1;
	}
	return NULL;
}

static int kpm_find_sec(const struct kpm_load_info *info, const char *name)
{
	for (int i = 1; i < info->hdr->e_shnum; i++) {
		Elf64_Shdr *shdr = &info->sechdrs[i];
		if ((shdr->sh_flags & SHF_ALLOC) && host_strcmp && host_strcmp(info->secstrings + shdr->sh_name, name) == 0)
			return i;
	}
	return 0;
}

static int kpm_setup_load_info(struct kpm_load_info *info)
{
	info->sechdrs = (Elf64_Shdr *)((const char *)info->hdr + info->hdr->e_shoff);
	info->secstrings = (char *)((const char *)info->hdr + info->sechdrs[info->hdr->e_shstrndx].sh_offset);

	int rc = kpm_rewrite_section_headers(info);
	if (rc) return rc;

	if (!kpm_find_sec(info, KPM_SECT_INIT) || !kpm_find_sec(info, KPM_SECT_EXIT))
		return -ENOEXEC;

	info->modinfo_secobj = 0;
	for (int i = 1; i < info->hdr->e_shnum; i++) {
		if ((info->sechdrs[i].sh_flags & SHF_ALLOC) &&
		    host_strcmp && host_strcmp(info->secstrings + info->sechdrs[i].sh_name, KPM_SECT_INFO) == 0) {
			info->modinfo_secobj = i;
			break;
		}
	}
	if (!info->modinfo_secobj) return -ENOEXEC;

	info->modinfo_base = (const char *)info->hdr + info->sechdrs[info->modinfo_secobj].sh_offset;
	info->modinfo_size = info->sechdrs[info->modinfo_secobj].sh_size;

	char *name = kpm_get_next_modinfo(info, KPM_MODINFO_NAME, NULL);
	if (!name) return -ENOEXEC;
	info->modinfo_name = name;
	kpm_pr_alert("kpm: loading [%s]\n", name);

	char *version = kpm_get_next_modinfo(info, KPM_MODINFO_VERSION, NULL);
	if (version) info->modinfo_version = version;
	info->modinfo_license = kpm_get_next_modinfo(info, KPM_MODINFO_LICENSE, NULL);
	info->modinfo_author = kpm_get_next_modinfo(info, KPM_MODINFO_AUTHOR, NULL);
	info->modinfo_description = kpm_get_next_modinfo(info, KPM_MODINFO_DESCRIPTION, NULL);

	info->symtab = 0;
	for (Elf64_Shdr *sections = info->sechdrs; sections < info->sechdrs + info->hdr->e_shnum; sections++) {
		if (sections->sh_type == SHT_SYMTAB) {
			info->symtab = sections - info->sechdrs;
			info->strtab = sections->sh_link;
			info->strtab_data = (const char *)info->hdr + info->sechdrs[info->strtab].sh_offset;
			break;
		}
	}
	if (!info->symtab) return -ENOEXEC;
	return 0;
}

static __kpm_nocfi int kpm_move_module(struct kpm_image *img, struct kpm_load_info *info)
{
	if (!host_vmalloc) { kpm_pr_alert("kpm: vmalloc unresolved\n"); return -ENOENT; }
	img->base = host_vmalloc(img->size);
	if (!img->base) { kpm_pr_alert("kpm: vmalloc fail sz=%lu\n", img->size); return -ENOMEM; }
	if (host_set_memory_rw) host_set_memory_rw((unsigned long)img->base, DIV_ROUND_UP(img->size, PAGE_SIZE));
	if (host_memset) host_memset(img->base, 0, img->size);

	for (int i = 1; i < info->hdr->e_shnum; i++) {
		Elf64_Shdr *shdr = &info->sechdrs[i];
		if (!(shdr->sh_flags & SHF_ALLOC)) continue;
		void *dest = (char *)img->base + shdr->sh_entsize;
		const char *sname = info->secstrings + shdr->sh_name;

		if (shdr->sh_type != SHT_NOBITS && host_memcpy)
			host_memcpy(dest, (void *)shdr->sh_addr, shdr->sh_size);
		shdr->sh_addr = (unsigned long)dest;

		if (!img->init && host_strcmp && !host_strcmp(KPM_SECT_INIT, sname)) img->init = (const char *)dest;
		if (host_strcmp && !host_strcmp(KPM_SECT_CTL0, sname)) img->ctl0 = (const char *)dest;
		if (host_strcmp && !host_strcmp(KPM_SECT_CTL1, sname)) img->ctl1 = (const char *)dest;
		if (!img->exit && host_strcmp && !host_strcmp(KPM_SECT_EXIT, sname)) img->exit = (const char *)dest;
		if (!img->info && host_strcmp && !host_strcmp(KPM_SECT_INFO, sname)) img->info = (const char *)dest;
	}

	long delta = (const char *)img->info - info->modinfo_base;
	img->info_name = (char *)info->modinfo_name + delta;
	img->info_version = (char *)info->modinfo_version + delta;
	if (info->modinfo_license) img->info_license = (char *)info->modinfo_license + delta;
	if (info->modinfo_author) img->info_author = (char *)info->modinfo_author + delta;
	if (info->modinfo_description) img->info_description = (char *)info->modinfo_description + delta;
	return 0;
}

static int kpm_elf_header_check(struct kpm_load_info *info)
{
	if (info->len <= sizeof(*info->hdr)) return -ENOEXEC;
	if (info->hdr->e_ident[0] != 0x7f || info->hdr->e_ident[1] != 'E' ||
	    info->hdr->e_ident[2] != 'L' || info->hdr->e_ident[3] != 'F')
		return -ENOEXEC;
	if (info->hdr->e_type != ET_REL || info->hdr->e_machine != EM_AARCH64 ||
	    info->hdr->e_shentsize != sizeof(Elf64_Shdr))
		return -ENOEXEC;
	if (info->hdr->e_shoff >= info->len ||
	    (info->hdr->e_shnum * sizeof(Elf64_Shdr) > info->len - info->hdr->e_shoff))
		return -ENOEXEC;
	return 0;
}

struct kpm_image kpm_image = { 0 };

__kpm_nocfi long kpm_load_module(const void *data, unsigned long len, const char *args, const char *event, void *reserved)
{
	struct kpm_load_info info = { .hdr = data, .len = len };
	struct kpm_image *img = &kpm_image;
	long rc;

	if ((rc = kpm_elf_header_check(&info))) goto out;
	kpm_pr_alert("kpm: l1 ok len=%lu\n", len);
	if ((rc = kpm_setup_load_info(&info))) goto out;
	kpm_pr_alert("kpm: l2 ok name=%s\n", info.modinfo_name ?: "?");

	host_memset(img, 0, sizeof(*img));
	kpm_layout_sections(img, &info);
	kpm_layout_symtab(img, &info);
	kpm_pr_alert("kpm: l3 layout size=%lu\n", img->size);

	if ((rc = kpm_move_module(img, &info))) goto out;
	kpm_pr_alert("kpm: l4 move base=%px\n", img->base);

	if ((rc = kpm_simplify_symbols(img, &info))) goto out;
	kpm_pr_alert("kpm: l5 simplify ok\n");

	if ((rc = kpm_apply_relocations(img, &info))) goto out;
	kpm_pr_alert("kpm: l6 reloc ok\n");

	host_flush_icache_range((unsigned long)img->base, (unsigned long)img->base + img->size);
	if (host_set_memory_x) host_set_memory_x((unsigned long)img->base, DIV_ROUND_UP(img->size, PAGE_SIZE));

	if (!img->init) goto out;
	kpm_pr_alert("kpm: l8 init at %px\n", img->init);

	kpm_cfi_neuter_slowpath();

	kpm_initcall_t init_fn = *(kpm_initcall_t *)img->init;
	rc = init_fn(args, event, reserved);
	kpm_pr_alert("kpm: l9 init rc=%ld\n", rc);

	if (!rc) { img->loaded = true; kpm_pr_alert("kpm: [%s] ok\n", img->info_name ?: "?"); }
	else {
		kpm_pr_alert("kpm: [%s] fail rc=%ld\n", img->info_name ?: "?", rc);
		if (img->exit) { kpm_exitcall_t exit_fn = *(kpm_exitcall_t *)img->exit; exit_fn(reserved); }
	}

	if (rc) {
		if (host_set_memory_rw) host_set_memory_rw((unsigned long)img->base, DIV_ROUND_UP(img->size, PAGE_SIZE));
		if (host_vfree) host_vfree(img->base);
	}

out:
	if (!img->loaded) kpm_cfi_restore_slowpath();
	return rc;
}

/* ---- module lifecycle ---- */

static __kpm_nocfi int kpm_host_do_init(void)
{
	kpm_pr_alert("kpm: host init\n");

	kpm_live_parse(kpm_syms);

	resolve_all();

	if (!host_vmalloc) { kpm_pr_alert("kpm: vmalloc unresolved\n"); return -ENOSYS; }

	return kpm_ctl_init();
}

static int __init kpm_host_init(void) { return kpm_host_do_init(); }

void __kpm_nocfi kpm_unload_current(void)
{
	if (!kpm_image.loaded && !kpm_image.base) return;
	if (kpm_image.loaded && kpm_image.exit) {
		kpm_exitcall_t exit_fn = *(kpm_exitcall_t *)kpm_image.exit;
		exit_fn(NULL);
		kpm_image.loaded = false;
	}
	kpm_cfi_restore_slowpath();
	if (kpm_image.base) {
		if (host_set_memory_rw) host_set_memory_rw((unsigned long)kpm_image.base, DIV_ROUND_UP(kpm_image.size, PAGE_SIZE));
		if (host_vfree) host_vfree(kpm_image.base);
	}
	host_memset(&kpm_image, 0, sizeof(kpm_image));
}

int kpm_is_loaded(void) { return kpm_image.loaded ? 1 : 0; }

static void __kpm_nocfi kpm_host_do_exit(void)
{
	kpm_unload_current();
	kpm_ctl_exit();
	kpm_live_free();
}

static void __exit kpm_host_exit(void) { kpm_host_do_exit(); }

module_init(kpm_host_init);
module_exit(kpm_host_exit);
