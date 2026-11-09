// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * kpm_host.c - resident KPM loader agent (LKM) for pure Magisk / temp-root.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <asm/cacheflush.h>
#include <linux/elf.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/moduleloader.h>

#include "kpm_host.h"
#include "kpm_insn.h"

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("suzhi");
MODULE_DESCRIPTION("resident KPM loader agent for temp-root environments");

static char *kpm_syms = NULL;
module_param(kpm_syms, charp, 0644);

#define __kpm_nocfi __attribute__((no_sanitize("cfi")))

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

void *(*kf_memcpy)(void *, const void *, size_t);
void *(*kf_memset)(void *, int, size_t);
char *(*kf_strsep)(char **, const char *);
int (*kf_kstrtoull)(const char *, unsigned int, unsigned long long *);
int (*kf_snprintf)(char *, size_t, const char *, ...);
size_t (*kf_strlen)(const char *);
int (*kf_memcmp)(const void *, const void *, size_t);
char *(*kf_strncat)(char *, const char *, size_t);

int (*host_printk)(const char *fmt, ...);

static unsigned long (*host_copy_to_user)(void __user *to, const void *from,
					  unsigned long n);
static __kpm_nocfi int host_compat_copy_to_user(void __user *to, const void *from, int n)
{
	if (!host_copy_to_user)
		return -ENOSYS;
	return host_copy_to_user(to, from, n) ? 0 : n;
}

extern unsigned long kallsyms_lookup_name(const char *);

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
	{ "printk", &host_printk },
	{ "kallsyms_lookup_name", &kallsyms_lookup_name_fn },
	{ "compat_copy_to_user", (void *)host_compat_copy_to_user },
	{ "kf_memcpy", &kf_memcpy },
	{ "kf_memset", &kf_memset },
	{ "kf_strsep", &kf_strsep },
	{ "kf_kstrtoull", &kf_kstrtoull },
	{ "kf_snprintf", &kf_snprintf },
	{ "kf_strlen", &kf_strlen },
	{ "kf_memcmp", &kf_memcmp },
	{ "kf_strncat", &kf_strncat },
};

static void *(*host_vmalloc)(unsigned long);
static void (*host_vfree)(const void *);
static int (*host_set_memory_x)(unsigned long, int);
static int (*host_set_memory_rw)(unsigned long, int);
static int (*host_set_memory_ro)(unsigned long, int);
static void (*host_kick_all_cpus_sync)(void);

/* CFI slowpath variables */
static unsigned long kpm_slowpath_diag;
static unsigned long kpm_slowpath_plain;
static u32 kpm_slowpath_diag_orig;
static u32 kpm_slowpath_plain_orig;
static bool kpm_slowpath_patched;

static __kpm_nocfi unsigned long klookup(const char *name);

struct kpm_live_entry {
	const char *name;
	unsigned long addr;
};

static struct kpm_live_entry kpm_live[KPM_LIVE_MAX];
static unsigned int kpm_live_n;

static void kpm_live_parse(const char *str)
{
	const char *p = str;
	unsigned int n = 0;

	if (!str)
		return;

	while (p && *p && n < KPM_LIVE_MAX) {
		const char *comma = strchr(p, ',');
		const char *colon = strchr(p, ':');
		char name[128];
		size_t namelen;
		unsigned long long tmp;
		unsigned long addr;

		if (!colon || (comma && colon > comma))
			break;
		namelen = colon - p;
		if (namelen == 0 || namelen >= sizeof(name))
			break;
		memcpy(name, p, namelen);
		name[namelen] = '\0';
		if (sscanf(colon + 1, "%llx", &tmp) != 1) {
			p = comma ? comma + 1 : NULL;
			continue;
		}
		addr = (unsigned long)tmp;
		if (!addr)
			continue;
		kpm_live[n].name = kstrdup(name, GFP_KERNEL);
		kpm_live[n].addr = addr;
		n++;
		p = comma ? comma + 1 : NULL;
	}
	kpm_live_n = n;
	pr_alert("kpm: live table parsed %u entries\n", kpm_live_n);
}

static void kpm_live_free(void)
{
	unsigned int i;

	for (i = 0; i < kpm_live_n; i++)
		kfree(kpm_live[i].name);
	kpm_live_n = 0;
}

static __kpm_nocfi unsigned long kpm_live_find(const char *name)
{
	unsigned int i;

	for (i = 0; i < kpm_live_n; i++) {
		if (kpm_live[i].name && strcmp(kpm_live[i].name, name) == 0)
			return kpm_live[i].addr;
	}
	return 0;
}

static __kpm_nocfi bool kpm_cfi_patch_ret(unsigned long *addr, u32 *orig)
{
	u32 word;
	int rc;

	if (!addr || !*addr)
		return false;
	if (!host_set_memory_rw) {
		pr_alert("kpm: cfi slowpath neuter SKIPPED (%px): set_memory_rw unresolved\n",
			 (void *)*addr);
		return false;
	}
	word = *(u32 *)*addr;
	rc = host_set_memory_rw(*addr & PAGE_MASK, 1);
	if (rc) {
		pr_alert("kpm: cfi slowpath neuter SKIPPED (%px): set_memory_rw rc=%d\n",
			 (void *)*addr, rc);
		return false;
	}
	*orig = word;
	WRITE_ONCE(*(u32 *)*addr, 0xd65f03c0); /* aarch64 `ret` */
	flush_icache_range(*addr, *addr + 4);
	if (host_kick_all_cpus_sync)
		host_kick_all_cpus_sync();
	if (host_set_memory_ro)
		host_set_memory_ro(*addr & PAGE_MASK, 1);
	pr_alert("kpm: cfi slowpath NEUTERED %px (0x%08x -> ret)\n",
		 (void *)*addr, word);
	return true;
}

static __kpm_nocfi void kpm_cfi_neuter_slowpath(void)
{
	unsigned long addr;
	u32 orig;
	bool one = false;

	addr = klookup("__cfi_slowpath_diag");
	if (addr) {
		orig = 0;
		if (kpm_cfi_patch_ret(&addr, &orig)) {
			kpm_slowpath_diag = addr;
			kpm_slowpath_diag_orig = orig;
			one = true;
		}
	}

	addr = klookup("__cfi_slowpath");
	if (addr && addr != kpm_slowpath_diag) {
		orig = 0;
		if (kpm_cfi_patch_ret(&addr, &orig)) {
			kpm_slowpath_plain = addr;
			kpm_slowpath_plain_orig = orig;
			one = true;
		}
	}

	if (one)
		kpm_slowpath_patched = true;
	else
		pr_alert("kpm: cfi slowpath neuter: neither __cfi_slowpath_diag nor __cfi_slowpath resolved!\n");
}

static __kpm_nocfi void kpm_cfi_restore_slowpath(void)
{
	unsigned long addr;

	if (!kpm_slowpath_patched)
		return;

	addr = kpm_slowpath_diag;
	if (addr && kpm_slowpath_diag_orig) {
		int rc = 0;
		if (host_set_memory_rw)
			rc = host_set_memory_rw(addr & PAGE_MASK, 1);
		if (rc)
			pr_alert("kpm: cfi slowpath restore SKIPPED (%px): set_memory_rw rc=%d\n",
				 (void *)addr, rc);
		else {
			WRITE_ONCE(*(u32 *)addr, kpm_slowpath_diag_orig);
			flush_icache_range(addr, addr + 4);
			if (host_kick_all_cpus_sync)
				host_kick_all_cpus_sync();
			if (host_set_memory_ro)
				host_set_memory_ro(addr & PAGE_MASK, 1);
			pr_alert("kpm: cfi slowpath restored %px (0x%08x)\n",
				 (void *)addr, kpm_slowpath_diag_orig);
			kpm_slowpath_diag = 0;
			kpm_slowpath_diag_orig = 0;
		}
	}

	addr = kpm_slowpath_plain;
	if (addr && kpm_slowpath_plain_orig) {
		int rc = 0;
		if (host_set_memory_rw)
			rc = host_set_memory_rw(addr & PAGE_MASK, 1);
		if (rc)
			pr_alert("kpm: cfi slowpath restore SKIPPED (%px): set_memory_rw rc=%d\n",
				 (void *)addr, rc);
		else {
			WRITE_ONCE(*(u32 *)addr, kpm_slowpath_plain_orig);
			flush_icache_range(addr, addr + 4);
			if (host_kick_all_cpus_sync)
				host_kick_all_cpus_sync();
			if (host_set_memory_ro)
				host_set_memory_ro(addr & PAGE_MASK, 1);
			pr_alert("kpm: cfi slowpath restored %px (0x%08x)\n",
				 (void *)addr, kpm_slowpath_plain_orig);
			kpm_slowpath_plain = 0;
			kpm_slowpath_plain_orig = 0;
		}
	}

	kpm_slowpath_patched = false;
}

static __kpm_nocfi unsigned long klookup(const char *name)
{
	unsigned long addr;

	addr = kpm_live_find(name);
	if (addr)
		return addr;

	if (kallsyms_lookup_name_fn)
		return kallsyms_lookup_name_fn(name);

	return 0;
}

static __kpm_nocfi void __maybe_unused resolve_exec_alloc(void)
{
	unsigned long addr;

	if (kallsyms_lookup_name_fn) {
		addr = kallsyms_lookup_name_fn("vmalloc");
		if (addr)
			host_vmalloc = (void *(*)(unsigned long))addr;
		addr = kallsyms_lookup_name_fn("vfree");
		if (addr)
			host_vfree = (void (*)(const void *))addr;
		addr = kallsyms_lookup_name_fn("set_memory_rw");
		if (addr)
			host_set_memory_rw = (int (*)(unsigned long, int))addr;
		addr = kallsyms_lookup_name_fn("set_memory_ro");
		if (addr)
			host_set_memory_ro = (int (*)(unsigned long, int))addr;
		addr = kallsyms_lookup_name_fn("set_memory_x");
		if (addr)
			host_set_memory_x = (int (*)(unsigned long, int))addr;
		addr = kallsyms_lookup_name_fn("kick_all_cpus_sync");
		if (addr)
			host_kick_all_cpus_sync = (void (*)(void))addr;
		pr_alert("kpm: slowpath syms: diag=%px plain=%px kick=%px\n",
			 (void *)kallsyms_lookup_name_fn("__cfi_slowpath_diag"),
			 (void *)kallsyms_lookup_name_fn("__cfi_slowpath"),
			 (void *)host_kick_all_cpus_sync);
	}
}

static __kpm_nocfi void __maybe_unused resolve_kpm_syms(void)
{
	if (!kallsyms_lookup_name_fn)
		return;

	host_printk = (int (*)(const char *, ...))kallsyms_lookup_name_fn("printk");
	host_copy_to_user = (unsigned long (*)(void __user *, const void *, unsigned long))
		(kallsyms_lookup_name_fn("_copy_to_user") ?: kallsyms_lookup_name_fn("copy_to_user"));

	kf_memcpy = (void *(*)(void *, const void *, size_t))kallsyms_lookup_name_fn("memcpy");
	kf_memset = (void *(*)(void *, int, size_t))kallsyms_lookup_name_fn("memset");
	kf_strsep = (char *(*)(char **, const char *))kallsyms_lookup_name_fn("strsep");
	kf_kstrtoull = (int (*)(const char *, unsigned int, unsigned long long *))kallsyms_lookup_name_fn("kstrtoull");
	kf_snprintf = (int (*)(char *, size_t, const char *, ...))kallsyms_lookup_name_fn("snprintf");
	kf_strlen = (size_t (*)(const char *))kallsyms_lookup_name_fn("strlen");
	kf_memcmp = (int (*)(const void *, const void *, size_t))kallsyms_lookup_name_fn("memcmp");
	kf_strncat = (char *(*)(char *, const char *, size_t))kallsyms_lookup_name_fn("strncat");

	pr_alert("kpm: kf slots: printk=%px copy_to_user=%px strncat=%px\n",
		host_printk ? (void *)host_printk : NULL,
		host_copy_to_user ? (void *)host_copy_to_user : NULL,
		kf_strncat ? (void *)kf_strncat : NULL);
}

u64 kpm_get_symbol(const char *name)
{
	int i;
	unsigned long addr;

	if (name[0] == '\0')
		return 0;

	for (i = 0; i < ARRAY_SIZE(host_exports); i++) {
		if (strcmp(name, host_exports[i].name) == 0)
			return (u64)(unsigned long)host_exports[i].addr;
	}

	addr = klookup(name);
	if (addr)
		return (u64)addr;

	return 0;
}

/* ELF loader logic */
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
	int i, m;

	for (i = 0; i < info->hdr->e_shnum; i++)
		info->sechdrs[i].sh_entsize = ~0UL;

	for (m = 0; m < ARRAY_SIZE(masks); ++m) {
		for (i = 0; i < info->hdr->e_shnum; ++i) {
			Elf64_Shdr *s = &info->sechdrs[i];
			if ((s->sh_flags & masks[m][0]) != masks[m][0] ||
			    (s->sh_flags & masks[m][1]) || s->sh_entsize != ~0UL)
				continue;
			s->sh_entsize = kpm_get_offset(&img->size, s);
		}
		switch (m) {
		case 0:
			img->size = ALIGN(img->size, PAGE_SIZE);
			img->text_size = img->size;
			break;
		case 1:
			img->size = ALIGN(img->size, PAGE_SIZE);
			img->ro_size = img->size;
			break;
		case 2:
			break;
		case 3:
			img->size = ALIGN(img->size, PAGE_SIZE);
			break;
		}
	}
}

static bool kpm_is_core_symbol(const Elf64_Sym *src, const Elf64_Shdr *sechdrs, unsigned int shnum)
{
	const Elf64_Shdr *sec;
	if (src->st_shndx == SHN_UNDEF || src->st_shndx >= shnum || !src->st_name)
		return false;
	sec = sechdrs + src->st_shndx;
	if (!(sec->sh_flags & SHF_ALLOC) || !(sec->sh_flags & SHF_EXECINSTR))
		return false;
	return true;
}

static int kpm_simplify_symbols(struct kpm_image *img, const struct kpm_load_info *info)
{
	Elf64_Shdr *symsec = &info->sechdrs[info->symtab];
	Elf64_Sym *sym = (Elf64_Sym *)symsec->sh_addr;
	unsigned int i;
	int ret = 0;

	for (i = 1; i < symsec->sh_size / sizeof(Elf64_Sym); i++) {
		const char *name = info->strtab_data + sym[i].st_name;
		switch (sym[i].st_shndx) {
		case SHN_COMMON:
			break;
		case SHN_ABS:
			break;
		case SHN_UNDEF: {
			unsigned long addr = kpm_get_symbol(name);
			if (!addr) {
				pr_err("kpm: unknown symbol: %s\n", name);
				ret = -ENOENT;
				break;
			}
			sym[i].st_value = addr;
			break;
		}
		default: {
			unsigned long secbase = info->sechdrs[sym[i].st_shndx].sh_addr;
			sym[i].st_value += secbase;
			break;
		}
		}
	}
	return ret;
}

static int kpm_apply_relocations(struct kpm_image *img, const struct kpm_load_info *info)
{
	int rc = 0;
	unsigned int i;

	for (i = 1; i < info->hdr->e_shnum; i++) {
		unsigned int infosec = info->sechdrs[i].sh_info;
		if (infosec >= info->hdr->e_shnum)
			continue;
		if (!(info->sechdrs[infosec].sh_flags & SHF_ALLOC))
			continue;
		if (info->sechdrs[i].sh_type == SHT_RELA) {
			rc = kpm_apply_relocate_add(info->sechdrs, info->strtab_data, info->symtab, i, img);
			if (rc < 0)
				break;
		}
	}
	return rc;
}

static void kpm_layout_symtab(struct kpm_image *img, struct kpm_load_info *info)
{
	Elf64_Shdr *symsect = info->sechdrs + info->symtab;
	Elf64_Shdr *strsect = info->sechdrs + info->sechdrs[info->symtab].sh_link;
	const Elf64_Sym *src;
	unsigned int i, nsrc, ndst, strtab_size = 0;

	symsect->sh_flags |= SHF_ALLOC;
	symsect->sh_entsize = kpm_get_offset(&img->size, symsect);

	src = (const Elf64_Sym *)((const char *)info->hdr + symsect->sh_offset);
	nsrc = symsect->sh_size / sizeof(*src);

	strtab_size = 1;
	for (ndst = i = 0; i < nsrc; i++) {
		if (i == 0 || kpm_is_core_symbol(src + i, info->sechdrs, info->hdr->e_shnum)) {
			strtab_size += strlen(&info->strtab_data[src[i].st_name]) + 1;
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
	int i;
	info->sechdrs[0].sh_addr = 0;
	for (i = 1; i < info->hdr->e_shnum; i++) {
		Elf64_Shdr *shdr = &info->sechdrs[i];
		if (shdr->sh_type != SHT_NOBITS && info->len < shdr->sh_offset + shdr->sh_size)
			return -ENOEXEC;
		shdr->sh_addr = (unsigned long)((const char *)info->hdr + shdr->sh_offset);
	}
	return 0;
}

static char *kpm_next_string(char *string, unsigned long *secsize)
{
	while (string[0]) {
		string++;
		if ((*secsize)-- <= 1)
			return NULL;
	}
	while (!string[0]) {
		string++;
		if ((*secsize)-- <= 1)
			return NULL;
	}
	return string;
}

static char *kpm_get_next_modinfo(const struct kpm_load_info *info, const char *tag, char *prev)
{
	char *p;
	unsigned int taglen = strlen(tag);
	Elf64_Shdr *infosec;
	unsigned long size;
	char *modinfo;

	infosec = &info->sechdrs[info->modinfo_secobj];
	size = infosec->sh_size;
	modinfo = (char *)info->hdr + infosec->sh_offset;

	if (prev) {
		size -= prev - modinfo;
		modinfo = kpm_next_string(prev, &size);
	}
	for (p = modinfo; p; p = kpm_next_string(p, &size)) {
		if (strncmp(p, tag, taglen) == 0 && p[taglen] == '=')
			return p + taglen + 1;
	}
	return NULL;
}

static int kpm_find_sec(const struct kpm_load_info *info, const char *name)
{
	int i;
	for (i = 1; i < info->hdr->e_shnum; i++) {
		Elf64_Shdr *shdr = &info->sechdrs[i];
		if ((shdr->sh_flags & SHF_ALLOC) && strcmp(info->secstrings + shdr->sh_name, name) == 0)
			return i;
	}
	return 0;
}

static int kpm_setup_load_info(struct kpm_load_info *info)
{
	int rc = 0;
	Elf64_Shdr *sections;

	info->sechdrs = (Elf64_Shdr *)((const char *)info->hdr + info->hdr->e_shoff);
	info->secstrings = (char *)((const char *)info->hdr +
				    info->sechdrs[info->hdr->e_shstrndx].sh_offset);

	if ((rc = kpm_rewrite_section_headers(info))) {
		pr_err("kpm: rewrite section error\n");
		return rc;
	}

	if (!kpm_find_sec(info, KPM_SECT_INIT) || !kpm_find_sec(info, KPM_SECT_EXIT)) {
		pr_err("kpm: no .kpm.init or .kpm.exit section\n");
		return -ENOEXEC;
	}

	{
		int i;
		info->modinfo_secobj = 0;
		for (i = 1; i < info->hdr->e_shnum; i++) {
			if ((info->sechdrs[i].sh_flags & SHF_ALLOC) &&
			    strcmp(info->secstrings + info->sechdrs[i].sh_name, KPM_SECT_INFO) == 0) {
				info->modinfo_secobj = i;
				break;
			}
		}
	}
	if (!info->modinfo_secobj) {
		pr_err("kpm: no .kpm.info section\n");
		return -ENOEXEC;
	}
	info->modinfo_base = (const char *)info->hdr + info->sechdrs[info->modinfo_secobj].sh_offset;
	info->modinfo_size = info->sechdrs[info->modinfo_secobj].sh_size;

	{
		char *name = kpm_get_next_modinfo(info, KPM_MODINFO_NAME, NULL);
		if (!name) {
			pr_err("kpm: module name not found\n");
			return -ENOEXEC;
		}
		info->modinfo_name = name;
		pr_alert("kpm: loading [%s]\n", name);
	}
	{
		char *version = kpm_get_next_modinfo(info, KPM_MODINFO_VERSION, NULL);
		if (version)
			info->modinfo_version = version;
	}
	info->modinfo_license = kpm_get_next_modinfo(info, KPM_MODINFO_LICENSE, NULL);
	info->modinfo_author = kpm_get_next_modinfo(info, KPM_MODINFO_AUTHOR, NULL);
	info->modinfo_description = kpm_get_next_modinfo(info, KPM_MODINFO_DESCRIPTION, NULL);

	info->symtab = 0;
	for (sections = info->sechdrs; sections < info->sechdrs + info->hdr->e_shnum; sections++) {
		if (sections->sh_type == SHT_SYMTAB) {
			info->symtab = sections - info->sechdrs;
			info->strtab = sections->sh_link;
			info->strtab_data = (const char *)info->hdr + info->sechdrs[info->strtab].sh_offset;
			break;
		}
	}
	if (!info->symtab) {
		pr_err("kpm: module has no symbols (stripped?)\n");
		return -ENOEXEC;
	}
	return 0;
}

static __kpm_nocfi int kpm_move_module(struct kpm_image *img, struct kpm_load_info *info)
{
	int i;

	if (!host_vmalloc) {
		pr_err("kpm: vmalloc unresolved\n");
		return -ENOENT;
	}
	img->base = host_vmalloc(img->size);
	if (!img->base) {
		pr_err("kpm: vmalloc failed, need %lu bytes\n", img->size);
		return -ENOMEM;
	}
	if (host_set_memory_rw)
		host_set_memory_rw((unsigned long)img->base,
				   DIV_ROUND_UP(img->size, PAGE_SIZE));
	memset(img->base, 0, img->size);

	for (i = 1; i < info->hdr->e_shnum; i++) {
		void *dest;
		Elf64_Shdr *shdr = &info->sechdrs[i];
		const char *sname;
		if (!(shdr->sh_flags & SHF_ALLOC))
			continue;

		dest = (char *)img->base + shdr->sh_entsize;
		sname = info->secstrings + shdr->sh_name;

		if (shdr->sh_type != SHT_NOBITS)
			memcpy(dest, (void *)shdr->sh_addr, shdr->sh_size);

		shdr->sh_addr = (unsigned long)dest;

		if (!img->init && !strcmp(KPM_SECT_INIT, sname))
			img->init = (const char *)dest;
		if (!strcmp(KPM_SECT_CTL0, sname))
			img->ctl0 = (const char *)dest;
		if (!strcmp(KPM_SECT_CTL1, sname))
			img->ctl1 = (const char *)dest;
		if (!img->exit && !strcmp(KPM_SECT_EXIT, sname))
			img->exit = (const char *)dest;
		if (!img->info && !strcmp(KPM_SECT_INFO, sname))
			img->info = (const char *)dest;
	}

	{
		long delta = (const char *)img->info - info->modinfo_base;
		img->info_name = (char *)info->modinfo_name + delta;
		img->info_version = (char *)info->modinfo_version + delta;
		if (info->modinfo_license)
			img->info_license = (char *)info->modinfo_license + delta;
		if (info->modinfo_author)
			img->info_author = (char *)info->modinfo_author + delta;
		if (info->modinfo_description)
			img->info_description = (char *)info->modinfo_description + delta;
	}
	return 0;
}

static int kpm_elf_header_check(struct kpm_load_info *info)
{
	if (info->len <= sizeof(*info->hdr))
		return -ENOEXEC;
	if (memcmp(info->hdr->e_ident, ELFMAG, SELFMAG) || info->hdr->e_type != ET_REL ||
	    info->hdr->e_machine != EM_AARCH64 || info->hdr->e_shentsize != sizeof(Elf64_Shdr))
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
	long rc = 0;
	kpm_initcall_t init_fn;

	if ((rc = kpm_elf_header_check(&info)))
		goto out;
	pr_alert("kpm: l1 header ok len=%lu\n", len);
	if ((rc = kpm_setup_load_info(&info)))
		goto out;
	pr_alert("kpm: l2 setup ok name=%s\n", info.modinfo_name ?: "?");

	memset(img, 0, sizeof(*img));
	kpm_layout_sections(img, &info);
	kpm_layout_symtab(img, &info);
	pr_alert("kpm: l3 layout size=%lu text=%lu\n", img->size, img->text_size);

	if ((rc = kpm_move_module(img, &info)))
		goto out;
	pr_alert("kpm: l4 move base=%px size=%lu\n", img->base, img->size);

	if ((rc = kpm_simplify_symbols(img, &info)))
		goto out;
	pr_alert("kpm: l5 simplify ok\n");

	if ((rc = kpm_apply_relocations(img, &info)))
		goto out;
	pr_alert("kpm: l6 reloc ok\n");

	flush_icache_range((unsigned long)img->base, (unsigned long)img->base + img->size);
	pr_alert("kpm: l7 flush done\n");
	
	if (host_set_memory_x)
		host_set_memory_x((unsigned long)img->base,
				  DIV_ROUND_UP(img->size, PAGE_SIZE));

	if (!img->init)
		goto out;
	pr_alert("kpm: l8 call kpm init at %px\n", img->init);

	kpm_cfi_neuter_slowpath();

	init_fn = *(kpm_initcall_t *)img->init;
	pr_alert("kpm: init_fn addr=%px event=%s\n", (void *)init_fn, event ?: "");
	rc = init_fn(args, event, reserved);
	pr_alert("kpm: l9 kpm init rc=%ld\n", rc);

	if (!rc) {
		pr_alert("kpm: [%s] succeed\n", img->info_name ?: "?");
		img->loaded = true;
	} else {
		pr_err("kpm: [%s] failed rc=%ld, try exit ...\n",
		       img->info_name ?: "?", rc);
		if (img->exit) {
			kpm_exitcall_t exit_fn = *(kpm_exitcall_t *)img->exit;
			exit_fn(reserved);
		}
	}

	if (rc) {
		if (host_set_memory_rw)
			host_set_memory_rw((unsigned long)img->base,
					   DIV_ROUND_UP(img->size, PAGE_SIZE));
		if (host_vfree)
			host_vfree(img->base);
	}

out:
	if (!img->loaded)
		kpm_cfi_restore_slowpath();
	return rc;
}

/* module lifecycle */
static int __kpm_nocfi kpm_host_do_init(void)
{
	int rc;

	pr_alert("kpm: host init (agent mode)\n");

	kpm_live_parse(kpm_syms);

	kallsyms_lookup_name_fn =
		(unsigned long (*)(const char *))kpm_live_find("kallsyms_lookup_name");
	if (!kallsyms_lookup_name_fn) {
		pr_err("kpm: live table has no kallsyms_lookup_name entry, refusing\n");
		return -EINVAL;
	}
	pr_alert("kpm: t1 anchor kallsyms_lookup_name=%px\n", (void *)kallsyms_lookup_name_fn);

	resolve_exec_alloc();
	resolve_kpm_syms();
	pr_alert("kpm: t2 vmalloc=%px vfree=%px printk=%px copy_to_user=%px\n",
		host_vmalloc, host_vfree, host_printk, host_copy_to_user);

	if (!host_vmalloc) {
		pr_err("kpm: vmalloc unresolved, refusing\n");
		return -ENOSYS;
	}

	rc = kpm_ctl_init();
	if (rc)
		return rc;

	pr_alert("kpm: host ready. push .kpm as memory via ioctl(LOAD) on /dev/suzhi_loader\n");
	return 0;
}

static int __init kpm_host_init(void)
{
	return kpm_host_do_init();
}

void __kpm_nocfi kpm_unload_current(void)
{
	if (!kpm_image.loaded && !kpm_image.base)
		return;

	pr_alert("kpm: unload current image\n");
	if (kpm_image.loaded && kpm_image.exit) {
		kpm_exitcall_t exit_fn = *(kpm_exitcall_t *)kpm_image.exit;
		exit_fn(NULL);
		kpm_image.loaded = false;
	}
	kpm_cfi_restore_slowpath();
	if (kpm_image.base) {
		if (host_set_memory_rw)
			host_set_memory_rw((unsigned long)kpm_image.base,
					   DIV_ROUND_UP(kpm_image.size, PAGE_SIZE));
		if (host_vfree)
			host_vfree(kpm_image.base);
	}
	memset(&kpm_image, 0, sizeof(kpm_image));
}

int kpm_is_loaded(void)
{
	return kpm_image.loaded ? 1 : 0;
}

static void __kpm_nocfi kpm_host_do_exit(void)
{
	pr_alert("kpm: host exit\n");
	kpm_unload_current();
	kpm_ctl_exit();
	kpm_live_free();
	pr_alert("kpm: host exit done\n");
}

static void __exit kpm_host_exit(void)
{
	kpm_host_do_exit();
}

module_init(kpm_host_init);
module_exit(kpm_host_exit);
