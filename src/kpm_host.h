#ifndef _KPM_HOST_H_
#define _KPM_HOST_H_

#include <linux/elf.h>
#include <linux/kernel.h>
#include <linux/types.h>

#define KPM_HOST_NAME "kpm_host"
#define KPM_ELF_MACHINE EM_AARCH64
#define KPM_SECT_INIT ".kpm.init"
#define KPM_SECT_EXIT ".kpm.exit"
#define KPM_SECT_INFO ".kpm.info"
#define KPM_SECT_CTL0 ".kpm.ctl0"
#define KPM_SECT_CTL1 ".kpm.ctl1"

#define KPM_MODINFO_NAME "name"
#define KPM_MODINFO_VERSION "version"
#define KPM_MODINFO_LICENSE "license"
#define KPM_MODINFO_AUTHOR "author"
#define KPM_MODINFO_DESCRIPTION "description"

typedef long (*kpm_initcall_t)(const char *args, const char *event, void *reserved);
typedef long (*kpm_ctl0call_t)(const char *ctl_args, char *__user out_msg, int outlen);
typedef long (*kpm_ctl1call_t)(void *a1, void *a2, void *a3);
typedef long (*kpm_exitcall_t)(void *reserved);

struct kpm_load_info {
	const Elf64_Ehdr *hdr; /* ELF image */
	unsigned long len;
	Elf64_Shdr *sechdrs;
	const char *secstrings;
	unsigned int modinfo_secobj;
	unsigned int strtab;
	const char *strtab_data;
	unsigned int symtab;
	const char *modinfo_base;
	unsigned long modinfo_size;
	const char *modinfo_name;
	const char *modinfo_version;
	const char *modinfo_license;
	const char *modinfo_author;
	const char *modinfo_description;
};

struct kpm_image {
	void *base;
	unsigned long size;
	unsigned long text_size;
	unsigned long ro_size;
	const char *init;   /* .kpm.init */
	const char *exit;   /* .kpm.exit */
	const char *ctl0;   /* .kpm.ctl0 */
	const char *ctl1;   /* .kpm.ctl1 */
	const char *info;   /* .kpm.info (relocated) */
	char *info_name;
	char *info_version;
	char *info_license;
	char *info_author;
	char *info_description;
	bool loaded;
};

/* kpm_host.c */
long kpm_load_module(const void *data, unsigned long len, const char *args, const char *event, void *reserved);

/* resident agent (data path) */
extern struct kpm_image kpm_image;
int kpm_is_loaded(void);
void kpm_unload_current(void);

/* kpm_ctl.c */
int kpm_ctl_init(void);
void kpm_ctl_exit(void);

/* live symbol table (bootstrap anchor from userspace, replaces kprobe) */
#define KPM_LIVE_MAX 64
#define KPM_LIVE_NAME_MAX 128

/* kpm_host_re.c */
int kpm_apply_relocate_add(Elf64_Shdr *sechdrs, const char *strtab, unsigned int symindex, unsigned int relsec,
			   struct kpm_image *img);

/* symbol resolution backends */
extern u64 kpm_get_symbol(const char *name);

#endif /* _KPM_HOST_H_ */
