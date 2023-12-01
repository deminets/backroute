#include <arpa/inet.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>

#include <xtables.h>
#include <linux/netfilter.h>
#include "../module/nf_backroute.h"

//======================================================================

enum {
	O_UPDATE = 1 << 0,
	O_HOOK   = 1 << 1,
};

static const struct xt_option_entry BACKROUTE_opts[] = {
	{.name = "update",  .id = O_UPDATE, .type = XTTYPE_STRING},
	{.name = "hookout", .id = O_HOOK,   .type = XTTYPE_STRING},
	XTOPT_TABLEEND,
};


#define max(x, y) ( (x) > (y) ? (x) : (y) )
#define min(x, y) ( (x) < (y) ? (x) : (y) )

static int str2int(const char *str, int num, ...)
{
	const char *par;
	int ret = -EINVAL;
	int slen, plen, i;
	va_list arg;

	va_start( arg, num );

	if(!str || num <= 0) goto out;

	slen = strlen(str);

	for( i = 0; i < num; i++ ) {
		par = va_arg(arg, const char *);
		plen = strlen(par);
		if(strncasecmp(str, par, min(slen,plen)) == 0) {
			ret = i;
			break;
		}
	}

out:
	va_end( arg );
	return(ret);
}


static void BACKROUTE_parse(struct xt_option_call *cb)
{
	nf_backroute_t *opt = cb->data;
	int ret = 0;

	xtables_option_parse(cb);

	switch (cb->entry->id) {
		case O_UPDATE:
			ret = str2int(cb->arg, 3, "no","yes","always");
			if(ret >= 0) opt->f_update = ret;
			break;
		case O_HOOK:
			ret = str2int(cb->arg, 2, "pre","post");
			if(ret >= 0) opt->f_hook = ret;
			break;
		default:
			xtables_error(PARAMETER_PROBLEM, "BACKROUTE: unknown option");
			break;
	}// switch

	if(ret < 0) xtables_error(PARAMETER_PROBLEM, "BACKROUTE: unknown argument");

}


static void BACKROUTE_init(struct xt_entry_target *t)
{
	nf_backroute_t *opt = (nf_backroute_t *)t->data;

	/* default */
	opt->f_update = 0;
	opt->f_hook = 0;
}


const char *update_str[] = { "no","yes","always","ERROR"};

static void BACKROUTE_print(const void *ip, const struct xt_entry_target *target, int numeric)
{
	const nf_backroute_t *opt = (const nf_backroute_t *)target->data;

	printf(" update %s  hookout %s", update_str[opt->f_update], (opt->f_hook==hook_post)?"post":"pre" );
}

static void BACKROUTE_save(const void *ip, const struct xt_entry_target *target)
{
	const nf_backroute_t *opt = (const nf_backroute_t *)target->data;

	printf(" --update %s --hookout %s", update_str[opt->f_update], (opt->f_hook==hook_post)?"post":"pre" );
}

static void BACKROUTE_help(void)
{
	printf(
"BACKROUTE target options:\n"
"  --update  [no/yes/always]			update fix MAC in CT\n"
"  --hookout [post/pre]          		tramsit PRE/POST route\n");

	printf("(*) See man page or read the INCOMPATIBILITES file for compatibility issues.\n");
}

//======================================================================

static struct xtables_target backroute_tg_reg = {
	.name			= TARGET_NAME,
	.version		= XTABLES_VERSION,
	.revision   	= 0,
	.family			= NFPROTO_IPV4,
	.size			= XT_ALIGN(sizeof(nf_backroute_t)),
	.userspacesize	= XT_ALIGN(sizeof(nf_backroute_t)),
	.help			= BACKROUTE_help,
	.init			= BACKROUTE_init,
	.print			= BACKROUTE_print,
	.save			= BACKROUTE_save,
	.x6_parse		= BACKROUTE_parse,
	.x6_options		= BACKROUTE_opts,
};


void __attribute((constructor)) backroute_init(void)
{
	xtables_register_target(&backroute_tg_reg);
}

//======================================================================

