/* Name:		backroute
 * Date:		2024
 * Version:		1.0.0
 * Brief:		BackRoute module
 * License:		Apache License 2.0
 * Author(s):		deminets
 * */

#ifndef _INCLUDE_BACKROUTE_H
#define _INCLUDE_BACKROUTE_H

typedef
enum {	hook_pre  = 0,
		hook_post = 1,
	 } nf_backroute_hook_t;

typedef
struct nf_backroute_s {
	union {
		uint32_t all; 
		struct {
			uint32_t f_hook:1;
			uint32_t f_update:2;
		};
	};
} nf_backroute_t;

#define TARGET_NAME "BACKROUTE"

#endif // _INCLUDE_BACKROUTE_H
