/*
 * File Name: rg_crypto.h
 * Author: John Egan
 * Last Modified: May 6, 2009
 * Description: Header file for crypto primatives for RST Guard
 */

#ifndef _RP_CRYPTO_H
#define _RP_CRYPTO_H

#include <linux/types.h>

__u64 rg_get_nonce(void);
__u64 rg_get_unique_id(void);
__u64 rg_calc_secret_value(__u64 nonce, __u32 loc_ip, __u32 loc_port,
			   __u32 rmt_ip, __u32 rmt_port);
__u64 rg_calc_conn_hash(__u64 svalue, __u64 nonce, __u32 loc_ip, __u32 loc_port,
			__u32 rmt_ip, __u32 rmt_port);

/* DEBUG */
/* #define __RG_DEBUG */
#ifdef __RG_DEBUG
void rg_print_debug(char *string);
#endif

#endif
