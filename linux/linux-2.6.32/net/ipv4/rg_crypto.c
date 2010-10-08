/*
 * File Name: rg_cypto.c
 * Description: Implements the cyptographic primatives for the
 *		RST Guard TCP extension
 * Author: John Egan & Ricky Ghov
 * Last Modified: Dec 6, 2009
 */

#include <linux/types.h>
#include <linux/stat.h>
#include <linux/fcntl.h>
#include <linux/unistd.h>
#include <linux/stat.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <asm/byteorder.h>
#include "rg_crypto.h"

/* kernel includes */
#include <linux/syscalls.h>
#include <asm/msr.h>
#include <asm/uaccess.h>
#include <linux/string.h>
#include <linux/file.h>
#include <crypto/hash.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <crypto/rng.h>

#define XBUFSIZE 8

struct tcrypt_result {
	struct completion completion;
	int err;
};


static void tcrypt_complete(struct crypto_async_request *req, int err)
{
	struct tcrypt_result *res = req->data;

	if (err == -EINPROGRESS)
		return;

	res->err = err;
	complete(&res->completion);
}


static int testmgr_alloc_buf(char *buf[XBUFSIZE])
{
	int i;

	for (i = 0; i < XBUFSIZE; i++) {
		buf[i] = (void *)__get_free_page(GFP_KERNEL);
		if (!buf[i])
			goto err_free_buf;
	}

	return 0;
err_free_buf:
	while (i-- > 0)
		free_page((unsigned long)buf[i]);
	
	return -ENOMEM;
}

static void testmgr_free_buf(char *buf[XBUFSIZE])
{
	int i;

	for (i = 0; i < XBUFSIZE; i++)
		free_page((unsigned long)buf[i]);
}



/*
 * Method Name: rg_getNonce
 * Description: Returns a 64 bit random value by returning the first 64 bits
 *		by hashing the current cycle counter using sha512
 */
__u64 rg_get_nonce()
{
	char result[64];
	__u64 return_value;
	__u64 time = native_read_tsc();
	struct crypto_ahash * tfm;
	struct scatterlist sg[8];
	struct ahash_request *req;
	struct tcrypt_result tresult;
	void *hash_buff;
	char *xbuf[XBUFSIZE];
	int ret = -ENOMEM;

	tfm = crypto_alloc_ahash("sha512",0,0);
	if(IS_ERR(tfm)) {
		printk(KERN_ERR "alg: hash: Failed to load transform for hmac(sha512)");
		return 0;
	}

	if (testmgr_alloc_buf(xbuf)){
		crypto_free_ahash(tfm);
		return 0;
	}
	init_completion(&tresult.completion);
	req = ahash_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		printk(KERN_ERR "alg: rg_get_nonce Failed to allocate request "
			"for sha512");
		crypto_free_ahash(tfm);
		ahash_request_free(req);
		testmgr_free_buf(xbuf);
		return 0;
	}
	ahash_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				   tcrypt_complete, &tresult);
	memset(result, 0, 64);
	hash_buff = xbuf[0];
	ret = -EINVAL;
	memcpy(hash_buff, &time, sizeof (__u64));
	sg_init_one(&sg[0], hash_buff, sizeof (__u64));
	ahash_request_set_crypt(req, sg, result, sizeof(__u64));
	ret = crypto_ahash_digest(req);
	switch (ret) {
		case 0:
			break;
		case -EINPROGRESS:
		case -EBUSY:
			ret = wait_for_completion_interruptible(
				&tresult.completion);
			if (!ret && !(ret = tresult.err)) {
				INIT_COMPLETION(tresult.completion);
				break;
			}

		default:
			printk(KERN_ERR "alg: hash: digest failed "
				"for sha512: ret=%d\n", -ret);
			crypto_free_ahash(tfm);
			ahash_request_free(req);
			testmgr_free_buf(xbuf);
			return 0;
			
	}
	memcpy(&return_value,result,sizeof(__u64));
	crypto_free_ahash(tfm);
	ahash_request_free(req);
	testmgr_free_buf(xbuf);
	return return_value;
}

/*
 * Method Name: rg_getUniqueID
 * Description: Should retrieve the unique ID if it exists, otherwise
 *		generates a random unique id for this computer and
 *		stores it in the file .tcp_rg_uid. By default look in 
 *		/etc/tcp_rg_uid for it.
 * Return Value: The unique id in a 64 bit unsigned integer in
 *		 big endian order
 */
char *uidfname = "/etc/tcp_rg_uid";
__u64 rg_get_unique_id()
{
	int fp;
	__u64 uid = 0;

	mm_segment_t fs = get_fs();
	set_fs(KERNEL_DS);
	
	fp = sys_open(uidfname, O_RDONLY, 0644);
	if (fp < 0) {
		fp = sys_open(uidfname, O_WRONLY | O_CREAT, 0644);

		if (fp < 0) {
			return 42;
		}
		uid = rg_get_nonce();
		sys_write(fp, &uid, sizeof (__u64));
	} else {
		sys_read(fp, &uid, sizeof (__u64));
	}
	sys_close(fp);
	set_fs(fs);
	return uid; 
}

/*
 * Method Name: rg_calcSecretValue
 * Arguments: (all in big endian order)
 *		__u32 nonce - The nonce value
 *		__u32 loc_ip - My ip address
 *		__u32 loc_port - My port
 *		__u32 rmt_up - The remote ip address
 *		__u32 rmt_port - The remote port
 * Return Value: The s value in big endian order
 */
__u64 rg_calc_secret_value(__u64 nonce, __u32 loc_ip, __u32 loc_port, __u32 rmt_ip,
		     __u32 rmt_port)
{
	__u32 message[6];
	char result[64];
	__u64 return_value;
	__u64 uid = rg_get_unique_id();
	struct crypto_ahash * tfm;
	struct scatterlist sg[8];
	struct ahash_request *req;
	struct tcrypt_result tresult;
	void *hash_buff;
	char *xbuf[XBUFSIZE];
	int ret = -ENOMEM;

	tfm = crypto_alloc_ahash("hmac(sha512)",0,0);
	if(IS_ERR(tfm)) {
		printk(KERN_ERR "alg: hash: Failed to load transform for hmac(sha512)");
		return 0;
	}

	
	if (testmgr_alloc_buf(xbuf)){
		crypto_free_ahash(tfm);
		return 0;
	}

	init_completion(&tresult.completion);
	
	req = ahash_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		printk(KERN_ERR "alg: rg_calc_secret_value Failed to allocate request "
			"for sha512");
		crypto_free_ahash(tfm);
		testmgr_free_buf(xbuf);
		return 0;
	}
	ahash_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				   tcrypt_complete, &tresult);

	memset(result, 0, 64);
	hash_buff = xbuf[0];
	ret = -EINVAL;
	memcpy(message, &nonce, sizeof (__u64));
	message[2] = loc_ip;
	message[3] = loc_port;
	message[4] = rmt_ip;
	message[5] = rmt_port;
	memcpy(hash_buff, message, sizeof (__u32) * 6);
	sg_init_one(&sg[0], hash_buff, sizeof (__u32) * 6);
	crypto_ahash_clear_flags(tfm, ~0);
	ret = crypto_ahash_setkey(tfm, &uid, sizeof(__u64));
	if (ret) {
		printk(KERN_ERR "alg: hash: setkey failed "
			"for hmac(sha512): ret=%d\n",-ret);
		crypto_free_ahash(tfm);
		ahash_request_free(req);
		testmgr_free_buf(xbuf);
		return 0;
	}

	ahash_request_set_crypt(req, sg, result, sizeof (__u32) * 6);
	ret = crypto_ahash_digest(req);

	switch (ret) {
		case 0:
			break;
		case -EINPROGRESS:
		case -EBUSY:
			ret = wait_for_completion_interruptible(
				&tresult.completion);
			if (!ret && !(ret = tresult.err)) {
				INIT_COMPLETION(tresult.completion);
				break;
			}

		default:
			printk(KERN_ERR "alg: hash: digest failed "
				"for hmac(sha512): ret=%d\n", -ret);
			crypto_free_ahash(tfm);
			ahash_request_free(req);
			testmgr_free_buf(xbuf);
			return 0;
			
	}

	memcpy(&return_value,result,sizeof(__u64));
	crypto_free_ahash(tfm);
	ahash_request_free(req);
	testmgr_free_buf(xbuf);

	return return_value;

}

/*
 * Method Name: rg_calcConnHash
 * Arguments: (all in big endian order)
 *		__u64 svalue - The secret value
 *		__u32 nonce - The nonce value
 *		__u32 loc_ip - My ip address (if calculating my hash)
 *		__u32 loc_port - My port (if calculating my hash)
 *		__u32 rmt_up - The remote ip address
 *		__u32 rmt_port - The remote port
 * Return Value: The s value in big endian order
 */
__u64 rg_calc_conn_hash(__u64 svalue, __u64 nonce, __u32 loc_ip, __u32 loc_port,
		  __u32 rmt_ip, __u32 rmt_port)
{
	__u32 message[6];
	char result[64];
	__u64 return_value;
	struct crypto_ahash * tfm;
	struct scatterlist sg[8];
	struct ahash_request *req;
	struct tcrypt_result tresult;
	void *hash_buff;
	char *xbuf[XBUFSIZE];
	int ret = -ENOMEM;

	tfm = crypto_alloc_ahash("hmac(sha512)",0,0);
	
	if(IS_ERR(tfm)) {
		printk(KERN_ERR "alg: hash: Failed to load transform for hmac(sha512)");
		return 0;
	}
	
	if (testmgr_alloc_buf(xbuf)){
		crypto_free_ahash(tfm);
		return 0;
	}
	
	init_completion(&tresult.completion);
	req = ahash_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		printk(KERN_ERR "alg: rg_calc_secret_value Failed to allocate request "
			"for sha512");
		crypto_free_ahash(tfm);
		testmgr_free_buf(xbuf);
		return 0;
	}
	ahash_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				   tcrypt_complete, &tresult);


	memset(result, 0, 64);
	hash_buff = xbuf[0];

	ret = -EINVAL;
	
	memcpy(message, &nonce, sizeof (__u64));
	message[2] = loc_ip;
	message[3] = loc_port;
	message[4] = rmt_ip;
	message[5] = rmt_port;
	memcpy(hash_buff, message, sizeof (__u32) * 6);
	sg_init_one(&sg[0], hash_buff, sizeof (__u32) * 6);

	crypto_ahash_clear_flags(tfm, ~0);
	ret = crypto_ahash_setkey(tfm, &svalue, sizeof(__u64));
	if (ret) {
		printk(KERN_ERR "alg: hash: setkey failed "
			"for hmac(sha512): ret=%d\n", -ret);
		crypto_free_ahash(tfm);
		ahash_request_free(req);
		testmgr_free_buf(xbuf);
		return 0;
	}
	ahash_request_set_crypt(req, sg, result, sizeof (__u32) * 6);
	ret = crypto_ahash_digest(req);

	switch (ret) {
		case 0:
			break;
		case -EINPROGRESS:
		case -EBUSY:
			ret = wait_for_completion_interruptible(
				&tresult.completion);
			if (!ret && !(ret = tresult.err)) {
				INIT_COMPLETION(tresult.completion);
				break;
			}

		default:
			printk(KERN_ERR "alg: hash: digest failed "
				"for hmac(sha512): ret=%d\n", -ret);
			crypto_free_ahash(tfm);
			ahash_request_free(req);
			testmgr_free_buf(xbuf);
			return 0;
			
	}

	memcpy(&return_value, result, sizeof(__u64));
	crypto_free_ahash(tfm);
	ahash_request_free(req);
	testmgr_free_buf(xbuf);
	return return_value;

}

