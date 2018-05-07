#define pr_fmt(fmt) "cs423_mp4: " fmt

#include <linux/lsm_hooks.h>
#include <linux/security.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/binfmts.h>
#include <linux/fs.h>
#include <linux/printk.h>

#include "mp4_given.h"

#define NAME_SIZE 3
#define CTX_BUF_SIZE 48
#define PATH_BUF_SIZE 128

/**
 * get_inode_sid - Get the inode mp4 security label id
 *
 * @inode: the input inode
 *
 * @return the inode's security id if found.
 *
 */
static int get_inode_sid(struct inode *inode)
{
	int sid;

	if(!inode) {
		pr_err("get_inode_sid: inode is null! \n");
		goto NO_ACCESS;
	}

	struct dentry *den = d_find_alias(inode);
	if (!den) {
		pr_err("get_inode_sid: fail to get dentry\n");
		goto NO_ACCESS;
	}

	char *cred_ctx = kmalloc(CTX_BUF_SIZE, GFP_KERNEL);
	if(!cred_ctx) {
		dput(den);
		pr_err("get_inode_sid: fail to allocate cred_ctx\n");
		goto NO_ACCESS;
	}

	// get xattr of this inode
	if (!inode->i_op->getxattr) { // error handling for file system like proc
		dput(den);
		kfree(cred_ctx);
		goto NO_ACCESS;
	}

	int ret_sz = inode->i_op->getxattr(den, XATTR_NAME_MP4, cred_ctx, CTX_BUF_SIZE);
	if (ret_sz <= 0) {
		// if (printk_ratelimit()) {
		// 	pr_err("get_inode_sid: fail to getxattr, ret_sz %d !\n",ret_sz);
		// }
		dput(den);
		kfree(cred_ctx);
		goto NO_ACCESS;
	}
	cred_ctx[ret_sz] = '\0';

	// translate cred context into sid
	sid = __cred_ctx_to_sid(cred_ctx);

	// clean up
	kfree(cred_ctx);
	dput(den);

	return sid;


NO_ACCESS:
	return MP4_NO_ACCESS; // 0
}

/**
 * mp4_bprm_set_creds - Set the credentials for a new task
 *
 * @bprm: The linux binary preparation structure
 *
 * returns 0 on success.
 */
static int mp4_bprm_set_creds(struct linux_binprm *bprm)
{
	 if (bprm->cred_prepared){
     return 0;
	 }

	 // 1. find cred and blob
	 if (bprm->cred == NULL || bprm->cred->security == NULL) {
		 pr_err("cred or blob is NULL!");
		 return 0;
	 }
	 struct mp4_security *blob = bprm->cred->security;

	 // 2. get sid of the inode that create this process
	 if (bprm->file == NULL || bprm->file->f_inode == NULL) {
		 pr_err("file or f_inode is NULL!");
		 return 0;
	 }
	 int sid = get_inode_sid(bprm->file->f_inode);

	 // 3. set task blob to this sid
	 if (sid == MP4_TARGET_SID) {
		 blob->mp4_flags = sid;
	 }

	 return 0;
}

/**
 * mp4_cred_alloc_blank - Allocate a blank mp4 security label
 *
 * @cred: the new credentials
 * @gfp: the atomicity of the memory allocation
 *
 */
static int mp4_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	if (!cred) {
		return 0;
	}
	struct mp4_security *newblob;
	newblob = kzalloc(sizeof(struct mp4_security), gfp);
	if (newblob == NULL) {
		return -ENOMEM;
	}
	newblob->mp4_flags = MP4_NO_ACCESS;
	cred->security = newblob;

	return 0;
}


/**
 * mp4_cred_free - Free a created security label
 *
 * @cred: the credentials struct
 *
 */
static void mp4_cred_free(struct cred *cred)
{
	if (!cred) {
		return;
	}
	 struct mp4_security *blob = cred->security;
	 if (blob) {
		 kzfree(blob);
	 }
	 cred->security = NULL;

}

/**
 * mp4_cred_prepare - Prepare new credentials for modification
 *
 * @new: the new credentials
 * @old: the old credentials
 * @gfp: the atomicity of the memory allocation
 *
 */
static int mp4_cred_prepare(struct cred *new, const struct cred *old,
			    gfp_t gfp)
{
	struct mp4_security *newblob;
	newblob = kzalloc(sizeof(struct mp4_security), gfp);
	if (newblob == NULL) {
		return -ENOMEM;// fail to malloc
	}

	if (old->security != NULL) {
		memcpy(newblob, old->security, sizeof(struct mp4_security));
	}
	else {
		newblob->mp4_flags = MP4_NO_ACCESS;
	}

	new->security = newblob;

	return 0;
}

/**
 * mp4_inode_init_security - Set the security attribute of a newly created inode
 *
 * @inode: the newly created inode
 * @dir: the containing directory
 * @qstr: unused
 * @name: where to put the attribute name
 * @value: where to put the attribute value
 * @len: where to put the length of the attribute
 *
 * returns 0 if all goes well, -ENOMEM if no memory, -EOPNOTSUPP to skip
 *
 */
static int mp4_inode_init_security(struct inode *inode, struct inode *dir,
				   const struct qstr *qstr,
				   const char **name, void **value, size_t *len)
{

	if (!inode || !dir){
		return -EOPNOTSUPP;
	}

	// 1. check if the task creating this inode is target
	// if not : return

	if (!current_cred()->security) {
		goto RETURN;
	}
	struct mp4_security *blob = current_cred()->security;
	if (blob->mp4_flags != MP4_TARGET_SID) {
		return -EOPNOTSUPP;
	}
	// pr_info("mp4_inode_init_security: target %d", blob->mp4_flags);


	// 2. set xattr of for this inode
	// (*setxattr) (struct dentry *, const char *,const void *,size_t,0); --> a user-space function

	// set name
	char *n, *v = 0;
	n = kmalloc(NAME_SIZE*sizeof(char)+1, GFP_KERNEL);
	// n = kstrdup(XATTR_NAME_MP4, GFP_KERNEL);
	if (!n){
		return -ENOMEM;
	}
	int ret_n = snprintf(n, NAME_SIZE*sizeof(char)+1, XATTR_MP4_SUFFIX);
	if (ret_n <= 0) {
		goto RETURN;
	}
	n[ret_n] = '\0';
	*name = n;

	// set value and len
	int ret_v;
	v = kmalloc(CTX_BUF_SIZE, GFP_KERNEL);
	if (!v) {
		return -ENOMEM;
	}
	if (S_ISDIR(inode->i_mode)) { // check if the inode is a directory. *stat is a user-space
		ret_v = snprintf(v, CTX_BUF_SIZE, "dir-write");
		// v = kstrdup("dir-write", GFP_KERNEL);
		// *len = 10;
	}
	else {
		ret_v = snprintf(v, CTX_BUF_SIZE, "read-write");
		// v = kstrdup("read-write", GFP_KERNEL);
		// *len = 11;
	}
	if (ret_v <= 0) {
		goto RETURN;
	}
	v[ret_v] = '\0';
	*value = v;
	*len = ret_v + 1; // plus 1 here to include '\0'


RETURN:
	return 0;
}

/**
 * mp4_has_permission - Check if subject has permission to an object
 *
 * @ssid: the subject's security id
 * @osid: the object's security id
 * @mask: the operation mask
 *
 * returns 0 is access granter, -EACCES otherwise
 *
 */
static int mp4_has_permission(int ssid, int osid, int mask)
{
	/*
	 * read-only for non-target task accesing object with security label that is not NO_ACCESS
	 * ...
	 */

	switch (osid) {
		case MP4_NO_ACCESS:
			if (ssid == MP4_TARGET_SID) goto DENY;
			else goto GRANT;

		case MP4_READ_OBJ:
		// check all ops except read
		// true for both target and non-target
			if (mask&MAY_EXEC || mask&MAY_WRITE || mask&MAY_APPEND)
					goto DENY;
			else
					goto GRANT;

		case MP4_READ_WRITE:
			if(ssid == MP4_TARGET_SID) { // // target can read, write and append
				if (mask&MAY_EXEC)
						goto DENY;
				else
						goto GRANT;
			}
			else { // non-target can only read
				if (mask&MAY_EXEC || mask&MAY_WRITE || mask&MAY_APPEND)
						goto DENY;
				else
						goto GRANT;
			}

		case MP4_WRITE_OBJ:
			if(ssid == MP4_TARGET_SID) { // target can write and append
				if (mask&MAY_READ || mask&MAY_EXEC)
					goto DENY;
				else
					goto GRANT;
			}
			else { // non-target can only read
				if (mask&MAY_EXEC || mask&MAY_WRITE || mask&MAY_APPEND)
					goto DENY;
				else
					goto GRANT;
			}

		case MP4_EXEC_OBJ: // read and execute by ALL (both targets and non-targets)
			if (mask & WRITE || mask & MAY_APPEND) goto DENY;
			else goto GRANT;

		case MP4_READ_DIR:
			if (mask & MAY_WRITE) goto DENY; // targets can not write
			else goto GRANT; // full access by non-targets

		case MP4_RW_DIR: // full access by all
			goto GRANT;

	}

GRANT:
	return 0;
DENY:
	// pr_info("Deny! ssid %d, osid %d, mask %d", ssid, osid, mask);
	return -EACCES;
	// return 0;

}

/**
 * mp4_inode_permission - Check permission for an inode being opened
 *
 * @inode: the inode in question
 * @mask: the access requested
 *
 * This is the important access check hook
 *
 * returns 0 if access is granted, -EACCESS otherwise
 *
 */
static int mp4_inode_permission(struct inode *inode, int mask)
{
	if (!inode)
		goto GACCESS;
	int ssid;
 	int osid;
 	int permission;

	// 0. obtain path of the inode and skip if needed
	struct dentry *den = d_find_alias(inode);
	if (!den) {
		goto GACCESS;
	}
	char path_buf[PATH_BUF_SIZE];
	dentry_path_raw(den, path_buf, PATH_BUF_SIZE);
	int skip = mp4_should_skip_path(path_buf);
	if (skip) {
		dput(den);
		goto GACCESS;
	}

	// 1. get ssid
	struct cred *cred = current_cred(); //cred of current task
	if (!cred) { // checking if security is null.(non-target task could have null as secuity)
		dput(den);
		goto GACCESS;
	}
	if (!cred->security) {
		ssid = MP4_NO_ACCESS;
	}
	else {
		struct mp4_security *blob = cred->security;
		ssid = blob->mp4_flags;
	}

	// 3. get osid
	osid = get_inode_sid(inode);
	// pr_info("ssid:%d, osid:%d", ssid, osid);

	// 4. check for permission
	permission = mp4_has_permission(ssid, osid, mask);
	if (permission != 0) {
			pr_info("DENY! ssid%d, osid%d, mask%d", ssid, osid, mask);
	}

	dput(den);
	return permission;
GACCESS:
	return 0;
}


/*
 * This is the list of hooks that we will using for our security module.
 */
static struct security_hook_list mp4_hooks[] = {
	/*
	 * inode function to assign a label and to check permission
	 */
	LSM_HOOK_INIT(inode_init_security, mp4_inode_init_security),
	LSM_HOOK_INIT(inode_permission, mp4_inode_permission),

	/*
	 * setting the credentials subjective security label when laucnhing a
	 * binary
	 */
	LSM_HOOK_INIT(bprm_set_creds, mp4_bprm_set_creds),

	/* credentials handling and preparation */
	LSM_HOOK_INIT(cred_alloc_blank, mp4_cred_alloc_blank),
	LSM_HOOK_INIT(cred_free, mp4_cred_free),
	LSM_HOOK_INIT(cred_prepare, mp4_cred_prepare)
};

static __init int mp4_init(void)
{
	/*
	 * check if mp4 lsm is enabled with boot parameters
	 */
	if (!security_module_enable("mp4")){
		pr_info("mp4 LSM not enabled..");
		return 0;
	}


	pr_info("mp4 LSM initializing..");

	/*
	 * Register the mp4 hooks with lsm
	 */
	security_add_hooks(mp4_hooks, ARRAY_SIZE(mp4_hooks));

	return 0;
}

/*
 * early registration with the kernel
 */
security_initcall(mp4_init);
