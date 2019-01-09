// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2018 Intel Corporation. All rights reserved. */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <keyutils.h>
#include <syslog.h>

#include <ndctl.h>
#include <ndctl/libndctl.h>
#include "private.h"

#define PATH_SIZE	512
#define DESC_SIZE	128
#define KEY_CMD_SIZE	128

static int get_key_path(struct ndctl_dimm *dimm, char *path,
		const char *keypath, enum ndctl_key_type key_type)
{
	struct ndctl_ctx *ctx = ndctl_dimm_get_ctx(dimm);
	char hostname[HOST_NAME_MAX];
	int rc;

	rc = gethostname(hostname, HOST_NAME_MAX);
	if (rc < 0) {
		err(ctx, "gethostname: %s\n", strerror(errno));
		return -errno;
	}

	switch (key_type) {
	case ND_USER_OLD_KEY:
		rc = sprintf(path, "%s/nvdimm-old_%s_%s.blob",
				keypath, ndctl_dimm_get_unique_id(dimm),
				hostname);
		break;
	case ND_USER_KEY:
		rc = sprintf(path, "%s/nvdimm_%s_%s.blob",
				keypath, ndctl_dimm_get_unique_id(dimm),
				hostname);
		break;
	case ND_MASTER_OLD_KEY:
		rc = sprintf(path, "%s/nvdimm-master-old_%s_%s.blob",
				keypath, ndctl_dimm_get_unique_id(dimm),
				hostname);
		break;
	case ND_MASTER_KEY:
		rc = sprintf(path, "%s/nvdimm-master_%s_%s.blob",
				keypath, ndctl_dimm_get_unique_id(dimm),
				hostname);
		break;
	default:
		return -EINVAL;
	}

	if (rc < 0) {
		err(ctx, "error setting path: %s\n", strerror(errno));
		return -errno;
	}

	return 0;
}

static int get_key_desc(struct ndctl_dimm *dimm, char *desc,
		enum ndctl_key_type key_type)
{
	struct ndctl_ctx *ctx = ndctl_dimm_get_ctx(dimm);
	int rc;

	switch (key_type) {
	case ND_USER_OLD_KEY:
		rc = sprintf(desc, "nvdimm-old:%s",
				ndctl_dimm_get_unique_id(dimm));
		break;
	case ND_USER_KEY:
		rc = sprintf(desc, "nvdimm:%s",
				ndctl_dimm_get_unique_id(dimm));
		break;
	case ND_MASTER_OLD_KEY:
		rc = sprintf(desc, "nvdimm-master-old:%s",
				ndctl_dimm_get_unique_id(dimm));
		break;
	case ND_MASTER_KEY:
		rc = sprintf(desc, "nvdimm-master:%s",
				ndctl_dimm_get_unique_id(dimm));
		break;
	default:
		return -EINVAL;
	}

	if (rc < 0) {
		err(ctx, "error setting key description: %s\n",
				strerror(errno));
		return -errno;
	}

	return 0;
}

static char *load_key_blob(struct ndctl_ctx *ctx, const char *path, int *size)
{
	struct stat st;
	FILE *bfile = NULL;
	ssize_t read;
	int rc;
	char *blob, *pl;
	char prefix[] = "load ";

	rc = stat(path, &st);
	if (rc < 0)
		return NULL;

	if ((st.st_mode & S_IFMT) != S_IFREG) {
		err(ctx, "%s not a regular file\n", path);
		return NULL;
	}

	if (st.st_size == 0 || st.st_size > 4096) {
		err(ctx, "Invalid blob file size\n");
		return NULL;
	}

	*size = st.st_size + sizeof(prefix) - 1;
	blob = malloc(*size);
	if (!blob) {
		err(ctx, "Unable to allocate memory for blob\n");
		return NULL;
	}

	bfile = fopen(path, "r");
	if (!bfile) {
		err(ctx, "Unable to open %s: %s\n", path, strerror(errno));
		free(blob);
		return NULL;
	}

	memcpy(blob, prefix, sizeof(prefix) - 1);
	pl = blob + sizeof(prefix) - 1;
	read = fread(pl, st.st_size, 1, bfile);
	if (read < 0) {
		err(ctx, "Failed to read from blob file: %s\n",
				strerror(errno));
		free(blob);
		fclose(bfile);
		return NULL;
	}

	fclose(bfile);
	return blob;
}

static key_serial_t dimm_check_key(struct ndctl_dimm *dimm,
		enum ndctl_key_type key_type)
{
	char desc[DESC_SIZE];
	int rc;

	rc = get_key_desc(dimm, desc, key_type);
	if (rc < 0)
		return rc;

	return keyctl_search(KEY_SPEC_USER_KEYRING, "encrypted", desc, 0);
}

static key_serial_t dimm_create_key(struct ndctl_dimm *dimm,
		const char *master_key, const char *keypath,
		enum ndctl_key_type key_type)
{
	struct ndctl_ctx *ctx = ndctl_dimm_get_ctx(dimm);
	char desc[DESC_SIZE];
	char path[PATH_SIZE];
	char cmd[KEY_CMD_SIZE];
	key_serial_t key;
	void *buffer;
	int rc;
	ssize_t size;
	FILE *fp;
	ssize_t wrote;
	struct stat st;

	if (ndctl_dimm_is_active(dimm)) {
		err(ctx, "regions active on %s, op failed\n",
				ndctl_dimm_get_devname(dimm));
		return -EBUSY;
	}

	rc = get_key_desc(dimm, desc, key_type);
	if (rc < 0)
		return rc;

	/* make sure it's not already in the key ring */
	key = keyctl_search(KEY_SPEC_USER_KEYRING, "encrypted", desc, 0);
	if (key > 0) {
		err(ctx, "Error: key already present in user keyring\n");
		return -EEXIST;
	}

	rc = get_key_path(dimm, path, keypath, key_type);
	if (rc < 0)
		return rc;

	rc = stat(path, &st);
	if (rc == 0) {
		err(ctx, "%s already exists!\n", path);
		return -EEXIST;
	}

	rc = sprintf(cmd, "new enc32 %s 32", master_key);
	if (rc < 0) {
		err(ctx, "sprintf: %s\n", strerror(errno));
		return -errno;
	}

	key = add_key("encrypted", desc, cmd, strlen(cmd),
			KEY_SPEC_USER_KEYRING);
	if (key < 0) {
		err(ctx, "add_key failed: %s\n", strerror(errno));
		return -errno;
	}

	size = keyctl_read_alloc(key, &buffer);
	if (size < 0) {
		err(ctx, "keyctl_read_alloc failed: %ld\n", size);
		keyctl_unlink(key, KEY_SPEC_USER_KEYRING);
		return rc;
	}

	fp = fopen(path, "w");
	if (!fp) {
		rc = -errno;
		err(ctx, "Unable to open file %s: %s\n",
				path, strerror(errno));
		free(buffer);
		return rc;
	}

	 wrote = fwrite(buffer, 1, size, fp);
	 if (wrote != size) {
		 if (wrote == -1)
			 rc = -errno;
		 else
			 rc = -EIO;
		 err(ctx, "Failed to write to %s: %s\n",
				 path, strerror(-rc));
		 free(buffer);
		 return rc;
	 }

	 fclose(fp);
	 free(buffer);
	 return key;
}

static key_serial_t dimm_load_key(struct ndctl_dimm *dimm,
		const char *keypath, enum ndctl_key_type key_type)
{
	struct ndctl_ctx *ctx = ndctl_dimm_get_ctx(dimm);
	key_serial_t key;
	char desc[DESC_SIZE];
	char path[PATH_SIZE];
	int rc;
	char *blob;
	int size;

	if (ndctl_dimm_is_active(dimm)) {
		err(ctx, "regions active on %s, op failed\n",
				ndctl_dimm_get_devname(dimm));
		return -EBUSY;
	}

	rc = get_key_desc(dimm, desc, key_type);
	if (rc < 0)
		return rc;

	rc = get_key_path(dimm, path, keypath, key_type);
	if (rc < 0)
		return rc;

	blob = load_key_blob(ctx, path, &size);
	if (!blob)
		return -ENOMEM;

	key = add_key("encrypted", desc, blob, size, KEY_SPEC_USER_KEYRING);
	free(blob);
	if (key < 0) {
		err(ctx, "add_key failed: %s\n", strerror(errno));
		return -errno;
	}

	return key;
}

/*
 * The function will check to see if the existing key is there and remove
 * from user key ring if it is. Rename the existing key blob to old key
 * blob, and then attempt to inject the key as old key into the user key
 * ring.
 */
static key_serial_t move_key_to_old(struct ndctl_dimm *dimm,
		const char *keypath, enum ndctl_key_type key_type)
{
	struct ndctl_ctx *ctx = ndctl_dimm_get_ctx(dimm);
	int rc;
	key_serial_t key;
	char old_path[PATH_SIZE];
	char new_path[PATH_SIZE];
	enum ndctl_key_type okey_type;

	if (ndctl_dimm_is_active(dimm)) {
		err(ctx, "regions active on %s, op failed\n",
				ndctl_dimm_get_devname(dimm));
		return -EBUSY;
	}

	key = dimm_check_key(dimm, key_type);
	if (key > 0)
		keyctl_unlink(key, KEY_SPEC_USER_KEYRING);

	if (key_type == ND_USER_KEY)
		okey_type = ND_USER_OLD_KEY;
	else if (key_type == ND_MASTER_KEY)
		okey_type = ND_MASTER_OLD_KEY;
	else
		return -EINVAL;

	rc = get_key_path(dimm, old_path, keypath, key_type);
	if (rc < 0)
		return rc;

	rc = get_key_path(dimm, new_path, keypath, okey_type);
	if (rc < 0)
		return rc;

	rc = rename(old_path, new_path);
	if (rc < 0) {
		err(ctx, "rename failed from %s to %s: %s\n",
				old_path, new_path, strerror(errno));
		return -errno;
	}

	return dimm_load_key(dimm, keypath, okey_type);
}

static int dimm_remove_key(struct ndctl_dimm *dimm, const char *keypath,
		enum ndctl_key_type key_type)
{
	struct ndctl_ctx *ctx = ndctl_dimm_get_ctx(dimm);
	key_serial_t key;
	char path[PATH_SIZE];
	int rc;

	key = dimm_check_key(dimm, key_type);
	if (key > 0)
		keyctl_unlink(key, KEY_SPEC_USER_KEYRING);

	rc = get_key_path(dimm, path, keypath, key_type);
	if (rc < 0)
		return rc;

	rc = unlink(path);
	if (rc < 0) {
		err(ctx, "delete file %s failed: %s\n",
				path, strerror(errno));
		return -errno;
	}

	return 0;
}

NDCTL_EXPORT int ndctl_dimm_enable_key(struct ndctl_dimm *dimm,
		const char *master_key, const char *keypath,
		enum ndctl_key_type key_type)
{
	key_serial_t key;
	int rc;

	key = dimm_create_key(dimm, master_key, keypath, key_type);
	if (key < 0)
		return key;

	if (key_type == ND_MASTER_KEY)
		rc = ndctl_dimm_update_master_passphrase(dimm, 0, key);
	else
		rc = ndctl_dimm_update_passphrase(dimm, 0, key);
	if (rc < 0) {
		dimm_remove_key(dimm, keypath, key_type);
		return rc;
	}

	return 0;
}

NDCTL_EXPORT int ndctl_dimm_update_key(struct ndctl_dimm *dimm,
		const char *master_key, const char *keypath,
		enum ndctl_key_type key_type)
{
	int rc;
	key_serial_t old_key, new_key;
	enum ndctl_key_type okey_type;

	if (key_type == ND_USER_KEY)
		okey_type = ND_USER_OLD_KEY;
	else if (key_type == ND_MASTER_KEY)
		okey_type = ND_MASTER_OLD_KEY;
	else
		return -EINVAL;

	/*
	 * 1. check if current key is loaded and remove
	 * 2. move current key blob to old key blob
	 * 3. load old key blob
	 * 4. trigger change key with old and new key
	 * 5. remove old key
	 * 6. remove old key blob
	 */
	old_key = move_key_to_old(dimm, keypath, key_type);
	if (old_key < 0)
		return old_key;

	new_key = dimm_create_key(dimm, master_key, keypath, key_type);
	/* need to create new key here */
	if (new_key < 0) {
		new_key = dimm_load_key(dimm, keypath, key_type);
		if (new_key < 0)
			return new_key;
	}

	if (key_type == ND_MASTER_KEY)
		rc = ndctl_dimm_update_master_passphrase(dimm,
				old_key, new_key);
	else
		rc = ndctl_dimm_update_passphrase(dimm, old_key, new_key);
	if (rc < 0)
		return rc;

	rc = dimm_remove_key(dimm, keypath, okey_type);
	if (rc < 0)
		return rc;

	return 0;
}

static int check_key_run_and_discard(struct ndctl_dimm *dimm,
		int (*run_op)(struct ndctl_dimm *, long), const char *name,
		const char *keypath)
{
	struct ndctl_ctx *ctx = ndctl_dimm_get_ctx(dimm);
	key_serial_t key;
	int rc;

	key = dimm_check_key(dimm, ND_USER_KEY);
	if (key < 0) {
		key = dimm_load_key(dimm, keypath, ND_USER_KEY);
		if (key < 0 && run_op != ndctl_dimm_overwrite) {
			err(ctx, "Unable to load key\n");
			return -ENOKEY;
		} else
			key = 0;
	}

	rc = run_op(dimm, key);
	if (rc < 0) {
		err(ctx, "Failed %s for %s\n", name,
				ndctl_dimm_get_devname(dimm));
		return rc;
	}

	if (key) {
		rc = dimm_remove_key(dimm, keypath, ND_USER_KEY);
		if (rc < 0)
			err(ctx, "Unable to cleanup key.\n");
	}
	return 0;
}

NDCTL_EXPORT int ndctl_dimm_disable_key(struct ndctl_dimm *dimm,
		const char *keypath)
{
	return check_key_run_and_discard(dimm, ndctl_dimm_disable_passphrase,
			"disable passphrase", keypath);
}

NDCTL_EXPORT int ndctl_dimm_secure_erase_key(struct ndctl_dimm *dimm,
		const char *keypath)
{
	return check_key_run_and_discard(dimm, ndctl_dimm_secure_erase,
			"crypto erase", keypath);
}

NDCTL_EXPORT int ndctl_dimm_overwrite_key(struct ndctl_dimm *dimm,
		const char *keypath)
{
	return check_key_run_and_discard(dimm, ndctl_dimm_overwrite,
			"overwrite", keypath);
}
