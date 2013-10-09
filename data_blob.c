/* 
   Unix SMB/CIFS implementation.
   Easy management of byte-length data
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Andrew Bartlett 2001
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <string.h>

#include "replace.h"
#include "data_blob.h"

const DATA_BLOB data_blob_null = { NULL, 0 };

/**
 * @file
 * @brief Manipulation of arbitrary data blobs
 **/

/**
 construct a data blob, must be freed with data_blob_free()
 you can pass NULL for p and get a blank data blob
**/
_PUBLIC_ DATA_BLOB data_blob_named(const void *p, size_t length, const char *name)
{
	DATA_BLOB ret;

	if (p == NULL && length == 0) {
		ZERO_STRUCT(ret);
		return ret;
	}

	if (p) {
		ret.data = (uint8_t *)talloc_memdup(NULL, p, length);
	} else {
		ret.data = talloc_array(NULL, uint8_t, length);
	}
	if (ret.data == NULL) {
		ret.length = 0;
		return ret;
	}
	talloc_set_name_const(ret.data, name);
	ret.length = length;
	return ret;
}

/**
 construct a data blob, using supplied TALLOC_CTX
**/
_PUBLIC_ DATA_BLOB data_blob_talloc_named(TALLOC_CTX *mem_ctx, const void *p, size_t length, const char *name)
{
	DATA_BLOB ret = data_blob_named(p, length, name);

	if (ret.data) {
		talloc_steal(mem_ctx, ret.data);
	}
	return ret;
}

/**
free a data blob
**/
_PUBLIC_ void data_blob_free(DATA_BLOB *d)
{
	if (d) {
		talloc_free(d->data);
		d->data = NULL;
		d->length = 0;
	}
}

