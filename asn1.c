/* 
   Unix SMB/CIFS implementation.
   simple ASN1 routines
   Copyright (C) Andrew Tridgell 2001
   
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
#include <talloc.h>
#include <stdint.h>

#include "replace.h"
#include "data_blob.h"
#include "asn1.h"

/* allocate an asn1 structure */
struct asn1_data *asn1_init(TALLOC_CTX *mem_ctx)
{
	struct asn1_data *ret = talloc_zero(mem_ctx, struct asn1_data);
	return ret;
}

/* free an asn1 structure */
void asn1_free(struct asn1_data *data)
{
	talloc_free(data);
}

/* write to the ASN1 buffer, advancing the buffer pointer */
bool asn1_write(struct asn1_data *data, const void *p, int len)
{
	if (data->has_error)
		return false;
	if (data->length < (size_t)data->ofs + len) {
		uint8_t *newp;
		newp = talloc_realloc(data, data->data, uint8_t, data->ofs+len);
		if (!newp) {
			data->has_error = true;
			return false;
		}
		data->data = newp;
		data->length = data->ofs+len;
	}
	memcpy(data->data + data->ofs, p, len);
	data->ofs += len;
	return true;
}

/* useful fn for writing a uint8_t */
bool asn1_write_uint8(struct asn1_data *data, uint8_t v)
{
	return asn1_write(data, &v, 1);
}

/* push a tag onto the asn1 data buffer. Used for nested structures */
bool asn1_push_tag(struct asn1_data *data, uint8_t tag)
{
	struct nesting *nesting;

	asn1_write_uint8(data, tag);
	nesting = talloc(data, struct nesting);
	if (!nesting) {
		data->has_error = true;
		return false;
	}

	nesting->start = data->ofs;
	nesting->next = data->nesting;
	data->nesting = nesting;
	return asn1_write_uint8(data, 0xff);
}

/* pop a tag */
bool asn1_pop_tag(struct asn1_data *data)
{
	struct nesting *nesting;
	size_t len;

	nesting = data->nesting;

	if (!nesting) {
		data->has_error = true;
		return false;
	}
	len = data->ofs - (nesting->start+1);
	/* yes, this is ugly. We don't know in advance how many bytes the length
	   of a tag will take, so we assumed 1 byte. If we were wrong then we 
	   need to correct our mistake */
	if (len > 0xFFFFFF) {
		data->data[nesting->start] = 0x84;
		if (!asn1_write_uint8(data, 0)) return false;
		if (!asn1_write_uint8(data, 0)) return false;
		if (!asn1_write_uint8(data, 0)) return false;
		if (!asn1_write_uint8(data, 0)) return false;
		memmove(data->data+nesting->start+5, data->data+nesting->start+1, len);
		data->data[nesting->start+1] = (len>>24) & 0xFF;
		data->data[nesting->start+2] = (len>>16) & 0xFF;
		data->data[nesting->start+3] = (len>>8) & 0xFF;
		data->data[nesting->start+4] = len&0xff;
	} else if (len > 0xFFFF) {
		data->data[nesting->start] = 0x83;
		if (!asn1_write_uint8(data, 0)) return false;
		if (!asn1_write_uint8(data, 0)) return false;
		if (!asn1_write_uint8(data, 0)) return false;
		memmove(data->data+nesting->start+4, data->data+nesting->start+1, len);
		data->data[nesting->start+1] = (len>>16) & 0xFF;
		data->data[nesting->start+2] = (len>>8) & 0xFF;
		data->data[nesting->start+3] = len&0xff;
	} else if (len > 255) {
		data->data[nesting->start] = 0x82;
		if (!asn1_write_uint8(data, 0)) return false;
		if (!asn1_write_uint8(data, 0)) return false;
		memmove(data->data+nesting->start+3, data->data+nesting->start+1, len);
		data->data[nesting->start+1] = len>>8;
		data->data[nesting->start+2] = len&0xff;
	} else if (len > 127) {
		data->data[nesting->start] = 0x81;
		if (!asn1_write_uint8(data, 0)) return false;
		memmove(data->data+nesting->start+2, data->data+nesting->start+1, len);
		data->data[nesting->start+1] = len;
	} else {
		data->data[nesting->start] = len;
	}

	data->nesting = nesting->next;
	talloc_free(nesting);
	return true;
}

bool ber_write_OID_String(TALLOC_CTX *mem_ctx, DATA_BLOB *blob, const char *OID)
{
	unsigned int v, v2;
	const char *p = (const char *)OID;
	char *newp;
	int i;

	v = strtoul(p, &newp, 10);
	if (newp[0] != '.') return false;
	p = newp + 1;

	v2 = strtoul(p, &newp, 10);
	if (newp[0] != '.') return false;
	p = newp + 1;

	/*the ber representation can't use more space then the string one */
	*blob = data_blob_talloc(mem_ctx, NULL, strlen(OID));
	if (!blob->data) return false;

	blob->data[0] = 40*v + v2;

	i = 1;
	while (*p) {
		v = strtoul(p, &newp, 10);
		if (newp[0] == '.') {
			p = newp + 1;
		} else if (newp[0] == '\0') {
			p = newp;
		} else {
			data_blob_free(blob);
			return false;
		}
		if (v >= (1<<28)) blob->data[i++] = (0x80 | ((v>>28)&0x7f));
		if (v >= (1<<21)) blob->data[i++] = (0x80 | ((v>>21)&0x7f));
		if (v >= (1<<14)) blob->data[i++] = (0x80 | ((v>>14)&0x7f));
		if (v >= (1<<7)) blob->data[i++] = (0x80 | ((v>>7)&0x7f));
		blob->data[i++] = (v&0x7f);
	}

	blob->length = i;

	return true;
}

/* write an object ID to a ASN1 buffer */
bool asn1_write_OID(struct asn1_data *data, const char *OID)
{
	DATA_BLOB blob;

	if (!asn1_push_tag(data, ASN1_OID)) return false;

	if (!ber_write_OID_String(NULL, &blob, OID)) {
		data->has_error = true;
		return false;
	}

	if (!asn1_write(data, blob.data, blob.length)) {
		data_blob_free(&blob);
		data->has_error = true;
		return false;
	}
	data_blob_free(&blob);
	return asn1_pop_tag(data);
}

/* write an octet string */
bool asn1_write_OctetString(struct asn1_data *data, const void *p, size_t length)
{
	asn1_push_tag(data, ASN1_OCTET_STRING);
	asn1_write(data, p, length);
	asn1_pop_tag(data);
	return !data->has_error;
}

