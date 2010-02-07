
#include <talloc.h>
#include <stdint.h>

#include "replace.h"
#include "data_blob.h"
#include "asn1.h"
#include "spnego.h"

/*
  generate a krb5 GSS-API wrapper packet given a ticket
*/
DATA_BLOB spnego_gen_krb5_wrap(const DATA_BLOB ticket, const uint8_t tok_id[2])
{
	ASN1_DATA *data;
	DATA_BLOB ret;

	data = asn1_init(talloc_init("gssapi"));
	if (data == NULL) {
		return data_blob_null;
	}

	asn1_push_tag(data, ASN1_APPLICATION(0));
	asn1_write_OID(data, OID_KERBEROS5);

	asn1_write(data, tok_id, 2);
	asn1_write(data, ticket.data, ticket.length);
	asn1_pop_tag(data);

#if 0
	if (data->has_error) {
		DEBUG(1,("Failed to build krb5 wrapper at offset %d\n", (int)data->ofs));
	}
#endif

	ret = data_blob(data->data, data->length);
	asn1_free(data);

	return ret;
}

/*
  Generate a negTokenInit as used by the client side ... It has a mechType
  (OID), and a mechToken (a security blob) ... 

  Really, we need to break out the NTLMSSP stuff as well, because it could be
  raw in the packets!
*/
DATA_BLOB gen_negTokenInit(const char *OID, DATA_BLOB blob)
{
	ASN1_DATA *data;
	DATA_BLOB ret;

	data = asn1_init(talloc_init("spnego"));
	if (data == NULL) {
		return data_blob_null;
	}

	asn1_push_tag(data, ASN1_APPLICATION(0));
	asn1_write_OID(data,OID_SPNEGO);
	asn1_push_tag(data, ASN1_CONTEXT(0));
	asn1_push_tag(data, ASN1_SEQUENCE(0));

	asn1_push_tag(data, ASN1_CONTEXT(0));
	asn1_push_tag(data, ASN1_SEQUENCE(0));
	asn1_write_OID(data, OID);
	asn1_pop_tag(data);
	asn1_pop_tag(data);

	asn1_push_tag(data, ASN1_CONTEXT(2));
	asn1_write_OctetString(data,blob.data,blob.length);
	asn1_pop_tag(data);

	asn1_pop_tag(data);
	asn1_pop_tag(data);

	asn1_pop_tag(data);

#if 0
	if (data->has_error) {
		DEBUG(1,("Failed to build negTokenInit at offset %d\n", (int)data->ofs));
	}
#endif

	ret = data_blob(data->data, data->length);
	asn1_free(data);

	return ret;
}

