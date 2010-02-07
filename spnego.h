#ifndef  _SPNEGO_H
#define  _SPNEGO_H

/* not really SPNEGO but GSSAPI (RFC 1964) */
#define TOK_ID_KRB_AP_REQ	(unsigned char *)"\x01\x00"
#define TOK_ID_KRB_AP_REP	(unsigned char *)"\x02\x00"
#define TOK_ID_KRB_ERROR	(unsigned char *)"\x03\x00"
#define TOK_ID_GSS_GETMIC	(unsigned char *)"\x01\x01"
#define TOK_ID_GSS_WRAP		(unsigned char *)"\x02\x01"

#endif /* _SPNEGO_H */
