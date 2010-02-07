#include <sys/types.h>
#include <string.h>

/* glibc doesn't have strlcpy, strlcat. Ensure we do. JRA. We
 * don't link to libreplace so need them here. */

/* like strncpy but does not 0 fill the buffer and always null
 *    terminates. bufsize is the size of the destination buffer */

#ifndef HAVE_STRLCPY
size_t strlcpy(char *d, const char *s, size_t bufsize)
{
	size_t len = strlen(s);
	size_t ret = len;
	if (bufsize <= 0) return 0;
	if (len >= bufsize) len = bufsize-1;
	memcpy(d, s, len);
	d[len] = 0;
	return ret;
}
#endif

/* like strncat but does not 0 fill the buffer and always null
 *    terminates. bufsize is the length of the buffer, which should
 *       be one more than the maximum resulting string length */

#ifndef HAVE_STRLCAT
size_t strlcat(char *d, const char *s, size_t bufsize)
{
	size_t len1 = strlen(d);
	size_t len2 = strlen(s);
	size_t ret = len1 + len2;

	if (len1+len2 >= bufsize) {
		if (bufsize < (len1+1)) {
			return ret;
		}
		len2 = bufsize - (len1+1);
	}
	if (len2 > 0) {
		memcpy(d+len1, s, len2);
		d[len1+len2] = 0;
	}
	return ret;
}
#endif

