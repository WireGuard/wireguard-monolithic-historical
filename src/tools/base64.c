/*
 * Copyright (c) 1996, 1998 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 * Portions Copyright (c) 1995 by International Business Machines, Inc.
 *
 * International Business Machines, Inc. (hereinafter called IBM) grants
 * permission under its copyrights to use, copy, modify, and distribute this
 * Software with or without fee, provided that the above copyright notice and
 * all paragraphs of this notice appear in all copies, and that the name of IBM
 * not be used in connection with the marketing of any product incorporating
 * the Software or modifications thereof, without specific, written prior
 * permission.
 *
 * To the extent it has a right to do so, IBM grants an immunity from suit
 * under its patents, if any, for the use, sale or manufacture of products to
 * the extent that such products are used for performing Domain Name System
 * dynamic updates in TCP/IP networks by means of the Software.  No immunity is
 * granted for any product per se or for any other function of any product.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", AND IBM DISCLAIMS ALL WARRANTIES,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE.  IN NO EVENT SHALL IBM BE LIABLE FOR ANY SPECIAL,
 * DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE, EVEN
 * IF IBM IS APPRISED OF THE POSSIBILITY OF SUCH DAMAGES.
 */

#include "base64.h"
#include <sys/types.h>
#include <assert.h>
#include <stdlib.h>
#include <ctype.h>

#if defined(NEED_B64_NTOP) || defined(NEED_B64_PTON)
static const char base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char pad64 = '=';
#endif

#ifdef NEED_B64_NTOP
int b64_ntop(unsigned char const *src, size_t srclength, char *target, size_t targsize)
{
	size_t datalength = 0;
	uint8_t input[3];
	uint8_t output[4];
	size_t i;

	while (2 < srclength) {
		input[0] = *src++;
		input[1] = *src++;
		input[2] = *src++;
		srclength -= 3;

		output[0] = input[0] >> 2;
		output[1] = ((input[0] & 0x03) << 4) + (input[1] >> 4);
		output[2] = ((input[1] & 0x0f) << 2) + (input[2] >> 6);
		output[3] = input[2] & 0x3f;
		assert(output[0] < 64);
		assert(output[1] < 64);
		assert(output[2] < 64);
		assert(output[3] < 64);

		if (datalength + 4 > targsize)
			return -1;
		target[datalength++] = base64[output[0]];
		target[datalength++] = base64[output[1]];
		target[datalength++] = base64[output[2]];
		target[datalength++] = base64[output[3]];
	}
	if (0 != srclength) {
		input[0] = input[1] = input[2] = '\0';
		for (i = 0; i < srclength; i++)
			input[i] = *src++;
		output[0] = input[0] >> 2;
		output[1] = ((input[0] & 0x03) << 4) + (input[1] >> 4);
		output[2] = ((input[1] & 0x0f) << 2) + (input[2] >> 6);
		assert(output[0] < 64);
		assert(output[1] < 64);
		assert(output[2] < 64);

		if (datalength + 4 > targsize)
			return -1;
		target[datalength++] = base64[output[0]];
		target[datalength++] = base64[output[1]];
		if (srclength == 1)
			target[datalength++] = pad64;
		else
			target[datalength++] = base64[output[2]];
		target[datalength++] = pad64;
	}
	if (datalength >= targsize)
		return (-1);
	target[datalength] = '\0';
	return datalength;
}
#endif

#ifdef NEED_B64_PTON
int b64_pton(char const *src, uint8_t *target, size_t targsize)
{
	static int b64rmap_initialized = 0;
	static uint8_t b64rmap[256];
	static const uint8_t b64rmap_special = 0xf0;
	static const uint8_t b64rmap_end = 0xfd;
	static const uint8_t b64rmap_space = 0xfe;
	static const uint8_t b64rmap_invalid = 0xff;
	int tarindex, state, ch;
	uint8_t ofs;

	if (!b64rmap_initialized) {
		int i;
		char ch;
		b64rmap[0] = b64rmap_end;
		for (i = 1; i < 256; ++i) {
			ch = (char)i;
			if (isspace(ch))
				b64rmap[i] = b64rmap_space;
			else if (ch == pad64)
				b64rmap[i] = b64rmap_end;
			else
				b64rmap[i] = b64rmap_invalid;
		}
		for (i = 0; base64[i] != '\0'; ++i)
			b64rmap[(uint8_t)base64[i]] = i;
		b64rmap_initialized = 1;
	}

	state = 0;
	tarindex = 0;

	for (;;) {
		ch = *src++;
		ofs = b64rmap[ch];

		if (ofs >= b64rmap_special) {
			if (ofs == b64rmap_space)
				continue;
			if (ofs == b64rmap_end)
				break;
			return -1;
		}

		switch (state) {
		case 0:
			if ((size_t)tarindex >= targsize)
				return -1;
			target[tarindex] = ofs << 2;
			state = 1;
			break;
		case 1:
			if ((size_t)tarindex + 1 >= targsize)
				return -1;
			target[tarindex]   |=  ofs >> 4;
			target[tarindex+1]  = (ofs & 0x0f) << 4 ;
			tarindex++;
			state = 2;
			break;
		case 2:
			if ((size_t)tarindex + 1 >= targsize)
				return -1;
			target[tarindex]   |=  ofs >> 2;
			target[tarindex+1]  = (ofs & 0x03) << 6;
			tarindex++;
			state = 3;
			break;
		case 3:
			if ((size_t)tarindex >= targsize)
				return -1;
			target[tarindex] |= ofs;
			tarindex++;
			state = 0;
			break;
		default:
			abort();
		}
	}

	if (ch == pad64) {
		ch = *src++;
		switch (state) {
		case 0:
		case 1:
			return -1;

		case 2:
			for (; ch; ch = *src++) {
				if (b64rmap[ch] != b64rmap_space)
					break;
			}
			if (ch != pad64)
				return -1;
			ch = *src++;
		case 3:
			for (; ch; ch = *src++) {
				if (b64rmap[ch] != b64rmap_space)
					return -1;
			}
			if (target[tarindex] != 0)
				return -1;
		}
	} else {
		if (state != 0)
			return -1;
	}

	return tarindex;
}
#endif
