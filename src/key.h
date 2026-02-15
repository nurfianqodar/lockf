#ifndef LF_KEY_H_
#define LF_KEY_H_

#include "header.h"
#include <stddef.h>
#include <stdint.h>

#define LF_KEY_LEN 32

typedef uint8_t LF_key[LF_KEY_LEN];

int LF_key_new(LF_key *key, const LF_header *header, const uint8_t *pwd,
	       size_t pwd_len);

void LF_key_cleanse(LF_key *key);

#endif // INCLUDEsrckeykey.h_
