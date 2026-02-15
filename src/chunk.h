#ifndef LF_CHUNK_H_
#define LF_CHUNK_H_

#include "header.h"
#include "key.h"
#include <stdint.h>

#define LF_CHK_BUF_CAP (1024 * 256)
#define LF_CHK_BUF_LEN_MAX LF_CHK_BUF_CAP
#define LF_CHK_ID_LEN 4
#define LF_CHK_TAG_LEN 16

typedef enum {
	LF_CMODE_UNDEF,
	LF_CMODE_PLAIN,
	LF_CMODE_CIPHER,
} LF_chunk_mode;

typedef struct {
	LF_chunk_mode mode;
	uint8_t id[LF_CHK_ID_LEN];
	uint8_t buf[LF_CHK_BUF_CAP];
	uint32_t buf_len;
	uint8_t tag[LF_CHK_TAG_LEN];
} LF_chunk;

int LF_chunk_encrypt(LF_chunk *chunk, const LF_header *header,
		     const LF_key *key);

int LF_chunk_decrypt(LF_chunk *chunk, const LF_header *header,
		     const LF_key *key);

int LF_chunk_read(LF_chunk *chunk, int fd, LF_chunk_mode mode);

int LF_chunk_write(const LF_chunk *chunk, int fd);

void LF_chunk_cleanse(LF_chunk *chunk);

#endif // !LF_CHUNK_H_
