#ifndef LF_HEADER_H_
#define LF_HEADER_H_

#include <stdint.h>

#define LF_HDR_MAGIC_LEN 4
#define LF_HDR_SALT_LEN 16
#define LF_HDR_BNONCE_LEN 8

typedef struct {
	uint8_t magic[4];
	uint32_t time_cost;
	uint32_t memory_cost;
	uint32_t parallelism;
	uint8_t salt[LF_HDR_SALT_LEN];
	uint8_t bnonce[LF_HDR_BNONCE_LEN];
} LF_header;

int LF_header_new(LF_header *header, uint32_t t, uint32_t m, uint32_t p);
int LF_header_read(LF_header *header, int fd);
int LF_header_write(const LF_header *header, int fd);
void LF_header_cleanse(LF_header *header);

#endif // !LF_HEADER_H_
