#include "header.h"
#include "io_util.h"
#include <asm-generic/errno-base.h>
#include <endian.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <string.h>

const uint8_t MAGIC[LF_HDR_MAGIC_LEN] = { 0xde, 0xad, 0xbe, 0xef };

int LF_header_new(LF_header *header, uint32_t t, uint32_t m, uint32_t p)
{
	memcpy(header->magic, MAGIC, LF_HDR_MAGIC_LEN);
	header->time_cost = t;
	header->memory_cost = m;
	header->parallelism = p;
	if (1 != RAND_bytes(header->bnonce, LF_HDR_BNONCE_LEN)) {
		return -4094;
	}
	if (1 != RAND_bytes(header->salt, LF_HDR_SALT_LEN)) {
		return -4094;
	}
	return 0;
}

int LF_header_read(LF_header *header, int fd)
{
	int ret;
	ret = LF_io_read_exact(fd, header->magic, LF_HDR_MAGIC_LEN);
	if (0 != ret) {
		return ret;
	}
	if (0 != memcmp(header->magic, MAGIC, LF_HDR_MAGIC_LEN)) {
		return -EINVAL;
	}
	ret = LF_io_read_u32(fd, &header->time_cost, LITTLE_ENDIAN);
	if (0 != ret) {
		return ret;
	}
	ret = LF_io_read_u32(fd, &header->memory_cost, LITTLE_ENDIAN);
	if (0 != ret) {
		return ret;
	}
	ret = LF_io_read_u32(fd, &header->parallelism, LITTLE_ENDIAN);
	if (0 != ret) {
		return ret;
	}
	ret = LF_io_read_exact(fd, header->salt, LF_HDR_SALT_LEN);
	if (0 != ret) {
		return ret;
	}
	ret = LF_io_read_exact(fd, header->bnonce, LF_HDR_BNONCE_LEN);
	if (0 != ret) {
		return ret;
	}
	return 0;
}

int LF_header_write(const LF_header *header, int fd)
{
	int ret;
	ret = LF_io_write_exact(fd, header->magic, LF_HDR_MAGIC_LEN);
	if (0 != ret) {
		return ret;
	}
	ret = LF_io_write_u32(fd, &header->time_cost, LITTLE_ENDIAN);
	if (0 != ret) {
		return ret;
	}
	ret = LF_io_write_u32(fd, &header->memory_cost, LITTLE_ENDIAN);
	if (0 != ret) {
		return ret;
	}
	ret = LF_io_write_u32(fd, &header->parallelism, LITTLE_ENDIAN);
	if (0 != ret) {
		return ret;
	}
	ret = LF_io_write_exact(fd, header->salt, LF_HDR_SALT_LEN);
	if (0 != ret) {
		return ret;
	}
	ret = LF_io_write_exact(fd, header->bnonce, LF_HDR_BNONCE_LEN);
	if (0 != ret) {
		return ret;
	}
	return 0;
}

void LF_header_cleanse(LF_header *header)
{
	OPENSSL_cleanse(header, sizeof *header);
}
