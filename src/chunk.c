#include "chunk.h"
#include "err.h"
#include "header.h"
#include "io_util.h"
#include "key.h"
#include <asm-generic/errno-base.h>
#include <assert.h>
#include <endian.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define NONCE_LEN (LF_HDR_BNONCE_LEN + LF_CHK_ID_LEN)

static void _derive_nonce(const LF_header *header, const LF_chunk *chunk,
			  uint8_t out[NONCE_LEN])
{
	memcpy(out, header->bnonce, LF_HDR_BNONCE_LEN);
	memcpy(out + LF_HDR_BNONCE_LEN, chunk->id, LF_CHK_ID_LEN);
}

int LF_chunk_encrypt(LF_chunk *chunk, const LF_header *header,
		     const LF_key *key)
{
	if (chunk->mode != LF_CMODE_PLAIN) {
		return LF_E_INVALID;
	}
	if (1 != RAND_bytes(chunk->id, LF_CHK_ID_LEN)) {
		return LF_E_UNKNOWN;
	}
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		return LF_E_UNKNOWN;
	}
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
		EVP_CIPHER_CTX_free(ctx);
		return LF_E_UNKNOWN;
	}
	if (1 !=
	    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL)) {
		EVP_CIPHER_CTX_free(ctx);
		return LF_E_UNKNOWN;
	}
	uint8_t nonce[NONCE_LEN];
	_derive_nonce(header, chunk, nonce);
	if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, *key, nonce)) {
		EVP_CIPHER_CTX_free(ctx);
		return LF_E_UNKNOWN;
	}
	int cipher_len;
	if (1 != EVP_EncryptUpdate(ctx, chunk->buf, &cipher_len, chunk->buf,
				   (int)chunk->buf_len)) {
		EVP_CIPHER_CTX_free(ctx);
		return LF_E_UNKNOWN;
	}
	int final_len;
	if (1 != EVP_EncryptFinal_ex(ctx, NULL, &final_len)) {
		EVP_CIPHER_CTX_free(ctx);
		return LF_E_UNKNOWN;
	}
	cipher_len += final_len;
	if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, LF_CHK_TAG_LEN,
				     chunk->tag)) {
		EVP_CIPHER_CTX_free(ctx);
		return LF_E_UNKNOWN;
	}
	chunk->mode = LF_CMODE_CIPHER;
	chunk->buf_len = (uint32_t)cipher_len;

	EVP_CIPHER_CTX_free(ctx);
	return LF_E_OK;
}

int LF_chunk_decrypt(LF_chunk *chunk, const LF_header *header,
		     const LF_key *key)
{
	if (LF_CMODE_CIPHER != chunk->mode) {
		return LF_E_INVALID;
	}
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		return LF_E_UNKNOWN;
	}
	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
		EVP_CIPHER_CTX_free(ctx);
		return LF_E_UNKNOWN;
	}
	if (1 !=
	    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL)) {
		EVP_CIPHER_CTX_free(ctx);
		return LF_E_UNKNOWN;
	}
	uint8_t nonce[NONCE_LEN];
	_derive_nonce(header, chunk, nonce);
	if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, *key, nonce)) {
		EVP_CIPHER_CTX_free(ctx);
		return LF_E_UNKNOWN;
	}
	int plain_len;
	if (1 != EVP_DecryptUpdate(ctx, chunk->buf, &plain_len, chunk->buf,
				   (int)chunk->buf_len)) {
		EVP_CIPHER_CTX_free(ctx);
		return LF_E_UNKNOWN;
	}
	if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, LF_CHK_TAG_LEN,
				     chunk->tag)) {
		EVP_CIPHER_CTX_free(ctx);
		return LF_E_UNKNOWN;
	}
	int final_len;
	if (1 != EVP_DecryptFinal_ex(ctx, NULL, &final_len)) {
		EVP_CIPHER_CTX_free(ctx);
		return LF_E_UNKNOWN;
	}
	plain_len += final_len;
	chunk->mode = LF_CMODE_PLAIN;
	chunk->buf_len = (uint32_t)plain_len;
	OPENSSL_cleanse(chunk->id, LF_CHK_ID_LEN);
	OPENSSL_cleanse(chunk->tag, LF_CHK_TAG_LEN);
	EVP_CIPHER_CTX_free(ctx);
	return LF_E_OK;
}

int LF_chunk_read(LF_chunk *chunk, int fd, LF_chunk_mode mode)
{
	LF_chunk_cleanse(chunk);
	chunk->mode = mode;

	int ret;
	switch (mode) {
	case LF_CMODE_PLAIN:
		size_t out_len;
		ret = LF_io_read_max_or_eof(fd, chunk->buf, &out_len,
					    LF_CHK_BUF_LEN_MAX);
		if (0 != ret) {
			return ret;
		}
		chunk->buf_len = (uint32_t)out_len;
		break;
	case LF_CMODE_CIPHER:
		ret = LF_io_read_exact(fd, chunk->id, LF_CHK_ID_LEN);
		if (0 != ret) {
			return ret;
		}
		ret = LF_io_read_u32(fd, &chunk->buf_len, LITTLE_ENDIAN);
		if (0 != ret) {
			return ret;
		}
		ret = LF_io_read_exact(fd, chunk->buf, (size_t)chunk->buf_len);
		if (0 != ret) {
			return ret;
		}
		ret = LF_io_read_exact(fd, chunk->tag, LF_CHK_TAG_LEN);
		if (0 != ret) {
			return ret;
		}
		break;
	case LF_CMODE_UNDEF:
	default:
		return LF_E_INVALID;
	}
	return LF_E_OK;
}

int LF_chunk_write(const LF_chunk *chunk, int fd)
{
	int ret;
	switch (chunk->mode) {
	case LF_CMODE_PLAIN:
		ret = LF_io_write_exact(fd, chunk->buf, (size_t)chunk->buf_len);
		if (0 != ret) {
			return ret;
		}
		break;
	case LF_CMODE_CIPHER:
		ret = LF_io_write_exact(fd, chunk->id, LF_CHK_ID_LEN);
		if (0 != ret) {
			return ret;
		}
		ret = LF_io_write_u32(fd, &chunk->buf_len, LITTLE_ENDIAN);
		if (0 != ret) {
			return ret;
		}
		ret = LF_io_write_exact(fd, &chunk->buf,
					(size_t)chunk->buf_len);
		if (0 != ret) {
			return ret;
		}
		ret = LF_io_write_exact(fd, chunk->tag, LF_CHK_TAG_LEN);
		if (0 != ret) {
			return ret;
		}
		break;
	case LF_CMODE_UNDEF:
		return LF_E_INVALID;
	}
	return LF_E_OK;
}

void LF_chunk_cleanse(LF_chunk *chunk)
{
	OPENSSL_cleanse(chunk, sizeof *chunk);
	chunk->mode = LF_CMODE_UNDEF;
}
