#include "key.h"
#include "header.h"
#include <argon2.h>
#include <openssl/crypto.h>

int LF_key_new(LF_key *key, const LF_header *header, const uint8_t *pwd,
	       size_t pwd_len)
{
	if (ARGON2_OK !=
	    argon2id_hash_raw(header->time_cost, header->memory_cost,
			      header->parallelism, pwd, pwd_len, header->salt,
			      LF_HDR_SALT_LEN, *key, LF_KEY_LEN)) {
		return -4094;
	}
	return 0;
}

void LF_key_cleanse(LF_key *key)
{
	OPENSSL_cleanse(*key, LF_KEY_LEN);
}
