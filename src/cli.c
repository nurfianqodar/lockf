#include "cli.h"
#include "chunk.h"
#include "err.h"
#include "header.h"
#include "io_util.h"
#include "key.h"
#include <linux/limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <wchar.h>

static int strtou32(const char *s, uint32_t *out)
{
	if (!s || !out) {
		return LF_E_INVALID;
	}
	errno = 0;
	char *end = NULL;
	unsigned long val = strtoul(s, &end, 10);
	if (end == s) {
		return LF_E_INVALID;
	}
	if ('\0' != *end) {
		return LF_E_INVALID;
	}
	if (ERANGE == errno) {
		return LF_E_RANGE;
	}
	if (val > UINT32_MAX) {
		return LF_E_RANGE;
	}
	*out = (uint32_t)val;
	return LF_E_OK;
}

static int cli_run(const LF_cli_config *config, int fd_in, int fd_out)
{
	int ret;
	LF_header header;
	switch (config->mode) {
	case LF_CLIMODE_ENCRYPT:
		ret = LF_header_new(&header, config->time_cost,
				    config->memory_cost, config->parallelism);
		if (ret != 0) {
			return ret;
		}
		ret = LF_header_write(&header, fd_out);
		if (ret != 0) {
			return ret;
		}
		break;
	case LF_CLIMODE_DECRYPT:
		ret = LF_header_read(&header, fd_in);
		if (ret != 0) {
			return ret;
		}
		break;
	default:
		return LF_E_INVALID;
	}

	LF_key key;
	ret = LF_key_new(&key, &header, config->pwd, config->pwd_len);
	if (ret != 0) {
		return ret;
	}

	LF_chunk chunk;
	LF_chunk_mode chunk_mode;
	switch (config->mode) {
	case LF_CLIMODE_ENCRYPT:
		chunk_mode = LF_CMODE_PLAIN;
		break;
	case LF_CLIMODE_DECRYPT:
		chunk_mode = LF_CMODE_CIPHER;
		break;
	default:
		return LF_E_INVALID;
	}

	do {
		ret = LF_chunk_read(&chunk, fd_in, chunk_mode);
		if (0 != ret) {
			return ret;
		}
		switch (config->mode) {
		case LF_CLIMODE_ENCRYPT:
			ret = LF_chunk_encrypt(&chunk, &header, &key);
			if (0 != ret) {
				return ret;
			}
			break;
		case LF_CLIMODE_DECRYPT:
			ret = LF_chunk_decrypt(&chunk, &header, &key);
			if (0 != ret) {
				return ret;
			}
			break;
		default:
			return LF_E_INVALID;
		}
		ret = LF_chunk_write(&chunk, fd_out);
		if (0 != ret) {
			return ret;
		}
	} while (chunk.buf_len == LF_CHK_BUF_LEN_MAX);
	return LF_E_OK;
}

int LF_cli_config_parse(LF_cli_config *config, int argc, char **argv)
{
	bool has_opath, has_ipath, has_pwd, has_time, has_mem, has_para;
	has_opath = has_ipath = has_pwd = has_time = has_mem = has_para = false;
	if (argc < 8) {
		return LF_E_INVALID;
	}
	int idx = 1;
	switch (argv[idx][0]) {
	case 'e':
		config->mode = LF_CLIMODE_ENCRYPT;
		break;
	case 'd':
		config->mode = LF_CLIMODE_DECRYPT;
		break;
	default:
		return LF_E_INVALID;
	}
	idx += 1;

	int ret;
	while (idx < argc) {
		const char *flag = argv[idx];
		idx += 1;
		const char *value = argv[idx];
		idx += 1;
		size_t value_len = strlen(value);
		if (0 == strcmp(flag, "-i")) { // In file
			if (value_len > PATH_MAX) {
				return LF_E_INVALID;
			}
			strcpy(config->input_path, value);
			has_ipath = true;
		} else if (0 == strcmp(flag, "-o")) { // Out File
			if (value_len > PATH_MAX) {
				return LF_E_INVALID;
			}
			strcpy(config->output_path, value);
			has_opath = true;
		} else if (0 == strcmp(flag, "-t")) { // Time cost
			if (0 != (ret = strtou32(value, &config->time_cost))) {
				return ret;
			}
			has_time = true;
		} else if (0 == strcmp(flag, "-m")) { // Memory cost
			if (0 !=
			    (ret = strtou32(value, &config->memory_cost))) {
				return ret;
			}
			has_mem = true;
		} else if (0 == strcmp(flag, "-p")) { // Parallelism
			if (0 !=
			    (ret = strtou32(value, &config->parallelism))) {
				return ret;
			}
			has_para = true;
		} else if (0 == strcmp(flag, "-P")) { // Password
			if (value_len > LF_CLI_PWD_MAX) {
				return LF_E_INVALID;
			}
			strcpy((char *)config->pwd, value);
			has_pwd = true;
		} else { // invalid options
			return LF_E_INVALID;
		}
	}
	if (!(has_ipath && has_opath && has_pwd)) {
		return LF_E_INVALID;
	}
	if (!has_time) {
		config->time_cost = LF_CLI_TIME_COST_DEFAULT;
	}
	if (!has_mem) {
		config->memory_cost = LF_CLI_MEMORY_COST_DEFAULT;
	}
	if (!has_para) {
		config->parallelism = LF_CLI_PARALLELISM_DEFAULT;
	}
	return LF_E_OK;
}

int LF_cli_config_validate(const LF_cli_config *config)
{
	(void)config;
	return LF_E_OK;
}

int LF_cli_run(const LF_cli_config *config)
{
	int fd_in, fd_out;
	int ret;
	ret = LF_io_open_read(&fd_in, config->input_path);
	if (0 != ret) {
		return ret;
	}
	ret = LF_io_open_wirte(&fd_out, config->output_path, false);
	if (0 != ret) {
		LF_io_close(&fd_in);
		return ret;
	}
	ret = cli_run(config, fd_in, fd_out);

	if (0 != ret) {
		LF_io_close(&fd_in);
		LF_io_close(&fd_out);
		remove(config->output_path);
		return ret;
	}
	return LF_E_OK;
}

static const char *USAGE = "Usage:\n"
			   "lockf <MODE> <OPTIONS> <VALUE> ...\n"
			   "MODE:\n"
			   "\te: encrypt\n"
			   "\td: decrypt\n"
			   "\nOPTIONS:\n"
			   "\t-i: input file,\t\tvalue: path,\trequired\n"
			   "\t-o: output file,\tvalue: path,\trequired\n"
			   "\t-P: password,\t\tvalue: string,\trequired\n"
			   "\t-t: time cost,\t\tvalue: uint32,\toptional\n"
			   "\t-m: memory cost,\tvalue: uint32,\toptional\n"
			   "\t-p: parallelism,\tvalue: uint32,\toptional\n";

void LF_cli_print_usage(void)
{
	printf("%s", USAGE);
}
