#include "cli.h"
#include "chunk.h"
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
		return -EINVAL;
	}

	errno = 0;
	char *end = NULL;

	unsigned long val = strtoul(s, &end, 10);

	/* 1. No digits parsed */
	if (end == s) {
		return -EINVAL;
	}

	/* 2. Extra junk after number */
	if (*end != '\0') {
		return -EINVAL;
	}

	/* 3. Overflow/underflow from strtoul */
	if (errno == ERANGE) {
		return -ERANGE;
	}

	/* 4. Range check for uint32_t */
	if (val > UINT32_MAX) {
		return -ERANGE;
	}

	*out = (uint32_t)val;
	return 0;
}

int LF_cli_config_parse(LF_cli_config *config, int argc, char **argv)
{
	bool has_opath, has_ipath, has_pwd, has_time, has_mem, has_para;
	has_opath = has_ipath = has_pwd = has_time = has_mem = has_para = false;

	if (argc < 8) {
		return -1;
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
		return -1;
	}
	idx += 1;

	while (idx < argc) {
		const char *flag = argv[idx];
		idx += 1;
		const char *value = argv[idx];
		idx += 1;
		size_t value_len = strlen(value);

		if (0 == strcmp(flag, "-i")) { // In file
			if (value_len > PATH_MAX) {
				return -1;
			}
			strcpy(config->input_path, value);
			has_ipath = true;
		} else if (0 == strcmp(flag, "-o")) { // Out File
			if (value_len > PATH_MAX) {
				return -1;
			}
			strcpy(config->output_path, value);
			has_opath = true;
		} else if (0 == strcmp(flag, "-t")) { // Time cost
			if (0 != strtou32(value, &config->time_cost)) {
				return -1;
			}
			has_time = true;
		} else if (0 == strcmp(flag, "-m")) { // Memory cost
			if (0 != strtou32(value, &config->memory_cost)) {
				return -1;
			}
			has_mem = true;
		} else if (0 == strcmp(flag, "-p")) { // Parallelism
			if (0 != strtou32(value, &config->parallelism)) {
				return -1;
			}
			has_para = true;
		} else if (0 == strcmp(flag, "-P")) { // Password
			if (value_len > LF_CLI_PWD_MAX) {
				return -1;
			}
			strcpy((char *)config->pwd, value);
			has_pwd = true;
		} else { // invalid options
			return -1;
		}
	}
	if (!(has_ipath && has_opath && has_pwd)) {
		return -1;
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
	return 0;
}

int LF_cli_config_validate(const LF_cli_config *config)
{
	(void)config;
	return 0;
}

int LF_cli_run(const LF_cli_config *config)
{
	int fd_in, fd_out;
	int ret;
	ret = LF_io_open_read(&fd_in, config->input_path);
	if (0 != ret) {
		printf("open read error\n");
		return ret;
	}
	ret = LF_io_open_wirte(&fd_out, config->output_path, false);
	if (0 != ret) {
		printf("open write error\n");
		LF_io_close(&fd_in);
		return ret;
	}

	LF_header header;
	switch (config->mode) {
	case LF_CLIMODE_ENCRYPT:
		ret = LF_header_new(&header, config->time_cost,
				    config->memory_cost, config->parallelism);
		if (ret != 0) {
			printf("new header error\n");
			LF_io_close(&fd_in);
			LF_io_close(&fd_out);
			remove(config->output_path);
			return -1;
		}
		ret = LF_header_write(&header, fd_out);
		if (ret != 0) {
			printf("write new header error %s\n", strerror(errno));
			LF_io_close(&fd_in);
			LF_io_close(&fd_out);
			remove(config->output_path);
			return -1;
		}
		break;
	case LF_CLIMODE_DECRYPT:
		ret = LF_header_read(&header, fd_in);
		if (ret != 0) {
			printf("read header error: %s\n", strerror(errno));
			LF_io_close(&fd_in);
			LF_io_close(&fd_out);
			remove(config->output_path);
			return -1;
		}
		break;
	default:
		LF_io_close(&fd_in);
		LF_io_close(&fd_out);
		remove(config->output_path);
		return -1;
	}

	LF_key key;
	ret = LF_key_new(&key, &header, config->pwd, config->pwd_len);
	if (ret != 0) {
		LF_io_close(&fd_in);
		LF_io_close(&fd_out);
		remove(config->output_path);
		return -1;
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
		LF_io_close(&fd_in);
		LF_io_close(&fd_out);
		remove(config->output_path);
		return -1;
	}

	do {
		ret = LF_chunk_read(&chunk, fd_in, chunk_mode);
		if (0 != ret) {
			printf("read chunk error\n");
			LF_io_close(&fd_in);
			LF_io_close(&fd_out);
			remove(config->output_path);
			return -1;
		}
		switch (config->mode) {
		case LF_CLIMODE_ENCRYPT:
			ret = LF_chunk_encrypt(&chunk, &header, &key);
			if (0 != ret) {
				LF_io_close(&fd_in);
				LF_io_close(&fd_out);
				remove(config->output_path);
				return -1;
			}
			break;
		case LF_CLIMODE_DECRYPT:
			ret = LF_chunk_decrypt(&chunk, &header, &key);
			if (0 != ret) {
				LF_io_close(&fd_in);
				LF_io_close(&fd_out);
				remove(config->output_path);
				return -1;
			}
			break;
		default:
			LF_io_close(&fd_in);
			LF_io_close(&fd_out);
			remove(config->output_path);
			return -1;
		}
		ret = LF_chunk_write(&chunk, fd_out);
		if (0 != ret) {
			LF_io_close(&fd_in);
			LF_io_close(&fd_out);
			remove(config->output_path);
			return -1;
		}
	} while (chunk.buf_len == LF_CHK_BUF_LEN_MAX);
	return 0;
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
