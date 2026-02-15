#ifndef LF_CLI_H_
#define LF_CLI_H_

#include <linux/limits.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
	LF_CLIMODE_ENCRYPT,
	LF_CLIMODE_DECRYPT,
} LF_cli_mode;

#define LF_CLI_TIME_COST_DEFAULT 4
#define LF_CLI_MEMORY_COST_DEFAULT (1024 * 128)
#define LF_CLI_PARALLELISM_DEFAULT 4

#define LF_CLI_PWD_CAP 256
#define LF_CLI_PWD_MAX LF_CLI_PWD_CAP

typedef struct {
	LF_cli_mode mode;
	uint32_t time_cost;
	uint32_t memory_cost;
	uint32_t parallelism;
	uint8_t pwd[LF_CLI_PWD_CAP];
	size_t pwd_len;
	char input_path[PATH_MAX];
	char output_path[PATH_MAX];
} LF_cli_config;

int LF_cli_config_parse(LF_cli_config *config, int argc, char **argv);
int LF_cli_config_validate(const LF_cli_config *config);
int LF_cli_run(const LF_cli_config *config);

void LF_cli_print_usage(void);

#endif // !LF_CLI_H_
