#include "cli.h"
#include <stdio.h>

int main(int argc, char **argv)
{
	LF_cli_config config;
	if (0 != LF_cli_config_parse(&config, argc, argv)) {
		LF_cli_print_usage();
		return 1;
	}
	printf("%s\n", config.input_path);
	printf("%s\n", config.output_path);
	printf("%s\n", config.pwd);

	if (-1 == LF_cli_run(&config)) {
		printf("operation error");
		return 1;
	}
	return 0;
}
