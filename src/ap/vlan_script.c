/*
 * hostapd / VLAN initialization
 * Copyright 2003, Instant802 Networks, Inc.
 * Copyright 2005-2006, Devicescape Software, Inc.
 * Copyright (c) 2009, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#include "utils/common.h"
#include <stdarg.h>
#include <sys/types.h>
#include <sys/wait.h>

int run_script(char* output, int size, const char* script, ...)
{
	va_list ap;
	char *args[100];
	int argno = 0;
	pid_t pid;
	siginfo_t status;
	int filedes[2];

	va_start(ap, script);

	while (1) {
		args[argno] = va_arg(ap, char *);
		if (!args[argno])
			break;
		argno++;
		if (argno >= 100)
			break;
	}

	if (output) {
		if (pipe(filedes) < 0) {
			perror("pipe");
			return -1;
		}
	}

	pid = fork();
	if (pid < 0) {
		if (output) {
			close(filedes[1]);
			close(filedes[0]);
		}
		perror("fork");
		return -1;
	} else if (pid == 0) {
		if (output) {
			while ((dup2(filedes[1], STDOUT_FILENO) == -1) && (errno == EINTR)) {};
			close(filedes[1]);
			close(filedes[0]);
		}
		execv(script, args);
		perror("execv");
		exit(1);
	}
	if (output)
		close(filedes[1]);
	if (waitid(P_PID, pid, &status, WEXITED) < 0)
		return -1;
	if (status.si_code != CLD_EXITED)
		return -1;
	if (status.si_status != 0)
		return 1;
	if (!output)
		return 0;

	for (;;) {
		if (size <= 0)
			break;
		if (read(filedes[0], output, 1) <= 0)
			break;
		if (*output == '\n') {
			*output = '\0';
			break;
		}
		output++;
		size--;
	}

	close(filedes[0]);
	return 0;
}


