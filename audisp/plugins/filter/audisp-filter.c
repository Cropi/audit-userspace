/* audisp-filter.c --
 * Copyright 2024 Red Hat Inc.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *   Attila Lakatos <alakatos@redhat.com>
 *
 */

#include "config.h"
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <sys/select.h>
#include <errno.h>
#include <syslog.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#ifdef HAVE_LIBCAP_NG
#include <cap-ng.h>
#endif
#include "libaudit.h"
#include "common.h"
#include "auparse.h"

struct filter_rule
{
	char *expr;
	int lineno;
	struct filter_rule *next;
};

struct filter_list
{
	struct filter_rule *head;
	struct filter_rule *tail;
};

/* Global Data */
static volatile int stop = 0;
static volatile int hup = 0;
static int pipefd[2];

enum
{
	ALLOWLIST,
	BLOCKLIST
};
static int mode = -1;
static const char *binary = NULL;
static char **binary_args = NULL;
static const char *config_file = NULL;
static int errors = 0;
static struct filter_list list;

/*
 * SIGTERM handler
 */
static void term_handler(int sig)
{
	stop = 1;
}

/*
 * SIGHUP handler: re-read config
 */
static void hup_handler(int sig)
{
	hup = 1;
}

static void reload_config(void)
{
	hup = 0;
}

static void print_list(struct filter_list *list)
{
	struct filter_rule *rule;
	int count = 0;

	printf("List print start\n");
	for (rule = list->head; rule != NULL; rule = rule->next, count++)
	{
		printf("Rule %d on line %d: %s\n", count, rule->lineno, rule->expr);
	}
	printf("List print end\n");
}

static void handle_event(auparse_state_t *au, auparse_cb_event_t cb_event_type, void *user_data)
{
	if (cb_event_type != AUPARSE_CB_EVENT_READY)
		return;

	int rc, forward_event, i;
	int nrecords = auparse_get_num_records(au);
	char **records = malloc(sizeof(char *) * nrecords);
	if (!records)
		return;

	/* save the whole event to a 2D dynamic array, based on preconfigured rules we will:
		- either forward them to the child process
		- or completely drop them
	*/
	i = 0;
	auparse_first_record(au);
	do
	{
		printf("[handle_event] %s\n", auparse_get_record_text(au));
		if (asprintf(&records[i], "%s\n", auparse_get_record_text(au)) == -1)
		{
			syslog(LOG_ERR, "Failed to allocate memory for record");
			break;
		}
		i++;
	} while (auparse_next_record(au) > 0);

	ausearch_set_stop(au, AUSEARCH_STOP_EVENT);

	// add rules(expressions) to the ausearch engine
	for (struct filter_rule *rule = list.head; rule != NULL; rule = rule->next)
	{
		char *error = NULL;
		rc = ausearch_add_expression(au, rule->expr, &error, AUSEARCH_RULE_OR);
	}

	// Determine whether to forward or drop the event
	rc = ausearch_next_event(au);
	if (rc > 0) /* matched */
	{
		forward_event = (mode == ALLOWLIST) ? 0 : 1;
	}
	else if (rc == 0) /* not matched */
	{
		forward_event = (mode == ALLOWLIST) ? 1 : 0;
	}
	else
	{
		syslog(LOG_ERR, "ausearch_next_event returned %d", rc);
		goto cleanup;
	}

	if (forward_event)
	{
		for (i = 0; i < nrecords; i++)
		{
			ssize_t write_rc = write(pipefd[1], records[i], strlen(records[i]));
			if (write_rc == -1)
			{
				syslog(LOG_ERR, "Failed to write to pipe\n");
			}
			printf("[forward_event] str=%s\n", records[i]);
		}
	}

cleanup:
	for (i = 0; i < nrecords; i++)
	{
		free(records[i]);
	}
	free(records);
}

static int parse_args(int argc, const char *argv[])
{
	if (argc <= 3)
	{
		syslog(LOG_ERR, "%s: Not enough arguments", argv[0]);
		return 1;
	}

	for (int i = 0; i < argc; i++)
	{
		printf("arg %d = %s\n", i, argv[i]);
	}

	if (strcasecmp(argv[1], "allowlist") == 0)
		mode = ALLOWLIST;
	else if (strcasecmp(argv[1], "blocklist") == 0)
		mode = BLOCKLIST;
	else
	{
		syslog(LOG_ERR, "Invalid mode %s specified, possible values are: allowlist, blocklist.", argv[1]);
		return 1;
	}

	config_file = argv[2];
	binary = argv[3];

	argc -= 3;
	argv += 3;

	binary_args = malloc(sizeof(char *) * (argc + 1)); /* +1 is for the last NULL */
	if (!binary_args)
		return -1;
	for (int i = 0; i < argc; i++)
	{
		binary_args[i] = (char *)argv[i];
	}
	binary_args[argc] = NULL;

	return 0;
}

static char *get_line(FILE *f, char *buf, unsigned size, int lineno, const char *file)
{
	int too_long = 0;

	while (fgets_unlocked(buf, size, f))
	{
		/* remove newline */
		char *ptr = strchr(buf, 0x0a);
		if (ptr)
		{
			if (!too_long)
			{
				*ptr = 0;
				return buf;
			}
			// Reset and start with trules
			too_long = 1;
		}
	}
	return NULL;
}

static void reset_list(struct filter_list *list)
{
	list->head = list->tail = NULL;
}

static void free_filter_rule(struct filter_rule *rule)
{
	free(rule->expr);
}

static void free_filter_list(struct filter_list *list)
{
	struct filter_rule *current = list->head, *to_delete;
	while (current != NULL)
	{
		to_delete = current;
		current = current->next;
		free_filter_rule(to_delete);
		free(to_delete);
	}
}

static void append_rule(struct filter_list *list, struct filter_rule *rule)
{
	if (list->head == NULL)
	{
		list->head = list->tail = rule;
	}
	else
	{
		list->tail->next = rule;
		list->tail = rule;
	}
}

static struct filter_rule *parse_line(char *line, int lineno)
{
	struct filter_rule *rule;
	auparse_state_t *au;
	const char *buf[] = {NULL};
	int rc;
	char *error = NULL;

	if ((au = auparse_init(AUSOURCE_BUFFER_ARRAY, buf)) == NULL)
	{
		// syslog(LOG_ERR, "auparse_init failed");
		printf("auparse_init failll\n");
		return NULL;
	}

	// Skip whitespace
	while (*line == ' ')
		line++;

	// Empty line or it's a comment
	if (!*line || *line == '#')
	{
		auparse_destroy(au);
		return NULL;
	}

	if ((rule = malloc(sizeof(struct filter_rule))) == NULL)
	{
		auparse_destroy(au);
		return NULL;
	}
	rule->lineno = lineno;
	rule->next = NULL;

	if ((rule->expr = strdup(line)) == NULL)
	{
		auparse_destroy(au);
		free(rule);
		return NULL;
	}

	if (ausearch_add_expression(au, rule->expr, &error, AUSEARCH_RULE_OR) != 0)
	{
		syslog(LOG_ERR, "Invalid expression: %s, reason: %s\n", rule->expr, error);
		free_filter_rule(rule);
		free(rule);
		rule = NULL;
		errors++;
	}

	auparse_destroy(au);
	return rule;
}

static int load_rules(struct filter_list *list)
{
	int fd, lineno = 0;
	struct stat st;
	char buf[1024];
	FILE *f;

	reset_list(list);
	errors = 0;

	/* open the file */
	if ((fd = open(config_file, O_RDONLY)) < 0)
	{
		if (errno != ENOENT)
		{
			syslog(LOG_ERR, "Error opening config file (%s)",
				   strerror(errno));
			return 1;
		}
		syslog(LOG_ERR,
			   "Config file %s doesn't exist, skipping", config_file);
		return 1;
	}

	if (fstat(fd, &st) < 0)
	{
		syslog(LOG_ERR, "Error fstat'ing config file (%s)",
			   strerror(errno));
		close(fd);
		return 1;
	}
	if (st.st_uid != 0)
	{
		syslog(LOG_ERR, "Error - %s isn't owned by root",
			   config_file);
		close(fd);
		return 1;
	}
	if ((st.st_mode & S_IWOTH) == S_IWOTH)
	{
		syslog(LOG_ERR, "Error - %s is world writable",
			   config_file);
		close(fd);
		return 1;
	}
	if (!S_ISREG(st.st_mode))
	{
		syslog(LOG_ERR, "Error - %s is not a regular file",
			   config_file);
		close(fd);
		return 1;
	}

	/* it's ok, read line by line */
	f = fdopen(fd, "rm");
	if (f == NULL)
	{
		syslog(LOG_ERR, "Error - fdopen failed (%s)",
			   strerror(errno));
		close(fd);
		return 1;
	}

	while (get_line(f, buf, sizeof(buf), lineno, config_file))
	{
		lineno++;
		struct filter_rule *rule;
		if ((rule = parse_line(buf, lineno)) == NULL)
			continue;

		append_rule(list, rule);
	}
	fclose(f);

	return errors;
}

int main(int argc, const char *argv[])
{
	auparse_state_t *au = NULL;
	struct sigaction sa;
	char buffer[MAX_AUDIT_MESSAGE_LENGTH];
	pid_t cpid;

	if (parse_args(argc, argv))
		return 1;

	if (load_rules(&list))
	{
		free_filter_list(&list);
		return 1;
	}

	print_list(&list);

	/* Register sighandlers */
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	/* Set handler for the ones we care about */
	sa.sa_handler = term_handler;
	sigaction(SIGTERM, &sa, NULL);
	sa.sa_handler = hup_handler;
	sigaction(SIGHUP, &sa, NULL);

#ifdef HAVE_LIBCAP_NG
	// Drop capabilities
	capng_clear(CAPNG_SELECT_BOTH);
	if (capng_apply(CAPNG_SELECT_BOTH))
		syslog(LOG_WARNING, "%s plugin was unable to drop capabilities, continuing with elevated privileges", argv[0]);
#endif

	if (pipe(pipefd) == -1)
	{
		syslog(LOG_ERR, "%s is exiting due to not being able to open a pipe\n", argv[0]);
		return -1;
	}

	cpid = fork();
	if (cpid == -1)
	{
		syslog(LOG_ERR, "%s is exiting due to fork() error\n", argv[0]);
		return -1;
	}

	if (cpid == 0)
	{
		/* Child reads filtered input*/

		close(pipefd[1]);
		dup2(pipefd[0], STDIN_FILENO);
		close(pipefd[0]);

		execve(binary, binary_args, NULL);
		syslog(LOG_ERR, "%s execve errored\n", argv[0]);
	}
	else
	{
		/* Parent reads input and forwards data after filters have been applied */
		close(pipefd[0]);

		au = auparse_init(AUSOURCE_FEED, 0);
		if (au == NULL)
		{
			syslog(LOG_ERR, "%s is exiting due to auparse_init errors\n", argv[0]);
			return -1;
		}

		auparse_set_eoe_timeout(2);
		auparse_add_callback(au, handle_event, NULL, NULL);
		do
		{
			fd_set read_mask;
			int retval;
			int read_size = 1; /* Set to 1 so it's not EOF */

			/* Load configuration */
			if (hup)
			{
				reload_config();
			}
			do
			{
				FD_ZERO(&read_mask);
				FD_SET(0, &read_mask);

				if (auparse_feed_has_data(au))
				{
					struct timeval tv;
					tv.tv_sec = 1;
					tv.tv_usec = 0;
					retval = select(1, &read_mask, NULL, NULL, &tv);
				}
				else
					retval = select(1, &read_mask, NULL, NULL, NULL);

				printf("SSSS\n");

				/* If we timed out & have events, shake them loose */
				if (retval == 0 && auparse_feed_has_data(au))
					auparse_feed_age_events(au);

			} while (retval == -1 && errno == EINTR && !hup && !stop);

			/* Now the event loop */
			if (!stop && !hup && retval > 0)
			{
				while ((read_size = read(0, buffer, MAX_AUDIT_MESSAGE_LENGTH)) > 0)
				{
					auparse_feed(au, buffer, read_size);
				}
			}
			if (read_size == 0) /* EOF */
				break;
		} while (stop == 0);

		auparse_flush_feed(au);
		auparse_destroy(au);
		waitpid(cpid, NULL, 0);
	}

	return 0;
}
