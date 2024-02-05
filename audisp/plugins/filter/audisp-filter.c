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

typedef struct filter_type
{
	char *type;
	char *operator;
} filter_type_t;

typedef struct filter_pair
{
	char *key;
	char *key_operator;
	char *value;
	char *value_operator;
} filter_pair_t;

typedef enum
{
	FILTER_TYPE, /* e.g. type = "SYSCALL"*/
	FILTER_PAIR	 /* e.g. key="uid" value="root" */
} filter_t;

/* Depending on the value of filter, we filter based on:
 *  - audit event type
 *  - audit record pair (key and value)
 */
struct filter_rule
{
	filter_t filter;
	union
	{
		filter_type_t type;
		filter_pair_t pair;
	} data;

	struct filter_rule *next;
};

struct filter_rules
{
	struct filter_rule *head;
	struct filter_rule *tail;
	struct filter_rules *next;
};

struct filter_list
{
	struct filter_rules *head;
	struct filter_rules *tail;
};

static struct filter_rule *parse_type(char **buf, int lineno);
static struct filter_rule *parse_pair(char **buf, int lineno);
struct filter_parser
{
	const char *filter_str;
	filter_t filter;
	struct filter_rule *(*parse)(char **buf, int lineno);
} parsers[] = {
	{"type", FILTER_TYPE, parse_type},
	{"key", FILTER_PAIR, parse_pair},
	{NULL, -1, NULL}};

static void print_rules(struct filter_rules *rules)
{
	struct filter_rule *rule;
	for (rule = rules->head; rule != NULL; rule = rule->next)
	{
		printf("\t");
		if (rule->filter == FILTER_PAIR)
		{
			printf("key %s %s ", rule->data.pair.key_operator, rule->data.pair.key);
			if (rule->data.pair.value != NULL)
			{
				printf("value |%s| %s ", rule->data.pair.value_operator, rule->data.pair.value);
			}
		}
		else if (rule->filter == FILTER_TYPE)
		{
			printf("type %s %s", rule->data.type.operator, rule->data.type.type);
		}
		printf("\n");
	}
}

static void print_list(struct filter_list *list)
{
	struct filter_rules *rules;
	int count = 0;

	printf("List print start\n");
	for (rules = list->head; rules != NULL; rules = rules->next, count++)
	{
		printf("Rule %d:\n", count);
		print_rules(rules);
	}
	printf("List print end\n");
}

/* Global Data */
static volatile int stop = 0;
static volatile int hup = 0;
static int pipefd[2];
/* mode:
   0 - allowlist
   1 - blocklist
*/
enum
{
	BLOCKLIST = 0,
	ALLOWLIST = 1
};
static int mode = -1;
static const char *binary = NULL;
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

static void dump_fields_of_record(auparse_state_t *au)
{
	printf("record type %d(%s) has %d fields\n", auparse_get_type(au),
		   audit_msg_type_to_name(auparse_get_type(au)),
		   auparse_get_num_fields(au));

	printf("line=%d file=%s\n", auparse_get_line_number(au),
		   auparse_get_filename(au) ? auparse_get_filename(au) : "stdin");

	const au_event_t *e = auparse_get_timestamp(au);
	if (e == NULL)
	{
		printf("Error getting timestamp - aborting\n");
		return;
	}
	/* Note that e->sec can be treated as time_t data if you want
	 * something a little more readable */
	printf("event time: %u.%u:%lu, host=%s\n", (unsigned)e->sec,
		   e->milli, e->serial, e->host ? e->host : "?");
	auparse_first_field(au);

	do
	{
		printf("field: %s=%s (%s)\n",
			   auparse_get_field_name(au),
			   auparse_get_field_str(au),
			   auparse_interpret_field(au));
	} while (auparse_next_field(au) > 0);
	printf("\n");
}

/* This function shows how to dump a whole record's text */
static void dump_whole_record(auparse_state_t *au)
{
	printf("%s: %s\n", audit_msg_type_to_name(auparse_get_type(au)),
		   auparse_get_record_text(au));
	printf("\n");
}

static void handle_event(auparse_state_t *au, auparse_cb_event_t cb_event_type, void *user_data)
{
	int type, rc, num = 0, found = 0;

	if (cb_event_type != AUPARSE_CB_EVENT_READY)
		return;

	printf("[handle_event] New event au=%p\n", au);

	auparse_first_record(au);
	do
	{
		printf("[handle_event] %s\n", auparse_get_record_text(au));

		// const char *text = auparse_get_record_text(au);
		// const ssize_t len = strlen(text);
		// char *tmp = malloc(len+2);
		// strcpy(tmp, auparse_get_record_text(au));
		// tmp[len] = '\n';
		// tmp[len + 1] = '\0';

		// ssize_t rc;
		// if ((rc = write(pipefd[1], tmp, strlen(tmp))) == -1)
		// {
		// 	printf("[handle_event] write() failed\n");
		// }
		// printf("[handle_event] write rc=%u\n", rc);
	} while (auparse_next_record(au) > 0);
	printf("[handle_event] Event ended\n");

	// const char *expr = "type = SYSCALL";
	// char *error = NULL;
	// rc = ausearch_add_expression(au, expr, &error, AUSEARCH_RULE_AND);
	// printf("ausearch_add_expression rc=%d error=%s\n", rc, error);

	// return;

	/* allowlist: found=1, blocklist: found=0 */
	for (struct filter_rules *rules = list.head; rules != NULL; rules = rules->next)
	{
		rc = auparse_first_record(au);
		printf("[handle_event] auparse_first_record rc=%d\n", rc);
		rc = ausearch_set_stop(au, AUSEARCH_STOP_EVENT);
		printf("[handle_event] ausearch_set_stop rc=%d\n", rc);
		ausearch_expr(au);

		/* create the ausearch query based on a single config line */
		for (struct filter_rule *rule = rules->head; rule != NULL; rule = rule->next)
		{
			printf("[handle_event] will filter by %d\n", rule->filter);
			if (rule->filter == FILTER_TYPE)
			{
				rc = ausearch_add_item(au, "type", rule->data.type.operator, rule->data.type.type, AUSEARCH_RULE_AND);
				printf("[handle_event] ausearch_add_item type rc=%d\n", rc);
			}
			else if (rule->filter == FILTER_PAIR)
			{
				char *key, *op, *value;
				if (rule->data.pair.value != NULL)
				{
					/* check for key-value pair */
					key = rule->data.pair.key;
					op = rule->data.pair.value_operator;
					value = rule->data.pair.value;
				}
				else
				{
					/* check for existence of a specific key*/
					key = rule->data.pair.key;
					op = "exists";
					value = NULL;
				}
				rc = ausearch_add_item(au, key, op, value, AUSEARCH_RULE_AND);
				printf("[handle_event] ausearch_add_item pair rc=%d\n", rc);
			}
		}

		found = ausearch_next_event(au);
		ausearch_clear(au);
		// auparse_reset(au);
		printf("[handle_event] ausearch_next_event found=%d\n\n", found);
		printf("Event after iteration:\n");
		rc = auparse_first_record(au);
		printf("[handle_event2] auparse_first_record rc=%d\n", rc);
		do
		{
			printf("[handle_event2] %s\n", auparse_get_record_text(au));
		} while (auparse_next_record(au) > 0);
	}

	// if (ausearch_add_item(au, "uid", "=", "1001", AUSEARCH_RULE_AND))
	// {
	// 	printf("ausearch error\n");
	// }
	// else
	// {
	// 	if (ausearch_set_stop(au, AUSEARCH_STOP_EVENT))
	// 	{
	// 		printf("ausearch_set_stop error - %s\n", strerror(errno));
	// 	}
	// 	else
	// 	{
	// 		if (ausearch_next_event(au) <= 0)
	// 			printf("Error searching for auid - %s\n", strerror(errno));
	// 		else
	// 			printf("Found %s = %s\n", auparse_get_field_name(au),
	// 				   auparse_get_field_str(au));
	// 	}
	// }
	// ausearch_clear(au);
	return;
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
		mode = 1;
	else if (strcasecmp(argv[1], "blocklist") == 0)
		mode = 0;
	else
	{
		syslog(LOG_ERR, "%s: Invalid mode specified, possible values are: allowlist, blocklist.");
		return 1;
	}

	config_file = argv[2];
	binary = argv[3];

	return 0;
}

static char *get_line(FILE *f, char *buf, unsigned size, int lineno,
					  const char *file)
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

static void reset_rules(struct filter_rules *rules)
{
	rules->head = rules->tail = NULL;
	rules->next = NULL;
}

static struct filter_rule *parse_type(char **buf, int lineno)
{
	char *token;
	struct filter_rule *rule;

	if ((rule = malloc(sizeof(struct filter_rule))) == NULL)
		return NULL;

	rule->filter = FILTER_TYPE;
	rule->next = NULL;

	token = strtok_r(NULL, " ", buf);
	if (!token)
	{
		free(rule);
		return NULL;
	}

	rule->data.type.operator= strdup(token);

	token = strtok_r(NULL, " ", buf);
	if (!token)
	{
		free(rule);
		return NULL;
	}

	rule->data.type.type = strdup(token);
	if (!rule->data.type.type)
	{
		free(rule);
		return NULL;
	}

	return rule;
}

static struct filter_rule *parse_pair(char **buf, int lineno)
{
	char *ptr;
	struct filter_rule *rule;
	int i = 0;

	if ((rule = malloc(sizeof(struct filter_rule))) == NULL)
		return NULL;

	rule->filter = FILTER_PAIR;
	rule->next = NULL;
	rule->data.pair.key = NULL;
	rule->data.pair.key_operator = NULL;
	rule->data.pair.value = NULL;
	rule->data.pair.value_operator = NULL;

	ptr = strtok_r(NULL, " ", buf);
	if (!ptr)
	{
		printf("Operator is missing on line %d\n", lineno);
		return NULL;
	}

	rule->data.pair.key_operator = strdup(ptr);

	ptr = strtok_r(NULL, " ", buf);
	if (!ptr)
	{
		printf("Key is missing on line %d\n", lineno);
		return NULL;
	}
	rule->data.pair.key = strdup(ptr);

	if (strncmp(*buf, "value", strlen("value")) == 0)
	{
		ptr = strtok_r(NULL, " ", buf);
		ptr = strtok_r(NULL, " ", buf);
		if (!ptr)
		{
			printf("Operator is missing on line %d\n", lineno);
			return NULL;
		}

		rule->data.pair.value_operator = strdup(ptr);

		ptr = strtok_r(NULL, " ", buf);
		if (!ptr)
		{
			printf("Value is missing on line %d\n", lineno);
			return NULL;
		}
		rule->data.pair.value = strdup(ptr);
	}

	return rule;
}

static void free_filter_rules(struct filter_rules *rules)
{
	struct filter_rule *current = rules->head, *to_delete;
	while (current != NULL)
	{
		to_delete = current;
		current = current->next;
		if (to_delete->filter == FILTER_TYPE)
		{
			free(to_delete->data.pair.key);
			free(to_delete->data.pair.key_operator);
			free(to_delete->data.pair.value);
			free(to_delete->data.pair.value_operator);
		}
		else if (to_delete->filter == FILTER_PAIR)
		{
			free(to_delete->data.type.type);
		}

		free(to_delete);
	}
}

static void free_filter_list(struct filter_list *list)
{
	struct filter_rules *current = list->head, *to_delete;
	while (current != NULL)
	{
		to_delete = current;
		current = current->next;
		free_filter_rules(to_delete);
		free(to_delete);
	}
}

static void append_rule(struct filter_rules *rules, struct filter_rule *rule)
{
	if (rules->head == NULL)
	{
		rules->head = rules->tail = rule;
	}
	else
	{
		rules->tail->next = rule;
		rules->tail = rule;
	}
}

static void append_rules(struct filter_list *list, struct filter_rules *rules)
{
	if (list->head == NULL)
	{
		list->head = list->tail = rules;
	}
	else
	{
		list->tail->next = rules;
		list->tail = rules;
	}
}

static struct filter_parser *find_parser(char *token)
{
	for (int i = 0; parsers[i].filter_str != NULL; i++)
	{
		if (strncasecmp(parsers[i].filter_str, token, strlen(parsers[i].filter_str)) == 0)
		{
			return &parsers[i];
		}
	}
	return NULL;
}

static struct filter_rules *parse_line(char *line, int lineno)
{
	struct filter_rules *rules;
	int line_has_error = 0;
	char *token, *saveptr;

	if ((rules = malloc(sizeof(struct filter_rules))) == NULL)
		return NULL;
	reset_rules(rules);

	token = strtok_r(line, " ", &saveptr);
	while (token != NULL)
	{
		printf("token=%s saveptr=%s\n", token, saveptr);

		// Trim leading whitespace
		while (*token == ' ')
			token++;

		if (!*token)
			break;

		// Skip comments
		if (token[0] == '#')
			break;

		struct filter_parser *parser;
		if ((parser = find_parser(token)) == NULL)
		{
			syslog(LOG_ERR, "Invalid keyword(%s) on token %d", token, lineno);
			line_has_error = 1;
			break;
		}

		struct filter_rule *rule;
		if ((rule = parser->parse(&saveptr, lineno)) == NULL)
		{
			line_has_error = 1;
			break;
		}
		append_rule(rules, rule);

		token = strtok_r(NULL, " ", &saveptr);
	}

	errors += line_has_error;

	if (line_has_error)
	{
		free_filter_rules(rules);
		free(rules);
		rules = NULL;
	}

	return rules;
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
		syslog(LOG_WARNING,
			   "Config file %s doesn't exist, skipping", config_file);
		return 0;
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

		struct filter_rules *rules;
		if ((rules = parse_line(buf, lineno)) == NULL)
			continue;

		append_rules(list, rules);
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

	printf("parse_args()\n");
	if (parse_args(argc, argv))
		return 1;

	printf("load_rules()\n");
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

		char *args[] = {"/usr/local/sbin/audisp-syslog", NULL};
		execve("/usr/local/sbin/audisp-syslog", args, NULL);
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
