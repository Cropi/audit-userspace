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
#ifdef HAVE_LIBCAP_NG
#include <cap-ng.h>
#endif
#include "libaudit.h"
#include "common.h"
#include "auparse.h"

typedef enum {
	OPERATOR_UNKNOWN,
	OPERATOR_EQUALS,
	OPERATOR_NOT_EQUALS
} filter_operator_t;

typedef struct filter_type {
	char *type;
	filter_operator_t operator;
} filter_type_t;

typedef struct filter_pair {
	char *key;
	filter_operator_t key_operator;
	char *value;
	filter_operator_t value_operator;
} filter_pair_t;

typedef enum {
	FILTER_TYPE, /* e.g. type = "SYSCALL"*/
	FILTER_PAIR /* e.g. key="uid" value="root" */
} filter_t;


/* Depending on the value of filter, we filter based on:
 *  - audit event type
 *  - audit record pair (key and value)
 */
struct filter_rule {
	filter_t filter;
	union {
		filter_type_t type;
		filter_pair_t pair;
	} data;

	struct filter_rule *next;
};

struct filter_rules {
	struct filter_rule *head;
	struct filter_rule *tail;
	struct filter_rules *next;
};

struct filter_list {
	struct filter_rules *head;
	struct filter_rules *tail;
};

static struct filter_rule *parse_type(char **buf, int lineno);
static struct filter_rule *parse_pair(char **buf, int lineno);
struct filter_parser {
	const char *filter_str;
	filter_t filter;
	struct filter_rule* (*parse)(char **buf, int lineno);
} parsers[] = {
	{ "type", FILTER_TYPE, parse_type },
	{ "key", FILTER_PAIR, parse_pair },
	{ NULL, -1, NULL }
};

static void print_rules(struct filter_rules *rules)
{
	struct filter_rule *rule;
	for (rule = rules->head; rule != NULL; rule = rule->next) {
		printf("\t");
		if (rule->filter == FILTER_PAIR) {
			printf("key %s %d ", rule->data.pair.key, rule->data.pair.key_operator);
			if (rule->data.pair.value != NULL) {
				printf("value %s %d ", rule->data.pair.value, rule->data.pair.value_operator);
			}
		} else if (rule->filter == FILTER_TYPE) {
			printf("type %s %d", rule->data.type.type, rule->data.type.operator);
		}
		printf("\n");
	}
}

static void print_list(struct filter_list *list)
{
	struct filter_rules *rules;
	int count = 0;

	for (rules = list->head; rules != NULL; rules = rules->next, count++) {
		printf("Rule %d:\n", count);
		print_rules(rules);
	}
}

/* Global Data */
static volatile int stop = 0;
static volatile int hup = 0;
static auparse_state_t *au = NULL;
/* mode:
   0 - allowlist
   1 - blocklist
*/
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

static void handle_event(auparse_state_t *au,
						 auparse_cb_event_t cb_event_type, void *user_data)
{
	int type, num = 0;

	if (cb_event_type != AUPARSE_CB_EVENT_READY)
		return;

	printf("SZEVASZ: %d\n", *(int *)user_data);
	auparse_first_record(au);
	do {
		printf("[WRITE] %s\n", auparse_get_record_text(au));
		if (write(*(int *)user_data, auparse_get_record_text(au), MAX_AUDIT_MESSAGE_LENGTH) == -1) {
			printf("[WRITE] BAj van\n");
		}
	} while (auparse_next_record(au) > 0);
	printf("\n");
	return;

	/* Loop through the records in the event looking for one to process.
	   We use physical record number because we may search around and
	   move the cursor accidentally skipping a record. */
	printf("New event: cb_event_type=%d\n", cb_event_type);
	while (auparse_goto_record_num(au, num) > 0)
	{
		printf("Szevaasz:\n");
		type = auparse_get_type(au);
		dump_fields_of_record(au);

		/* Now we can branch based on what record type we find.
		   This is just a few suggestions, but it could be anything. */
		switch (type)
		{
		case AUDIT_AVC:
			// dump_fields_of_record(au);
			break;
		case AUDIT_SYSCALL:
			// dump_whole_record(au);
			break;
		case AUDIT_USER_LOGIN:
			break;
		case AUDIT_ANOM_ABEND:
			break;
		case AUDIT_MAC_STATUS:
			// dump_whole_event(au);a
			break;
		default:
			break;
		}
		num++;
	}
}

static int parse_args(int argc, const char *argv[])
{
	if (argc <= 3) {
		syslog(LOG_ERR, "%s: Not enough arguments", argv[0]);
		return 1;
	}

	for (int i = 0; i < argc; i++) {
		printf("arg %d = %s\n", i, argv[i]);
	}

	if (strcasecmp(argv[1], "allowlist") == 0)
		mode = 0;
	else if (strcasecmp(argv[1], "blocklist") == 0)
		mode = 1;
	else {
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

	while (fgets_unlocked(buf, size, f)) {
		 /* remove newline */
		char *ptr = strchr(buf, 0x0a);
		if (ptr) {
			if (!too_long) {
				*ptr = 0;
				return buf;
			}
			// Reset and start with trules
			too_long = 1;
		}
	}
	return NULL;
}

static void reset_ruleset(struct filter_list *list)
{
	list->head = NULL;
	list->tail = NULL;
}


static filter_operator_t str_to_operator(char *str)
{
	if (strcmp(str, "=") == 0)
		return OPERATOR_EQUALS;
	else if (strcmp(str, "!=") == 0)
		return OPERATOR_NOT_EQUALS;
	return OPERATOR_UNKNOWN;
}

static struct filter_rule *parse_type(char **buf, int lineno)
{
	char *token, *saveptr;
	struct filter_rule *rule;

	if ((rule = malloc(sizeof(struct filter_rule))) == NULL)
		return NULL;

	rule->filter = FILTER_TYPE;
	rule->next = NULL;

	token = strtok_r(*buf, " ", &saveptr);
	if (!token || strcmp(token, "type") != 0) {
		free(rule);
		return NULL;
	}

	token = strtok_r(NULL, " ", &saveptr);
	if (!token) {
		free(rule);
		return NULL;
	}

	rule->data.type.operator = str_to_operator(token);
	if (rule->data.type.operator == OPERATOR_UNKNOWN) {
		free(rule);
		return NULL;
	}

	token = strtok_r(NULL, " ", &saveptr);
	if (!token) {
		free(rule);
		return NULL;
	}

	rule->data.type.type = strdup(token);
	if (!rule->data.type.type) {
		free(rule);
		return NULL;
	}

	*buf = saveptr;

	return rule;
}

static struct filter_rule *parse_pair(char **buf, int lineno)
{
	char *ptr, *saveptr;
	struct filter_rule *rule;
	int i = 0;

	if ((rule = malloc(sizeof(struct filter_rule))) == NULL)
		return NULL;

	rule->filter = FILTER_PAIR;
	rule->next = NULL;

	printf("1\n");
	ptr = strtok_r(*buf, " ", &saveptr);
	if (!ptr)
		return NULL;
			printf("2\n");
	if (strcmp(*buf, "key") != 0) 
		return NULL;

	printf("3\n");
	ptr = strtok_r(NULL, " ", &saveptr);
	if (!ptr) {
		printf("Operator is missing on line %d\n", lineno);
		return NULL;
	}

	printf("4\n");
	rule->data.pair.key_operator = str_to_operator(ptr);
	if (rule->data.pair.key_operator == OPERATOR_UNKNOWN) {
		printf("Invalid operator on line %d\n", lineno);
		return NULL;
	}
	
	printf("5\n");
	ptr = strtok_r(NULL, " ", &saveptr);
	if (!ptr) {
		printf("Key is missing on line %d\n", lineno);
		return NULL;
	}
	printf("6\n");
	rule->data.pair.key = strdup(ptr);

	*buf = saveptr;

	printf("7\n");
	if (strncmp(*buf, "value", strlen("value")) == 0) {
		ptr = strtok_r(NULL, " ", &saveptr);
		printf("9\n");
		ptr = strtok_r(NULL, " ", &saveptr);
		if (!ptr) {
			printf("Operator is missing on line %d\n", lineno);
			return NULL;
		}
		printf("10\n");
		rule->data.pair.value_operator = str_to_operator(ptr);
		if (rule->data.pair.value_operator == OPERATOR_UNKNOWN) {
			printf("Operator is invalid on line %d\n", lineno);
			return NULL;
		}
		
			printf("11\n");
		ptr = strtok_r(NULL, " ", &saveptr);
		if (!ptr) {
			printf("Value is missing on line %d\n", lineno);
			return NULL;
		}
		rule->data.pair.value = strdup(ptr);
		*buf = saveptr;
		printf("12\n");
	}
	printf("C buf=%s\n", *buf);

	return rule;
}

static void free_filter_rules(struct filter_rules *rules)
{
	struct filter_rule *current = rules->head, *to_delete;
	while (current != NULL) {
		to_delete = current;
		current = current->next;
		// free_filter(to_delete);
		if (to_delete->filter == FILTER_TYPE) {
			free(to_delete->data.pair.key);
			free(to_delete->data.pair.value);
		} else if (to_delete->filter == FILTER_PAIR) {
			free(to_delete->data.type.type);
		}

		free(to_delete);
	}
}

static void append_rule(struct filter_rules *rules, struct filter_rule *rule) {
	if (rules->head == NULL) {
		rules->head = rules->tail = rule;
	} else {
		rules->tail->next = rule;
		rules->tail = rule;
	}
}

static void append_rules(struct filter_list *list, struct filter_rules *rules) {
	if (list->head == NULL) {
		list->head = list->tail = rules;
	} else {
		list->tail->next = rules;
		list->tail = rules;
	}
}


static struct filter_parser *find_parser(char *token) {
	for (int i = 0; parsers[i].filter_str != NULL; i++) {
		if (strncasecmp(parsers[i].filter_str, token, strlen(parsers[i].filter_str)) == 0) {
			return &parsers[i];
		}
	}
	return NULL;
}

static struct filter_rules *parse_line(char *line, int lineno)
{
	char *token;
	struct filter_rules *rules;
	int line_has_error = 0;

	if ((rules =  malloc(sizeof(struct filter_rules))) == NULL)
		return NULL;
	rules->head = rules->tail = NULL;
	rules->next = NULL;

	printf("Line start: |%s|\n", line);
	token = line;
	while (token != NULL) {
		printf("Remaining: |%s|\n", token);

		// Trim leading whitespace
		while (*token == ' ')
			token++;

		if (!*token)
			break;

		// Skip comments
		if (token[0] == '#')
			break;

		printf("token=%d *token=%d\n", token, *token);
		struct filter_parser *parser;
		if ((parser = find_parser(token)) == NULL) {
			printf("Invalid keyword(%s) on line %d", token, lineno);
			syslog(LOG_ERR, "Invalid keyword(%s) on line %d", token, lineno);
			line_has_error = 1;
			break;
		}

		struct filter_rule *rule;
		printf("Found a parser: %s\n", parser->filter_str);
		if ((rule = parser->parse(&token, lineno)) == NULL) {
			printf("Error: parser returned NULL\n");
			line_has_error = 1;
			break;
		}

		append_rule(rules, rule);

	}
	printf("Line end\n");

	errors += line_has_error;

	if (line_has_error) {
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

	reset_ruleset(list);
	errors = 0;

	/* open the file */
	if ((fd = open(config_file, O_RDONLY)) < 0) {
		if (errno != ENOENT) {
			syslog(LOG_ERR, "Error opening config file (%s)",
				strerror(errno));
			return 1;
		}
		syslog(LOG_WARNING,
			"Config file %s doesn't exist, skipping", config_file);
		return 0;
	}

	if (fstat(fd, &st) < 0) {
		syslog(LOG_ERR, "Error fstat'ing config file (%s)",
			strerror(errno));
		close(fd);
		return 1;
	}
	if (st.st_uid != 0) {
		syslog(LOG_ERR, "Error - %s isn't owned by root",
			config_file);
		close(fd);
		return 1;
	}
	if ((st.st_mode & S_IWOTH) == S_IWOTH) {
		syslog(LOG_ERR, "Error - %s is world writable",
			config_file);
		close(fd);
		return 1;
	}
	if (!S_ISREG(st.st_mode)) {
		syslog(LOG_ERR, "Error - %s is not a regular file",
			config_file);
		close(fd);
		return 1;
	}

	/* it's ok, read line by line */
	f = fdopen(fd, "rm");
	if (f == NULL) {
		syslog(LOG_ERR, "Error - fdopen failed (%s)",
			strerror(errno));
		close(fd);
		return 1;
	}

	while (get_line(f, buf, sizeof(buf), lineno, config_file)) {
		lineno++;

		struct filter_rules *rules;
		if ((rules = parse_line(buf, lineno)) == NULL)
			continue;

		append_rules(list, rules);
	}
	fclose(f);

	print_list(list);

	return errors;
}

int main(int argc, const char *argv[])
{
	struct sigaction sa;
	char tmp[MAX_AUDIT_MESSAGE_LENGTH];
	int pipefd[2];
	pid_t cpid;

	printf("parse_args()\n");
	if (parse_args(argc, argv))
		return 1;

	printf("load_rules()\n");
	if (load_rules(&list))
		return 1;

	printf("end\n");
	return 0;

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

	if (pipe(pipefd) == -1) {
		syslog(LOG_ERR, "%s is exiting due to not being able to open a pipe\n", argv[0]);
		return -1;
	}

	cpid = fork();
	if (cpid == -1) {
		syslog(LOG_ERR, "%s is exiting due to fork() error\n", argv[0]);
		return -1;
	}

	if (cpid == 0) { // Child reads filtered input

		close(pipefd[1]);
		execve("/usr/local/sbin/audisp-syslog", NULL, NULL);
		syslog(LOG_ERR, "%s execve errored\n", argv[0]);
	} else {
		// Parent forwards data after filters have been applied
		close(pipefd[0]);

		au = auparse_init(AUSOURCE_FEED, 0);
		if (au == NULL)
		{
			syslog(LOG_ERR, "%s is exiting due to auparse_init errors\n", argv[0]);
			return -1;
		}

		auparse_set_eoe_timeout(2);
		printf("pipefd[0]=%d pipefd[1]=%d\n", pipefd[0], pipefd[1]);
		auparse_add_callback(au, handle_event, (void *)&pipefd[1], NULL);

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
				while ((read_size = read(0, tmp,
										MAX_AUDIT_MESSAGE_LENGTH)) > 0)
				{
					auparse_feed(au, tmp, read_size);
				}
			}
			if (read_size == 0) /* EOF */
				break;
		} while (stop == 0);

		auparse_flush_feed(au);
		auparse_destroy(au);
	}

	return 0;
}
