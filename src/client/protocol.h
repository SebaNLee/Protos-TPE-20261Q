#ifndef CLIENT_PROTOCOL_H
#define CLIENT_PROTOCOL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define LINE_BUF_SIZE 4096
#define MAX_RESP_LINES 512
#define MAX_RESP_LINE_LEN 256

#define cmd_connections(fd, l, m) cmd_list(fd, "CONNECTIONS\n", l, m)
#define cmd_users(fd, l, m) cmd_list(fd, "USERS\n", l, m)

int connect_server(const char *host, uint16_t port);
int read_line(int fd, char *buf, size_t buf_len);

bool cmd_simple(int fd, const char *cmd, char *err, size_t err_sz);
bool cmd_auth(int fd, const char *user, const char *pass, char *err, size_t err_sz);
bool cmd_stats(int fd, uint64_t *total, uint64_t *conc, uint64_t *bytes_up, uint64_t *bytes_down);
int cmd_list(int fd, const char *cmd, char lines[][MAX_RESP_LINE_LEN], int max_lines);
int cmd_access_log(int fd, const char *filter, char lines[][MAX_RESP_LINE_LEN], int max_lines);
bool cmd_config(int fd, const char *param, uint32_t value, char *err, size_t err_sz);
bool cmd_add_user(int fd, const char *user, const char *pass, bool admin, char *err, size_t err_sz);
bool cmd_del_user(int fd, const char *user, char *err, size_t err_sz);
bool cmd_set_password(int fd, const char *user, const char *pass, char *err, size_t err_sz);
void cmd_quit(int fd);

#endif
