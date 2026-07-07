#include <check.h>
#include <stdio.h>
#include <string.h>

#include "monitor_commands.h"
#include "monitor_test_util.h"

/*
 * monitor_commands_test.c — tests unitarios del protocolo ChugusMonitor.
 *
 * Suites: greeting, auth (STM), CRLF/partial lines, pipelining, comandos CRUD,
 * CONFIG, ACCESS_LOG, HELP, QUIT, EOF sin '\n' final.
 */

static void setup_commands(struct monitor_commands_session *cmds, struct monitor_store *store)
{
    store_user_add(store, "admin", "admin", true);
    monitor_commands_session_init(cmds, store);
}

START_TEST(test_greeting)
{
    struct monitor_store *store = store_create();
    struct monitor_commands_session proto;
    setup_commands(&proto, store);
    char out[MT_DRAIN_SIZE];

    monitor_commands_queue_greeting(&proto);
    mt_drain_all(&proto, out, sizeof(out));
    ck_assert_str_eq(MONITOR_COMMANDS_GREETING, out);

    store_destroy(store);
}
END_TEST

START_TEST(test_crlf)
{
    /* Acepta '\r\n' además de '\n' como terminador de línea */
    struct monitor_store *store = store_create();
    struct monitor_commands_session proto;
    setup_commands(&proto, store);
    char out[MT_DRAIN_SIZE];

    mt_auth_admin(&proto);
    mt_feed(&proto, "STATS\r\n");
    mt_drain_all(&proto, out, sizeof(out));
    mt_assert_has(out, "total_connections=");

    store_destroy(store);
}
END_TEST

START_TEST(test_empty_line)
{
    struct monitor_store *store = store_create();
    struct monitor_commands_session proto;
    setup_commands(&proto, store);
    char out[MT_DRAIN_SIZE];

    monitor_commands_queue_greeting(&proto);
    mt_feed(&proto, "\n");
    mt_drain_all(&proto, out, sizeof(out));
    ck_assert_str_eq(MONITOR_COMMANDS_GREETING, out);

    store_destroy(store);
}
END_TEST

START_TEST(test_partial_line)
{
    /* Comando partido en varios feed(): no se ejecuta hasta el '\n' */
    struct monitor_store *store = store_create();
    struct monitor_commands_session proto;
    setup_commands(&proto, store);
    char out[MT_DRAIN_SIZE];

    mt_feed(&proto, "AUT");
    mt_drain_all(&proto, out, sizeof(out));
    ck_assert_str_eq("", out);

    mt_feed(&proto, "H admin admin\n");
    mt_drain_all(&proto, out, sizeof(out));
    mt_assert_has(out, "+OK\n");

    store_destroy(store);
}
END_TEST

START_TEST(test_line_too_long)
{
    struct monitor_store *store = store_create();
    struct monitor_commands_session proto;
    setup_commands(&proto, store);
    char out[MT_DRAIN_SIZE];
    char line[MONITOR_LINE_MAX + 2];

    memset(line, 'A', MONITOR_LINE_MAX + 1);
    line[MONITOR_LINE_MAX + 1] = '\0';

    mt_feed(&proto, line);
    mt_drain_all(&proto, out, sizeof(out));
    mt_assert_has(out, "-ERR line too long\n");

    store_destroy(store);
}
END_TEST

START_TEST(test_pipelining)
{
    /* Varios comandos en un solo feed: respuestas en el mismo orden */
    struct monitor_store *store = store_create();
    struct monitor_commands_session proto;
    setup_commands(&proto, store);
    char out[MT_DRAIN_SIZE];

    mt_feed(&proto, "AUTH admin admin\nSTATS\nCONNECTIONS\n");
    mt_drain_all(&proto, out, sizeof(out));
    mt_assert_has(out, "+OK\n");
    mt_assert_has(out, "total_connections=");
    mt_assert_has(out, "concurrent_connections=");

    store_destroy(store);
}
END_TEST

START_TEST(test_stats_before_auth)
{
    struct monitor_store *store = store_create();
    struct monitor_commands_session proto;
    setup_commands(&proto, store);
    char out[MT_DRAIN_SIZE];

    mt_feed(&proto, "STATS\n");
    mt_drain_all(&proto, out, sizeof(out));
    mt_assert_has(out, "-ERR not authenticated\n");

    store_destroy(store);
}
END_TEST

START_TEST(test_auth_ok)
{
    struct monitor_store *store = store_create();
    struct monitor_commands_session proto;
    setup_commands(&proto, store);
    char out[MT_DRAIN_SIZE];

    mt_auth_admin(&proto);
    mt_drain_all(&proto, out, sizeof(out));
    mt_assert_has(out, "+OK\n");
    ck_assert_int_eq(MONITOR_ST_AUTHENTICATED, proto.state);

    store_destroy(store);
}
END_TEST

START_TEST(test_auth_bad_pass)
{
    struct monitor_store *store = store_create();
    struct monitor_commands_session proto;
    setup_commands(&proto, store);
    char out[MT_DRAIN_SIZE];

    mt_feed(&proto, "AUTH admin wrong\n");
    mt_drain_all(&proto, out, sizeof(out));
    mt_assert_has(out, "-ERR invalid credentials\n");

    store_destroy(store);
}
END_TEST

START_TEST(test_auth_not_admin)
{
    struct monitor_store *store = store_create();
    struct monitor_commands_session proto;
    setup_commands(&proto, store);
    char out[MT_DRAIN_SIZE];

    store_user_add(store, "socks", "pass", false);
    mt_feed(&proto, "AUTH socks pass\n");
    mt_drain_all(&proto, out, sizeof(out));
    mt_assert_has(out, "-ERR not admin\n");

    store_destroy(store);
}
END_TEST

START_TEST(test_auth_syntax)
{
    struct monitor_store *store = store_create();
    struct monitor_commands_session proto;
    setup_commands(&proto, store);
    char out[MT_DRAIN_SIZE];

    mt_feed(&proto, "AUTH admin\n");
    mt_drain_all(&proto, out, sizeof(out));
    mt_assert_has(out, "-ERR syntax error\n");

    store_destroy(store);
}
END_TEST

START_TEST(test_auth_twice)
{
    struct monitor_store *store = store_create();
    struct monitor_commands_session proto;
    setup_commands(&proto, store);
    char out[MT_DRAIN_SIZE];

    mt_auth_admin(&proto);
    mt_feed(&proto, "AUTH admin admin\n");
    mt_drain_all(&proto, out, sizeof(out));
    mt_assert_has(out, "-ERR already authenticated\n");

    store_destroy(store);
}
END_TEST

START_TEST(test_stats)
{
    struct monitor_store *store = store_create();
    struct monitor_commands_session proto;
    setup_commands(&proto, store);
    char out[MT_DRAIN_SIZE];

    mt_sim_session(store, "u", "example.com", 443, 0, 0, true);
    mt_auth_admin(&proto);
    mt_feed(&proto, "STATS\n");
    mt_drain_all(&proto, out, sizeof(out));
    mt_assert_has(out, "total_connections=1");
    mt_assert_has(out, "concurrent_connections=0");

    store_destroy(store);
}
END_TEST

START_TEST(test_connections_empty)
{
    struct monitor_store *store = store_create();
    struct monitor_commands_session proto;
    setup_commands(&proto, store);
    char out[MT_DRAIN_SIZE];

    mt_auth_admin(&proto);
    mt_feed(&proto, "CONNECTIONS\n");
    mt_drain_all(&proto, out, sizeof(out));
    mt_assert_has(out, "+OK\n");

    store_destroy(store);
}
END_TEST

START_TEST(test_connections_active)
{
    struct monitor_store *store = store_create();
    struct monitor_commands_session proto;
    setup_commands(&proto, store);
    char out[MT_DRAIN_SIZE];

    const store_session_id sid =
        mt_sim_session(store, "alice", "host.test", 8080, 5, 10, false);
    mt_auth_admin(&proto);
    mt_feed(&proto, "CONNECTIONS\n");
    mt_drain_all(&proto, out, sizeof(out));
    mt_assert_has(out, "alice host.test:8080");
    mt_assert_has(out, "RELAY");

    store_session_end(store, sid);
    store_destroy(store);
}
END_TEST

START_TEST(test_users_empty)
{
    struct monitor_store *store = store_create();
    struct monitor_commands_session proto;
    setup_commands(&proto, store);
    char out[MT_DRAIN_SIZE];

    mt_auth_admin(&proto);
    mt_feed(&proto, "USERS\n");
    mt_drain_all(&proto, out, sizeof(out));
    mt_assert_has(out, "+OK\n");

    store_destroy(store);
}
END_TEST

START_TEST(test_users_active)
{
    struct monitor_store *store = store_create();
    struct monitor_commands_session proto;
    setup_commands(&proto, store);
    char out[MT_DRAIN_SIZE];

    mt_sim_session(store, "bob", "x.com", 80, 0, 0, false);
    mt_auth_admin(&proto);
    mt_feed(&proto, "USERS\n");
    mt_drain_all(&proto, out, sizeof(out));
    mt_assert_has(out, "+OK bob\n");

    store_destroy(store);
}
END_TEST

START_TEST(test_config_ok)
{
    struct monitor_store *store = store_create();
    struct monitor_commands_session proto;
    setup_commands(&proto, store);
    char out[MT_DRAIN_SIZE];
    uint32_t val = 0;

    mt_auth_admin(&proto);
    mt_feed(&proto, "CONFIG timeout 30\n");
    mt_drain_all(&proto, out, sizeof(out));
    mt_assert_has(out, "+OK\n");
    ck_assert(store_config_get(store, STORE_CFG_TIMEOUT, &val));
    ck_assert_uint_eq(30, val);

    store_destroy(store);
}
END_TEST

START_TEST(test_config_unknown)
{
    struct monitor_store *store = store_create();
    struct monitor_commands_session proto;
    setup_commands(&proto, store);
    char out[MT_DRAIN_SIZE];

    mt_auth_admin(&proto);
    mt_feed(&proto, "CONFIG foo 1\n");
    mt_drain_all(&proto, out, sizeof(out));
    mt_assert_has(out, "-ERR unknown param\n");

    store_destroy(store);
}
END_TEST

START_TEST(test_config_bad_value)
{
    struct monitor_store *store = store_create();
    struct monitor_commands_session proto;
    setup_commands(&proto, store);
    char out[MT_DRAIN_SIZE];

    mt_auth_admin(&proto);
    mt_feed(&proto, "CONFIG timeout 99999\n");
    mt_drain_all(&proto, out, sizeof(out));
    mt_assert_has(out, "-ERR invalid value\n");

    store_destroy(store);
}
END_TEST

START_TEST(test_access_log_all)
{
    struct monitor_store *store = store_create();
    struct monitor_commands_session proto;
    setup_commands(&proto, store);
    char out[MT_DRAIN_SIZE];

    mt_sim_session(store, "loguser", "site.org", 443, 0, 0, true);
    mt_auth_admin(&proto);
    mt_feed(&proto, "ACCESS_LOG\n");
    mt_drain_all(&proto, out, sizeof(out));
    mt_assert_has(out, "Access log for all users:");
    mt_assert_has(out, "loguser: site.org:443");

    store_destroy(store);
}
END_TEST

START_TEST(test_access_log_filter)
{
    struct monitor_store *store = store_create();
    struct monitor_commands_session proto;
    setup_commands(&proto, store);
    char out[MT_DRAIN_SIZE];

    store_user_add(store, "filterme", "p", false);
    mt_sim_session(store, "filterme", "only.me", 80, 0, 0, true);
    mt_auth_admin(&proto);
    mt_feed(&proto, "ACCESS_LOG filterme\n");
    mt_drain_all(&proto, out, sizeof(out));
    mt_assert_has(out, "Access log for user filterme:");
    mt_assert_has(out, "filterme: only.me:80");

    store_destroy(store);
}
END_TEST

START_TEST(test_access_log_missing_user)
{
    struct monitor_store *store = store_create();
    struct monitor_commands_session proto;
    setup_commands(&proto, store);
    char out[MT_DRAIN_SIZE];

    mt_auth_admin(&proto);
    mt_feed(&proto, "ACCESS_LOG nobody\n");
    mt_drain_all(&proto, out, sizeof(out));
    mt_assert_has(out, "-ERR user not found\n");

    store_destroy(store);
}
END_TEST

START_TEST(test_add_user)
{
    struct monitor_store *store = store_create();
    struct monitor_commands_session proto;
    setup_commands(&proto, store);
    char out[MT_DRAIN_SIZE];

    mt_auth_admin(&proto);
    mt_feed(&proto, "ADD_USER newone secret\n");
    mt_drain_all(&proto, out, sizeof(out));
    mt_assert_has(out, "+OK\n");
    ck_assert(store_user_validate(store, "newone", "secret"));

    store_destroy(store);
}
END_TEST

START_TEST(test_add_user_exists)
{
    struct monitor_store *store = store_create();
    struct monitor_commands_session proto;
    setup_commands(&proto, store);
    char out[MT_DRAIN_SIZE];

    store_user_add(store, "dup", "x", false);
    mt_auth_admin(&proto);
    mt_feed(&proto, "ADD_USER dup y\n");
    mt_drain_all(&proto, out, sizeof(out));
    mt_assert_has(out, "-ERR user exists\n");

    store_destroy(store);
}
END_TEST

START_TEST(test_del_user)
{
    struct monitor_store *store = store_create();
    struct monitor_commands_session proto;
    setup_commands(&proto, store);
    char out[MT_DRAIN_SIZE];

    store_user_add(store, "todel", "x", false);
    mt_auth_admin(&proto);
    mt_feed(&proto, "DEL_USER todel\n");
    mt_drain_all(&proto, out, sizeof(out));
    mt_assert_has(out, "+OK\n");
    ck_assert(!store_user_exists(store, "todel"));

    store_destroy(store);
}
END_TEST

START_TEST(test_del_last_admin)
{
    struct monitor_store *store = store_create();
    struct monitor_commands_session proto;
    setup_commands(&proto, store);
    char out[MT_DRAIN_SIZE];

    mt_auth_admin(&proto);
    mt_feed(&proto, "DEL_USER admin\n");
    mt_drain_all(&proto, out, sizeof(out));
    mt_assert_has(out, "-ERR cannot delete last admin\n");

    store_destroy(store);
}
END_TEST

START_TEST(test_set_password)
{
    struct monitor_store *store = store_create();
    struct monitor_commands_session proto;
    setup_commands(&proto, store);
    char out[MT_DRAIN_SIZE];

    store_user_add(store, "chpass", "old", false);
    mt_auth_admin(&proto);
    mt_feed(&proto, "SET_PASSWORD chpass new\n");
    mt_drain_all(&proto, out, sizeof(out));
    mt_assert_has(out, "+OK\n");
    ck_assert(store_user_validate(store, "chpass", "new"));

    store_destroy(store);
}
END_TEST

START_TEST(test_set_password_missing)
{
    struct monitor_store *store = store_create();
    struct monitor_commands_session proto;
    setup_commands(&proto, store);
    char out[MT_DRAIN_SIZE];

    mt_auth_admin(&proto);
    mt_feed(&proto, "SET_PASSWORD ghost x\n");
    mt_drain_all(&proto, out, sizeof(out));
    mt_assert_has(out, "-ERR user not found\n");

    store_destroy(store);
}
END_TEST

START_TEST(test_help_before_auth)
{
    struct monitor_store *store = store_create();
    struct monitor_commands_session proto;
    setup_commands(&proto, store);
    char out[MT_DRAIN_SIZE];

    mt_feed(&proto, "HELP\n");
    mt_drain_all(&proto, out, sizeof(out));
    mt_assert_has(out, "Available commands:");
    mt_assert_has(out, "AUTH username password");
    ck_assert_int_eq(MONITOR_ST_AWAIT_AUTH, proto.state);

    store_destroy(store);
}
END_TEST

START_TEST(test_help)
{
    struct monitor_store *store = store_create();
    struct monitor_commands_session proto;
    setup_commands(&proto, store);
    char out[MT_DRAIN_SIZE];

    mt_auth_admin(&proto);
    mt_feed(&proto, "HELP\n");
    mt_drain_all(&proto, out, sizeof(out));
    mt_assert_has(out, "Available commands:");
    mt_assert_has(out, "ADD_USER");

    store_destroy(store);
}
END_TEST

START_TEST(test_help_stats)
{
    struct monitor_store *store = store_create();
    struct monitor_commands_session proto;
    setup_commands(&proto, store);
    char out[MT_DRAIN_SIZE];

    mt_auth_admin(&proto);
    mt_feed(&proto, "HELP STATS\n");
    mt_drain_all(&proto, out, sizeof(out));
    mt_assert_has(out, "STATS — show server metrics");

    store_destroy(store);
}
END_TEST

START_TEST(test_help_connections)
{
    struct monitor_store *store = store_create();
    struct monitor_commands_session proto;
    setup_commands(&proto, store);
    char out[MT_DRAIN_SIZE];

    mt_feed(&proto, "HELP CONNECTIONS\n");
    mt_drain_all(&proto, out, sizeof(out));
    mt_assert_has(out, "CONNECTIONS — list active SOCKS sessions");

    store_destroy(store);
}
END_TEST

START_TEST(test_help_users)
{
    struct monitor_store *store = store_create();
    struct monitor_commands_session proto;
    setup_commands(&proto, store);
    char out[MT_DRAIN_SIZE];

    mt_feed(&proto, "HELP USERS\n");
    mt_drain_all(&proto, out, sizeof(out));
    mt_assert_has(out, "USERS — list usernames with active SOCKS connections");

    store_destroy(store);
}
END_TEST

START_TEST(test_help_unknown)
{
    struct monitor_store *store = store_create();
    struct monitor_commands_session proto;
    setup_commands(&proto, store);
    char out[MT_DRAIN_SIZE];

    mt_auth_admin(&proto);
    mt_feed(&proto, "HELP NOPE\n");
    mt_drain_all(&proto, out, sizeof(out));
    mt_assert_has(out, "-ERR unknown command\n");

    store_destroy(store);
}
END_TEST

START_TEST(test_quit)
{
    struct monitor_store *store = store_create();
    struct monitor_commands_session proto;
    setup_commands(&proto, store);
    char out[MT_DRAIN_SIZE];

    mt_auth_admin(&proto);
    mt_feed(&proto, "QUIT\n");
    mt_drain_all(&proto, out, sizeof(out));
    mt_assert_has(out, "+OK\n");
    ck_assert(proto.close_after_flush);

    store_destroy(store);
}
END_TEST

START_TEST(test_unknown_cmd)
{
    struct monitor_store *store = store_create();
    struct monitor_commands_session proto;
    setup_commands(&proto, store);
    char out[MT_DRAIN_SIZE];

    mt_auth_admin(&proto);
    mt_feed(&proto, "FOOBAR\n");
    mt_drain_all(&proto, out, sizeof(out));
    mt_assert_has(out, "-ERR unknown command\n");

    store_destroy(store);
}
END_TEST

START_TEST(test_eof_partial)
{
    /* EOF sin '\n' final: flush_on_eof debe procesar la línea pendiente */
    struct monitor_store *store = store_create();
    struct monitor_commands_session proto;
    setup_commands(&proto, store);
    char out[MT_DRAIN_SIZE];

    mt_auth_admin(&proto);
    mt_drain_all(&proto, out, sizeof(out));
    mt_feed(&proto, "STATS");
    monitor_commands_flush_on_eof(&proto);
    mt_drain_all(&proto, out, sizeof(out));
    mt_assert_has(out, "total_connections=");

    store_destroy(store);
}
END_TEST

Suite *monitor_commands_suite(void)
{
    Suite *s = suite_create("monitor_commands");

    TCase *tc = tcase_create("commands");
    tcase_add_test(tc, test_greeting);
    tcase_add_test(tc, test_crlf);
    tcase_add_test(tc, test_empty_line);
    tcase_add_test(tc, test_partial_line);
    tcase_add_test(tc, test_line_too_long);
    tcase_add_test(tc, test_pipelining);
    tcase_add_test(tc, test_stats_before_auth);
    tcase_add_test(tc, test_auth_ok);
    tcase_add_test(tc, test_auth_bad_pass);
    tcase_add_test(tc, test_auth_not_admin);
    tcase_add_test(tc, test_auth_syntax);
    tcase_add_test(tc, test_auth_twice);
    tcase_add_test(tc, test_stats);
    tcase_add_test(tc, test_connections_empty);
    tcase_add_test(tc, test_connections_active);
    tcase_add_test(tc, test_users_empty);
    tcase_add_test(tc, test_users_active);
    tcase_add_test(tc, test_config_ok);
    tcase_add_test(tc, test_config_unknown);
    tcase_add_test(tc, test_config_bad_value);
    tcase_add_test(tc, test_access_log_all);
    tcase_add_test(tc, test_access_log_filter);
    tcase_add_test(tc, test_access_log_missing_user);
    tcase_add_test(tc, test_add_user);
    tcase_add_test(tc, test_add_user_exists);
    tcase_add_test(tc, test_del_user);
    tcase_add_test(tc, test_del_last_admin);
    tcase_add_test(tc, test_set_password);
    tcase_add_test(tc, test_set_password_missing);
    tcase_add_test(tc, test_help_before_auth);
    tcase_add_test(tc, test_help);
    tcase_add_test(tc, test_help_stats);
    tcase_add_test(tc, test_help_connections);
    tcase_add_test(tc, test_help_users);
    tcase_add_test(tc, test_help_unknown);
    tcase_add_test(tc, test_quit);
    tcase_add_test(tc, test_unknown_cmd);
    tcase_add_test(tc, test_eof_partial);
    suite_add_tcase(s, tc);

    return s;
}

int main(void)
{
    SRunner *sr = srunner_create(monitor_commands_suite());
    srunner_run_all(sr, CK_NORMAL);
    const int n = srunner_ntests_failed(sr);
    srunner_free(sr);
    return n == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
