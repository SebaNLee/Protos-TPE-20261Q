#include <check.h>
#include <stdio.h>
#include <string.h>

#include "monitor_test_util.h"
#include "store.h"

/*
 * store_test.c — tests unitarios de monitor_store.
 *
 * Suites: usuarios y auth (SOCKS vs admin), config runtime, sesiones SOCKS,
 * métricas, access log circular y filtros.
 */

START_TEST(test_create_has_no_default_users)
{
    struct monitor_store *store = store_create();
    ck_assert_ptr_nonnull(store);
    ck_assert(!store_user_exists(store, "admin"));
    store_destroy(store);
}
END_TEST

START_TEST(test_config_defaults)
{
    struct monitor_store *store = store_create();
    uint32_t val = 0;

    ck_assert(store_config_get(store, STORE_CFG_TIMEOUT, &val));
    ck_assert_uint_eq(0, val);
    ck_assert(store_config_get(store, STORE_CFG_SESSIONS_CAP, &val));
    ck_assert_uint_eq(STORE_SESSIONS_CAP_DEFAULT, val);
    ck_assert(store_config_get(store, STORE_CFG_IO_BUFFER_SIZE, &val));
    ck_assert_uint_eq(4096, val);

    store_destroy(store);
}
END_TEST

START_TEST(test_socks_validate_ok)
{
    struct monitor_store *store = store_create();
    ck_assert_int_eq(STORE_USER_OK, store_user_add(store, "admin", "admin", true));
    ck_assert(store_user_validate(store, "admin", "admin"));
    store_destroy(store);
}
END_TEST

START_TEST(test_socks_validate_bad_pass)
{
    struct monitor_store *store = store_create();
    ck_assert(!store_user_validate(store, "admin", "wrong"));
    store_destroy(store);
}
END_TEST

START_TEST(test_admin_auth_ok)
{
    struct monitor_store *store = store_create();
    ck_assert_int_eq(STORE_USER_OK, store_user_add(store, "admin", "admin", true));
    ck_assert_int_eq(STORE_AUTH_OK, store_admin_authenticate(store, "admin", "admin"));
    store_destroy(store);
}
END_TEST

START_TEST(test_admin_auth_bad_pass)
{
    struct monitor_store *store = store_create();
    ck_assert_int_eq(STORE_AUTH_INVALID, store_admin_authenticate(store, "admin", "x"));
    store_destroy(store);
}
END_TEST

START_TEST(test_admin_auth_user_role)
{
    struct monitor_store *store = store_create();
    ck_assert_int_eq(STORE_USER_OK, store_user_add(store, "socksuser", "pass", false));
    ck_assert_int_eq(STORE_AUTH_NOT_ADMIN,
                     store_admin_authenticate(store, "socksuser", "pass"));
    store_destroy(store);
}
END_TEST

START_TEST(test_admin_auth_missing_user)
{
    struct monitor_store *store = store_create();
    ck_assert_int_eq(STORE_AUTH_INVALID, store_admin_authenticate(store, "nobody", "x"));
    store_destroy(store);
}
END_TEST

START_TEST(test_add_user)
{
    struct monitor_store *store = store_create();
    ck_assert_int_eq(STORE_USER_OK, store_user_add(store, "alice", "secret", false));
    ck_assert(store_user_validate(store, "alice", "secret"));
    store_destroy(store);
}
END_TEST

START_TEST(test_add_user_admin_role)
{
    struct monitor_store *store = store_create();
    ck_assert_int_eq(STORE_USER_OK, store_user_add(store, "bob", "secret", true));
    ck_assert_int_eq(STORE_AUTH_OK, store_admin_authenticate(store, "bob", "secret"));
    store_destroy(store);
}
END_TEST

START_TEST(test_add_user_duplicate)
{
    struct monitor_store *store = store_create();
    ck_assert_int_eq(STORE_USER_OK, store_user_add(store, "dup", "a", false));
    ck_assert_int_eq(STORE_USER_EXISTS, store_user_add(store, "dup", "b", false));
    store_destroy(store);
}
END_TEST

START_TEST(test_del_user)
{
    struct monitor_store *store = store_create();
    ck_assert_int_eq(STORE_USER_OK, store_user_add(store, "gone", "x", false));
    ck_assert_int_eq(STORE_USER_OK, store_user_delete(store, "gone"));
    ck_assert(!store_user_exists(store, "gone"));
    store_destroy(store);
}
END_TEST

START_TEST(test_del_missing)
{
    struct monitor_store *store = store_create();
    ck_assert_int_eq(STORE_USER_NOT_FOUND, store_user_delete(store, "ghost"));
    store_destroy(store);
}
END_TEST

START_TEST(test_del_last_admin)
{
    struct monitor_store *store = store_create();
    ck_assert_int_eq(STORE_USER_OK, store_user_add(store, "admin", "admin", true));
    ck_assert_int_eq(STORE_USER_LAST_ADMIN, store_user_delete(store, "admin"));
    store_destroy(store);
}
END_TEST

START_TEST(test_set_password)
{
    struct monitor_store *store = store_create();
    ck_assert_int_eq(STORE_USER_OK, store_user_add(store, "carol", "old", false));
    ck_assert_int_eq(STORE_USER_OK, store_user_set_password(store, "carol", "new"));
    ck_assert(!store_user_validate(store, "carol", "old"));
    ck_assert(store_user_validate(store, "carol", "new"));
    store_destroy(store);
}
END_TEST

START_TEST(test_table_full)
{
    struct monitor_store *store = store_create();
    char name[32];

    for (int i = 0; i < STORE_MAX_USERS; i++)
    {
        snprintf(name, sizeof(name), "u%d", i);
        ck_assert_int_eq(STORE_USER_OK, store_user_add(store, name, "p", false));
    }
    ck_assert_int_eq(STORE_USER_TABLE_FULL, store_user_add(store, "overflow", "p", false));
    store_destroy(store);
}
END_TEST

START_TEST(test_config_key_names)
{
    store_config_key key;

    ck_assert(store_config_key_from_name("timeout", &key));
    ck_assert_int_eq(STORE_CFG_TIMEOUT, key);
    ck_assert(store_config_key_from_name("max_connections", &key));
    ck_assert_int_eq(STORE_CFG_SESSIONS_CAP, key);
    ck_assert(store_config_key_from_name("io_buffer_size", &key));
    ck_assert_int_eq(STORE_CFG_IO_BUFFER_SIZE, key);
    ck_assert(!store_config_key_from_name("bogus", &key));
}
END_TEST

START_TEST(test_config_set_valid)
{
    struct monitor_store *store = store_create();
    uint32_t val = 0;

    ck_assert_int_eq(STORE_CFG_OK, store_config_set(store, STORE_CFG_TIMEOUT, 86400));
    ck_assert(store_config_get(store, STORE_CFG_TIMEOUT, &val));
    ck_assert_uint_eq(86400, val);

    ck_assert_int_eq(STORE_CFG_OK, store_config_set(store, STORE_CFG_SESSIONS_CAP, 1));
    ck_assert(store_config_get(store, STORE_CFG_SESSIONS_CAP, &val));
    ck_assert_uint_eq(1, val);

    ck_assert_int_eq(STORE_CFG_OK,
                     store_config_set(store, STORE_CFG_SESSIONS_CAP, STORE_SESSIONS_CAP_MAX));
    ck_assert(store_config_get(store, STORE_CFG_SESSIONS_CAP, &val));
    ck_assert_uint_eq(STORE_SESSIONS_CAP_MAX, val);

    ck_assert_int_eq(STORE_CFG_OK, store_config_set(store, STORE_CFG_IO_BUFFER_SIZE, 1024));
    ck_assert(store_config_get(store, STORE_CFG_IO_BUFFER_SIZE, &val));
    ck_assert_uint_eq(1024, val);

    ck_assert_int_eq(STORE_CFG_OK, store_config_set(store, STORE_CFG_IO_BUFFER_SIZE, 65536));
    ck_assert(store_config_get(store, STORE_CFG_IO_BUFFER_SIZE, &val));
    ck_assert_uint_eq(65536, val);

    store_destroy(store);
}
END_TEST

START_TEST(test_config_set_invalid)
{
    struct monitor_store *store = store_create();

    ck_assert_int_eq(STORE_CFG_INVALID_VALUE,
                     store_config_set(store, STORE_CFG_TIMEOUT, 86401));
    ck_assert_int_eq(STORE_CFG_INVALID_VALUE,
                     store_config_set(store, STORE_CFG_SESSIONS_CAP, 0));
    ck_assert_int_eq(STORE_CFG_INVALID_VALUE,
                     store_config_set(store, STORE_CFG_SESSIONS_CAP, STORE_SESSIONS_CAP_MAX + 1));
    ck_assert_int_eq(STORE_CFG_INVALID_VALUE,
                     store_config_set(store, STORE_CFG_IO_BUFFER_SIZE, 512));
    ck_assert_int_eq(STORE_CFG_INVALID_VALUE,
                     store_config_set(store, STORE_CFG_IO_BUFFER_SIZE, 70000));

    store_destroy(store);
}
END_TEST

START_TEST(test_session_metrics)
{
    struct monitor_store *store = store_create();
    store_metrics m = {0};

    const store_session_id id = store_session_begin(store);
    ck_assert(id != STORE_SESSION_INVALID);

    store_metrics_get(store, &m);
    ck_assert_uint_eq(1, m.total_connections);
    ck_assert_uint_eq(1, m.concurrent_connections);

    store_session_end(store, id);
    store_metrics_get(store, &m);
    ck_assert_uint_eq(1, m.total_connections);
    ck_assert_uint_eq(0, m.concurrent_connections);

    store_destroy(store);
}
END_TEST

START_TEST(test_bytes_metrics)
{
    struct monitor_store *store = store_create();
    store_metrics m = {0};
    const store_session_id id = store_session_begin(store);

    store_session_add_bytes(store, id, 100, 200);
    store_metrics_get(store, &m);
    ck_assert_uint_eq(100, m.bytes_up);
    ck_assert_uint_eq(200, m.bytes_down);

    store_session_end(store, id);
    store_destroy(store);
}
END_TEST

START_TEST(test_sessions_cap_limit)
{
    struct monitor_store *store = store_create();
    store_config_set(store, STORE_CFG_SESSIONS_CAP, 1);

    const store_session_id a = store_session_begin(store);
    ck_assert(a != STORE_SESSION_INVALID);
    ck_assert_int_eq(STORE_SESSION_INVALID, store_session_begin(store));

    store_session_end(store, a);
    store_destroy(store);
}
END_TEST

START_TEST(test_sessions_cap_grow_slots)
{
    struct monitor_store *store = store_create();
    store_session_id ids[1500];

    const uint32_t new_sessions_cap = 1500u;
    ck_assert_int_eq(STORE_CFG_OK,
                     store_config_set(store, STORE_CFG_SESSIONS_CAP, new_sessions_cap));

    for (size_t i = 0; i < new_sessions_cap; i++)
    {
        ids[i] = store_session_begin(store);
        ck_assert(ids[i] != STORE_SESSION_INVALID);
    }
    ck_assert_int_eq(STORE_SESSION_INVALID, store_session_begin(store));

    for (size_t i = 0; i < new_sessions_cap; i++)
    {
        store_session_end(store, ids[i]);
    }
    store_destroy(store);
}
END_TEST

START_TEST(test_sessions_cap_lower_below_active)
{
    struct monitor_store *store = store_create();

    const store_session_id a = store_session_begin(store);
    const store_session_id b = store_session_begin(store);
    ck_assert(a != STORE_SESSION_INVALID);
    ck_assert(b != STORE_SESSION_INVALID);

    ck_assert_int_eq(STORE_CFG_INVALID_VALUE,
                     store_config_set(store, STORE_CFG_SESSIONS_CAP, 1));

    store_session_end(store, a);
    store_session_end(store, b);
    store_destroy(store);
}
END_TEST

typedef struct
{
    size_t count;
} session_count;

static bool count_session(const store_active_session *s, void *ctx)
{
    (void)s;
    session_count *c = ctx;
    c->count++;
    return true;
}

START_TEST(test_connections_list)
{
    struct monitor_store *store = store_create();
    session_count cnt = {0};

    const store_session_id a = store_session_begin(store);
    const store_session_id b = store_session_begin(store);
    store_session_set_user(store, a, "u1");
    store_session_set_user(store, b, "u2");

    store_sessions_foreach(store, count_session, &cnt);
    ck_assert_uint_eq(2, cnt.count);

    store_session_end(store, a);
    store_session_end(store, b);
    store_destroy(store);
}
END_TEST

START_TEST(test_session_phases)
{
    ck_assert_str_eq("AUTH", store_session_phase_str(STORE_SESSION_AUTH));
    ck_assert_str_eq("CONNECTING", store_session_phase_str(STORE_SESSION_CONNECTING));
    ck_assert_str_eq("RELAY", store_session_phase_str(STORE_SESSION_RELAY));
    ck_assert_str_eq("DONE", store_session_phase_str(STORE_SESSION_DONE));
}
END_TEST

START_TEST(test_session_failed)
{
    struct monitor_store *store = store_create();
    mt_log_list logs = {0};

    const store_session_id id = store_session_begin(store);
    store_session_set_user(store, id, "failuser");
    store_session_set_dest(store, id, "bad.host", 80);
    store_session_mark_failed(store, id);

    store_log_foreach(store, NULL, mt_collect_log, &logs);
    ck_assert(logs.count > 0);
    ck_assert_str_eq("FAILED", store_log_state_str(STORE_LOG_FAILED));

    store_destroy(store);
}
END_TEST

START_TEST(test_session_end)
{
    struct monitor_store *store = store_create();
    const store_session_id id = store_session_begin(store);

    store_session_set_user(store, id, "doneuser");
    store_log_id log_id = store_session_set_dest(store, id, "ok.host", 443);
    ck_assert(log_id != STORE_LOG_INVALID);
    store_session_add_bytes(store, id, 10, 20);
    store_session_end(store, id);

    mt_log_list logs = {0};
    store_log_foreach(store, "doneuser", mt_collect_log, &logs);
    ck_assert_uint_eq(1, logs.count);

    store_destroy(store);
}
END_TEST

START_TEST(test_log_order)
{
    struct monitor_store *store = store_create();

    const store_session_id a = store_session_begin(store);
    store_session_set_user(store, a, "u");
    store_session_set_dest(store, a, "first.host", 80);
    store_session_end(store, a);

    const store_session_id b = store_session_begin(store);
    store_session_set_user(store, b, "u");
    store_session_set_dest(store, b, "second.host", 80);
    store_session_end(store, b);

    mt_log_list logs = {0};
    store_log_foreach(store, NULL, mt_collect_log, &logs);
    ck_assert_uint_ge(logs.count, 2);
    ck_assert_str_eq("second.host", logs.hosts[0]);
    ck_assert_str_eq("first.host", logs.hosts[1]);

    store_destroy(store);
}
END_TEST

START_TEST(test_log_filter)
{
    struct monitor_store *store = store_create();

    const store_session_id a = store_session_begin(store);
    store_session_set_user(store, a, "alice");
    store_session_set_dest(store, a, "a.host", 80);
    store_session_end(store, a);

    const store_session_id b = store_session_begin(store);
    store_session_set_user(store, b, "bob");
    store_session_set_dest(store, b, "b.host", 80);
    store_session_end(store, b);

    mt_log_list logs = {0};
    store_log_foreach(store, "alice", mt_collect_log, &logs);
    ck_assert_uint_eq(1, logs.count);
    ck_assert_str_eq("a.host", logs.hosts[0]);

    store_destroy(store);
}
END_TEST

static bool collect_one_log(const store_log_entry *entry, void *ctx)
{
    (void)entry;
    size_t *n = ctx;
    (*n)++;
    return true;
}

START_TEST(test_log_circular)
{
    /* Al superar STORE_LOG_CAPACITY, la entrada más antigua se pisa */
    struct monitor_store *store = store_create();
    size_t seen = 0;

    for (size_t i = 0; i < STORE_LOG_CAPACITY + 1; i++)
    {
        const store_session_id id = store_session_begin(store);
        store_session_set_user(store, id, "u");
        char host[32];
        snprintf(host, sizeof(host), "h%zu.host", i);
        store_session_set_dest(store, id, host, 80);
        store_session_end(store, id);
    }

    store_log_foreach(store, NULL, collect_one_log, &seen);
    ck_assert_uint_eq(STORE_LOG_CAPACITY, seen);

    store_destroy(store);
}
END_TEST

START_TEST(test_session_ttl_expired)
{
    struct monitor_store *store = store_create();
    mt_log_list logs = {0};

    const store_session_id id = store_session_begin(store);
    store_session_set_user(store, id, "idleuser");
    store_log_id log_id = store_session_set_dest(store, id, "idle.host", 80);
    ck_assert(log_id != STORE_LOG_INVALID);
    store_session_add_bytes(store, id, 5, 15);
    store_session_mark_ttl_expired(store, id);

    store_log_foreach(store, NULL, mt_collect_log, &logs);
    ck_assert_uint_eq(1, logs.count);
    ck_assert_str_eq("TTL_EXPIRED", store_log_state_str(STORE_LOG_TTL_EXPIRED));

    store_destroy(store);
}
END_TEST

START_TEST(test_log_states)
{
    ck_assert_str_eq("CONNECTED", store_log_state_str(STORE_LOG_CONNECTED));
    ck_assert_str_eq("CLOSED", store_log_state_str(STORE_LOG_CLOSED));
    ck_assert_str_eq("FAILED", store_log_state_str(STORE_LOG_FAILED));
    ck_assert_str_eq("TTL_EXPIRED", store_log_state_str(STORE_LOG_TTL_EXPIRED));
}
END_TEST

START_TEST(test_add_user_socks_auth)
{
    struct monitor_store *store = store_create();
    ck_assert_int_eq(STORE_USER_OK, store_user_add(store, "newbie", "pw", false));
    ck_assert(store_user_validate(store, "newbie", "pw"));
    store_destroy(store);
}
END_TEST

Suite *monitor_store_suite(void)
{
    Suite *s = suite_create("monitor_store");

    TCase *tc = tcase_create("store");
    tcase_add_test(tc, test_create_has_no_default_users);
    tcase_add_test(tc, test_config_defaults);
    tcase_add_test(tc, test_socks_validate_ok);
    tcase_add_test(tc, test_socks_validate_bad_pass);
    tcase_add_test(tc, test_admin_auth_ok);
    tcase_add_test(tc, test_admin_auth_bad_pass);
    tcase_add_test(tc, test_admin_auth_user_role);
    tcase_add_test(tc, test_admin_auth_missing_user);
    tcase_add_test(tc, test_add_user);
    tcase_add_test(tc, test_add_user_admin_role);
    tcase_add_test(tc, test_add_user_duplicate);
    tcase_add_test(tc, test_del_user);
    tcase_add_test(tc, test_del_missing);
    tcase_add_test(tc, test_del_last_admin);
    tcase_add_test(tc, test_set_password);
    tcase_add_test(tc, test_table_full);
    tcase_add_test(tc, test_config_key_names);
    tcase_add_test(tc, test_config_set_valid);
    tcase_add_test(tc, test_config_set_invalid);
    tcase_add_test(tc, test_session_metrics);
    tcase_add_test(tc, test_bytes_metrics);
    tcase_add_test(tc, test_sessions_cap_limit);
    tcase_add_test(tc, test_sessions_cap_grow_slots);
    tcase_add_test(tc, test_sessions_cap_lower_below_active);
    tcase_add_test(tc, test_connections_list);
    tcase_add_test(tc, test_session_phases);
    tcase_add_test(tc, test_session_failed);
    tcase_add_test(tc, test_session_end);
    tcase_add_test(tc, test_session_ttl_expired);
    tcase_add_test(tc, test_log_order);
    tcase_add_test(tc, test_log_filter);
    tcase_add_test(tc, test_log_circular);
    tcase_add_test(tc, test_log_states);
    tcase_add_test(tc, test_add_user_socks_auth);
    suite_add_tcase(s, tc);

    return s;
}

int main(void)
{
    SRunner *sr = srunner_create(monitor_store_suite());
    srunner_run_all(sr, CK_NORMAL);
    const int n = srunner_ntests_failed(sr);
    srunner_free(sr);
    return n == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
