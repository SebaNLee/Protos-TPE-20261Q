#include <check.h>
#include <stdlib.h>
#include <string.h>

#include "auth.h"

#include "server/monitor/store.h"

static socks_auth_status feed_bytes(socks_auth_parser *parser,
                                    const uint8_t *bytes,
                                    size_t len)
{
    socks_auth_status status = SOCKS_AUTH_NEED_MORE;

    for (size_t i = 0; i < len; i++)
    {
        status = socks_auth_parser_feed(parser, bytes[i]);
        if (status != SOCKS_AUTH_NEED_MORE)
        {
            break;
        }
    }

    return status;
}

START_TEST(test_auth_parse_admin)
{
    struct monitor_store *store = store_create();
    ck_assert_ptr_nonnull(store);
    ck_assert_int_eq(STORE_USER_OK, store_user_add(store, "admin", "admin", true));

    socks_auth_parser parser;
    socks_auth_parser_init(&parser);

    const uint8_t msg[] = {
        0x01, 0x05, 'a', 'd', 'm', 'i', 'n', 0x05, 'a', 'd', 'm', 'i', 'n'};

    ck_assert_int_eq(SOCKS_AUTH_PARSED, feed_bytes(&parser, msg, sizeof(msg)));
    ck_assert_uint_eq(5, socks_auth_username_len(&parser));
    ck_assert_uint_eq(5, socks_auth_password_len(&parser));
    ck_assert_mem_eq("admin", socks_auth_username(&parser), 5);
    ck_assert_mem_eq("admin", socks_auth_password(&parser), 5);
    ck_assert(socks_auth_validate(&parser, store));

    store_destroy(store);
}
END_TEST

START_TEST(test_auth_validate_wrong_password)
{
    struct monitor_store *store = store_create();
    ck_assert_ptr_nonnull(store);

    socks_auth_parser parser;
    socks_auth_parser_init(&parser);

    const uint8_t msg[] = {
        0x01, 0x05, 'a', 'd', 'm', 'i', 'n', 0x04, 'x', 'x', 'x', 'x'};

    ck_assert_int_eq(SOCKS_AUTH_PARSED, feed_bytes(&parser, msg, sizeof(msg)));
    ck_assert(!socks_auth_validate(&parser, store));

    store_destroy(store);
}
END_TEST

START_TEST(test_auth_reject_bad_version)
{
    socks_auth_parser parser;
    socks_auth_parser_init(&parser);

    ck_assert_int_eq(SOCKS_AUTH_REJECT, socks_auth_parser_feed(&parser, 0x02));
}
END_TEST

START_TEST(test_auth_reject_empty_username)
{
    socks_auth_parser parser;
    socks_auth_parser_init(&parser);

    ck_assert_int_eq(SOCKS_AUTH_NEED_MORE, socks_auth_parser_feed(&parser, 0x01));
    ck_assert_int_eq(SOCKS_AUTH_REJECT, socks_auth_parser_feed(&parser, 0x00));
}
END_TEST

Suite *socks5_auth_suite(void)
{
    Suite *s = suite_create("socks5_auth");

    TCase *tc = tcase_create("parser");
    tcase_add_test(tc, test_auth_parse_admin);
    tcase_add_test(tc, test_auth_validate_wrong_password);
    tcase_add_test(tc, test_auth_reject_bad_version);
    tcase_add_test(tc, test_auth_reject_empty_username);
    suite_add_tcase(s, tc);

    return s;
}

int main(void)
{
    int number_failed = 0;
    SRunner *sr = srunner_create(socks5_auth_suite());

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return number_failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
