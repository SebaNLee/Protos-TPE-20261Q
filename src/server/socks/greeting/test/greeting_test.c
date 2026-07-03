#include <check.h>
#include <stdlib.h>

#include "greeting.h"

START_TEST(test_greeting_accept_userpass)
{
    socks_greeting_parser parser;
    socks_greeting_parser_init(&parser);

    ck_assert_int_eq(SOCKS_GREETING_NEED_MORE, socks_greeting_parser_feed(&parser, 0x05));
    ck_assert_int_eq(SOCKS_GREETING_NEED_MORE, socks_greeting_parser_feed(&parser, 0x01));
    ck_assert_int_eq(SOCKS_GREETING_ACCEPT, socks_greeting_parser_feed(&parser, 0x02));
}
END_TEST

START_TEST(test_greeting_accept_userpass_among_many)
{
    socks_greeting_parser parser;
    socks_greeting_parser_init(&parser);

    ck_assert_int_eq(SOCKS_GREETING_NEED_MORE, socks_greeting_parser_feed(&parser, 0x05));
    ck_assert_int_eq(SOCKS_GREETING_NEED_MORE, socks_greeting_parser_feed(&parser, 0x02));
    ck_assert_int_eq(SOCKS_GREETING_NEED_MORE, socks_greeting_parser_feed(&parser, 0x00));
    ck_assert_int_eq(SOCKS_GREETING_ACCEPT, socks_greeting_parser_feed(&parser, 0x02));
}
END_TEST

START_TEST(test_greeting_reject_bad_version)
{
    socks_greeting_parser parser;
    socks_greeting_parser_init(&parser);

    ck_assert_int_eq(SOCKS_GREETING_REJECT, socks_greeting_parser_feed(&parser, 0x04));
}
END_TEST

START_TEST(test_greeting_reject_no_userpass)
{
    socks_greeting_parser parser;
    socks_greeting_parser_init(&parser);

    ck_assert_int_eq(SOCKS_GREETING_NEED_MORE, socks_greeting_parser_feed(&parser, 0x05));
    ck_assert_int_eq(SOCKS_GREETING_NEED_MORE, socks_greeting_parser_feed(&parser, 0x01));
    ck_assert_int_eq(SOCKS_GREETING_REJECT, socks_greeting_parser_feed(&parser, 0x00));
}
END_TEST

Suite *socks5_greeting_suite(void)
{
    Suite *s = suite_create("socks5_greeting");

    TCase *tc = tcase_create("parser");
    tcase_add_test(tc, test_greeting_accept_userpass);
    tcase_add_test(tc, test_greeting_accept_userpass_among_many);
    tcase_add_test(tc, test_greeting_reject_bad_version);
    tcase_add_test(tc, test_greeting_reject_no_userpass);
    suite_add_tcase(s, tc);

    return s;
}

int main(void)
{
    int number_failed = 0;
    SRunner *sr = srunner_create(socks5_greeting_suite());

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return number_failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
