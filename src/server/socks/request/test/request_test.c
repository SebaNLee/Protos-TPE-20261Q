#include <arpa/inet.h>
#include <check.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#include "request.h"

static socks_request_status feed_all(socks_request_parser *parser,
                                     const uint8_t *bytes,
                                     size_t len)
{
    socks_request_status status = SOCKS_REQUEST_NEED_MORE;

    for (size_t i = 0; i < len; i++)
    {
        status = socks_request_parser_feed(parser, bytes[i]);
        if (status != SOCKS_REQUEST_NEED_MORE)
        {
            break;
        }
    }

    return status;
}

START_TEST(test_request_ipv4)
{
    socks_request_parser parser;
    socks_request_parser_init(&parser);

    /* CONNECT 203.0.113.1:443 */
    const uint8_t msg[] = {
        0x05, 0x01, 0x00, 0x01, 203, 0, 113, 1, 0x01, 0xBB};

    ck_assert_int_eq(SOCKS_REQUEST_PARSED_ADDR, feed_all(&parser, msg, sizeof(msg)));
    ck_assert_uint_eq(443, socks_request_dest_port(&parser));

    const struct sockaddr_in *addr =
        (const struct sockaddr_in *)socks_request_dest_addr(&parser);
    ck_assert(addr != NULL);
    ck_assert_int_eq(AF_INET, addr->sin_family);
    ck_assert_int_eq(htonl(0xCB007101), addr->sin_addr.s_addr);
}
END_TEST

START_TEST(test_request_fqdn)
{
    socks_request_parser parser;
    socks_request_parser_init(&parser);

    const uint8_t msg[] = {
        0x05, 0x01, 0x00, 0x03, 0x0B,
        'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
        0x00, 0x50};

    ck_assert_int_eq(SOCKS_REQUEST_PARSED_FQDN, feed_all(&parser, msg, sizeof(msg)));
    ck_assert_uint_eq(80, socks_request_dest_port(&parser));
    ck_assert_str_eq("example.com", socks_request_fqdn(&parser));
}
END_TEST

START_TEST(test_request_reject_bad_cmd)
{
    socks_request_parser parser;
    socks_request_parser_init(&parser);

    const uint8_t msg[] = {0x05, 0x03, 0x00, 0x01};

    ck_assert_int_eq(SOCKS_REQUEST_REJECT, feed_all(&parser, msg, sizeof(msg)));
}
END_TEST

Suite *socks5_request_suite(void)
{
    Suite *s = suite_create("socks5_request");

    TCase *tc = tcase_create("parser");
    tcase_add_test(tc, test_request_ipv4);
    tcase_add_test(tc, test_request_fqdn);
    tcase_add_test(tc, test_request_reject_bad_cmd);
    suite_add_tcase(s, tc);

    return s;
}

int main(void)
{
    int number_failed = 0;
    SRunner *sr = srunner_create(socks5_request_suite());

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return number_failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
