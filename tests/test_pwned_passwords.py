from cleantrace.plugins.pwned_passwords import parse_range_count, sha1_password_parts


def test_sha1_password_parts_do_not_return_plaintext() -> None:
    prefix, suffix = sha1_password_parts("password")

    assert prefix == "5BAA6"
    assert suffix.startswith("1E4C9")
    assert "password" not in prefix + suffix


def test_parse_range_count() -> None:
    body = "ABCDEF:2\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:3303003\n"

    assert parse_range_count(body, "1E4C9B93F3F0682250B6CF8331B7EE68FD8") == 3_303_003
    assert parse_range_count(body, "missing") == 0
