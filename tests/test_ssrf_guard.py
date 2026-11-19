"""
The verified-evaluation path makes the platform call a URL a stranger supplied. This is the only thing
standing between that and the cloud metadata service, so it is tested with the classic bypass encodings.
DNS is replaced by a table; no test touches the network.
"""
import socket
import pytest
import ssrf_guard as G
from ssrf_guard import SSRFValidationError, validate_agent_url


@pytest.fixture()
def dns(monkeypatch):
    table = {}
    def fake(host, port, proto=0, **kw):
        if host not in table:
            raise socket.gaierror(-2, "Name or service not known")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in table[host]]
    monkeypatch.setattr(G.socket, "getaddrinfo", fake)
    return table


def refused(url):
    with pytest.raises(SSRFValidationError): validate_agent_url(url)


def test_a_public_https_host_is_accepted_and_the_validated_ips_are_returned_for_pinning(dns):
    dns["agent.example.com"] = ["93.184.216.34"]
    out = validate_agent_url("https://agent.example.com/run")
    assert out == {"url": "https://agent.example.com/run", "hostname": "agent.example.com", "public_ips": ["93.184.216.34"]}


@pytest.mark.parametrize("url", ["http://agent.example.com", "ftp://agent.example.com", "file:///etc/passwd", "gopher://agent.example.com",
                                 "javascript:alert(1)", "//agent.example.com", "agent.example.com", "", "   ", None, 5, ["https://a.com"]])
def test_only_https_urls_with_a_host_are_considered(dns, url):
    dns["agent.example.com"] = ["93.184.216.34"]; refused(url)


@pytest.mark.parametrize("url", ["https://localhost/", "https://LOCALHOST/", "https://metadata/", "https://metadata.google.internal/computeMetadata/v1/",
                                 "https://instance-data/", "https://169.254.169.254/latest/meta-data/"])
def test_known_internal_names_are_blocked_outright(dns, url): refused(url)


@pytest.mark.parametrize("ip", ["127.0.0.1", "127.1.2.3", "10.0.0.5", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254", "169.254.0.1",
                                "100.64.0.1", "100.127.255.255", "0.0.0.0", "224.0.0.1", "240.0.0.1", "255.255.255.255",
                                "[::1]", "[::]", "[fe80::1]", "[fc00::1]", "[fd00::1]", "[ff02::1]", "[::ffff:127.0.0.1]", "[::ffff:10.0.0.1]",
                                "[::ffff:169.254.169.254]", "[64:ff9b::7f00:1]"])
def test_literal_internal_ips_are_refused(dns, ip): refused(f"https://{ip}/")


@pytest.mark.parametrize("host", ["2130706433", "0x7f000001", "017700000001", "0177.0.0.1", "127.1", "0x7f.1", "127.0.1"])
def test_numeric_encodings_of_loopback_are_refused_because_they_resolve_to_it(dns, host):
    """inet_aton accepts decimal, hex and octal forms; the resolver turns each into 127.0.0.1."""
    dns[host] = ["127.0.0.1"]; refused(f"https://{host}/")


def test_a_name_that_resolves_to_a_private_address_is_refused(dns):
    dns["evil.example.com"] = ["10.0.0.5"]; refused("https://evil.example.com/")


def test_any_private_address_among_several_refuses_the_whole_host(dns):
    """DNS rebinding and split-horizon answers: one public IP does not excuse a private one."""
    dns["mixed.example.com"] = ["93.184.216.34", "10.0.0.5"]; refused("https://mixed.example.com/")
    dns["mixed2.example.com"] = ["93.184.216.34", "169.254.169.254"]; refused("https://mixed2.example.com/")


def test_a_trailing_dot_cannot_dodge_the_name_blocklist(dns):
    dns["localhost."] = ["127.0.0.1"]; refused("https://localhost./")


def test_an_unresolvable_host_is_refused_not_assumed_safe(dns):
    refused("https://does-not-exist.example.com/")


@pytest.mark.parametrize("url", ["https://agent.example.com:8443/", "https://agent.example.com:80/", "https://agent.example.com:22/", "https://agent.example.com:6379/"])
def test_only_port_443_is_allowed(dns, url):
    dns["agent.example.com"] = ["93.184.216.34"]; refused(url)


def test_the_explicit_default_port_is_fine(dns):
    dns["agent.example.com"] = ["93.184.216.34"]; assert validate_agent_url("https://agent.example.com:443/x")["public_ips"] == ["93.184.216.34"]


def test_an_overlong_url_is_refused(dns):
    dns["agent.example.com"] = ["93.184.216.34"]; refused("https://agent.example.com/" + "a" * 2100)


def test_a_userinfo_trick_is_judged_by_the_real_host(dns):
    """https://public.example.com@127.0.0.1/ connects to 127.0.0.1; the part before @ is credentials."""
    dns["public.example.com"] = ["93.184.216.34"]
    refused("https://public.example.com@127.0.0.1/"); refused("https://public.example.com:pw@10.0.0.1/")


def test_a_redirect_target_is_held_to_the_same_policy(dns):
    with pytest.raises(SSRFValidationError, match="Empty"): G.validate_redirect_target("", "agent.example.com")
    refused_target = "https://169.254.169.254/"
    with pytest.raises(SSRFValidationError): G.validate_redirect_target(refused_target, "agent.example.com")


def test_the_public_ip_predicate_on_edge_cases():
    for ip in ("8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"): assert G._is_public_ip(ip)
    for ip in ("", "not-an-ip", "999.1.1.1", "10.0.0.1", "::1", "100.64.0.1"): assert not G._is_public_ip(ip)
