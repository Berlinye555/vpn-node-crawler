from vpnnode.filters.exit_probe import parse_trace

TRACE = """fl=881f2
h=www.cloudflare.com
ip=203.0.113.9
ts=1795522395.123
visit_scheme=https
uag=Mozilla/5.0
colo=LAX
sliver=none
http=http/2
loc=JP
tls=TLSv1.3
sni=plaintext
warp=on"""


def test_parse_trace_fields():
    info = parse_trace(TRACE)
    assert info["ip"] == "203.0.113.9"
    assert info["loc"] == "JP"
    assert info["warp"] == "on"


def test_parse_trace_ignores_unknown_lines():
    info = parse_trace("foo=bar\nip=1.2.3.4\nnothing here")
    assert info == {"ip": "1.2.3.4", "loc": "", "warp": ""}


def test_parse_trace_empty():
    assert parse_trace("") == {"ip": "", "loc": "", "warp": ""}
