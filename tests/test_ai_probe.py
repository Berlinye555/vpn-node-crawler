from vpnnode.filters.ai_probe import TARGETS, classify, overall_level


def test_classify_healthy_responses():
    assert classify(401, '{"error":{"message":"missing api key"}}', [401]) == "ok"
    assert classify(200, "fl=abc\nh=chatgpt.com\n", [200]) == "ok"


def test_classify_region_blocked():
    body = '{"error":{"code":"unsupported_country_region_territory"}}'
    assert classify(403, body, [401]) == "region_blocked"


def test_classify_challenge():
    assert classify(403, "<title>Just a moment...</title>", [200]) == "challenge"
    assert classify(403, "<script src='https://challenges.cloudflare.com/x'></script>", [200]) == "challenge"


def test_classify_dead_and_blocked():
    assert classify(0, "", [200]) == "dead"
    assert classify(403, "Sorry, you have been blocked", [401]) == "blocked"
    assert classify(429, "slow down", [401]) == "unknown"


def test_classify_unknown_403_is_not_treated_as_blocked():
    # Anthropic 对部分出口返回该 403，属于服务端策略而非 IP 脏
    body = '{"error":{"type":"forbidden","message":"Request not allowed"}}'
    assert classify(403, body, [401]) == "unknown"


def test_overall_level_clean():
    levels = {name: "ok" for name in TARGETS}
    assert overall_level(levels) == "clean"


def test_overall_level_partial():
    levels = {"openai_api": "ok", "chatgpt": "challenge",
              "anthropic_api": "dead", "claude": "dead"}
    assert overall_level(levels) == "partial"


def test_overall_level_blocked():
    levels = {"openai_api": "region_blocked", "chatgpt": "challenge",
              "anthropic_api": "challenge", "claude": "challenge"}
    assert overall_level(levels) == "blocked"


def test_overall_level_dead():
    levels = {name: "dead" for name in TARGETS}
    assert overall_level(levels) == "dead"
