from moatline.redact import REDACTED, last_four, names_only, redact_list, redact_text, redact_url


def test_known_token_formats_are_removed():
    for secret in [
        "sk-test-FAKEabcdefghijklmnop1234",
        "ghp_FAKEFAKEFAKEFAKEFAKE1234",
        "github_pat_FAKEFAKEFAKEFAKEFAKE_1234",
        "xoxb-1234567890-FAKE",
        "AKIAFAKEFAKEFAKEFAKE",
        "AIzaFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE12",
    ]:
        assert secret not in redact_text(f"run --x {secret} now"), secret


def test_flags_and_assignments_are_redacted():
    assert redact_text("tool --token=abc123") == f"tool --token={REDACTED}"
    assert redact_text("tool --api-key abc123") == f"tool --api-key {REDACTED}"
    assert redact_text("export DB_PASSWORD=hunter2 && go") == f"export DB_PASSWORD={REDACTED} && go"
    assert redact_text("Authorization: Bearer abc.def.ghi") == f"Authorization: Bearer {REDACTED}"


def test_split_flag_in_argument_list():
    assert redact_list(["server.js", "--api-key", "shortpw42", "--port", "8080"]) == [
        "server.js",
        "--api-key",
        REDACTED,
        "--port",
        "8080",
    ]


def test_variable_references_survive():
    assert redact_text("--token=${GITHUB_TOKEN}") == "--token=${GITHUB_TOKEN}"
    assert redact_list(["--api-key", "${API_KEY}"]) == ["--api-key", "${API_KEY}"]
    assert redact_url("${API_BASE_URL:-https://api.example.com}/mcp").startswith("${API_BASE_URL")


def test_ordinary_text_is_untouched():
    for text in [
        "npx -y @modelcontextprotocol/server-github",
        "python3 ~/hooks/check.py",
        "jq -r '.tool_input.file_path' | xargs npx prettier --write",
        "Does this command look safe to execute?",
        "mcp-server-postgres-2024-edition-v2-beta",
    ]:
        assert redact_text(text) == text


def test_urls_lose_credentials_and_query():
    assert redact_url("https://user:pw@mcp.example.com:8443/v1?key=abc#frag") == (
        "https://mcp.example.com:8443/v1?[query removed]"
    )
    assert redact_url("https://mcp.example.com/mcp") == "https://mcp.example.com/mcp"


def test_helpers():
    assert names_only({"B": "secret", "A": "secret"}) == ["A", "B"]
    assert names_only("not a dict") == []
    assert last_four("sk-test-1234abcd") == "****abcd"
    assert last_four("abc") == "****"
