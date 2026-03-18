# KVStore Helper Tests

These tests cover only the proxy-related change in `lib/illumio/kvstore_mgmt/kvstore_helpers.py`.

## Unit test

Run:

```bash
pytest TA-Illumio/tests/unit/test_kvstore_helpers.py
```

What it covers:

- direct request path when no proxy is configured
- proxy tunnel behavior for HTTPS targets
- proxy basic-auth header creation from proxy URLs of the form `http://username:password@host:port`

## Integration test

This test is opt-in and uses a real proxy and a real reachable HTTPS target.

Set:

```bash
export KV_STORE_REPLICATION_PROXY='http://testuser:testpass@10.2.35.3:3128'
export KVSTORE_HELPERS_TEST_URL='https://example.com/'
```

Run:

```bash
pytest TA-Illumio/tests/integration/test_kvstore_helpers_integration.py
```

Notes:

- `KV_STORE_REPLICATION_PROXY` is only required for the proxy-path helper test. The direct helper test runs without it.
- Keep the target URL as a simple HTTPS endpoint that returns HTTP 200.
- These tests do not require Splunk or KV-store fixtures because they exercise the helper directly.

## KV-store upload integration test

This test writes to a real Splunk KV-store collection on the target Search Head.

Set:

```bash
export KVSTORE_SPLUNK_HOST='<search-head-host>'
export KVSTORE_SPLUNK_PORT='8089'
export KVSTORE_SPLUNK_SCHEME='https'
export KVSTORE_SPLUNK_USERNAME='<admin-username>'
export KVSTORE_SPLUNK_PASSWORD='<admin-password>'
export KVSTORE_SPLUNK_APP='TA-Illumio'
export KV_STORE_REPLICATION_PROXY='http://testuser:testpass@10.2.35.3:3128'
```

Run:

```bash
pytest TA-Illumio/tests/integration/test_kvstore_upload_integration.py
```

Notes:

- `KV_STORE_REPLICATION_PROXY` is optional. If it is blank or unset, the test connects directly.
- `KVSTORE_SPLUNK_SCHEME` defaults to `https`. Set it to `http` if the Splunk management endpoint is running over HTTP.
- The test creates a temporary KV-store collection, uploads one sample document, verifies the write, and then deletes the collection.

## KV-store copy integration test

This test exercises the real `copyCollection()` path from a source Splunk instance to a target Splunk instance.

Set:

```bash
export KVSTORE_SOURCE_HOST='<source-host>'
export KVSTORE_SOURCE_PORT='8089'
export KVSTORE_SOURCE_SCHEME='https'
export KVSTORE_SOURCE_USERNAME='<source-username>'
export KVSTORE_SOURCE_PASSWORD='<source-password>'

export KVSTORE_TARGET_HOST='<target-host>'
export KVSTORE_TARGET_PORT='8089'
export KVSTORE_TARGET_SCHEME='https'
export KVSTORE_TARGET_USERNAME='<target-username>'
export KVSTORE_TARGET_PASSWORD='<target-password>'

export KVSTORE_SPLUNK_APP='TA-Illumio'
export KV_STORE_REPLICATION_PROXY='http://testuser:testpass@10.2.35.3:3128'
```

Run:

```bash
pytest TA-Illumio/tests/integration/test_kvstore_copy_integration.py
```

Notes:

- `KV_STORE_REPLICATION_PROXY` is optional. If it is blank or unset, the target-side calls connect directly.
- The test creates a temporary source collection, inserts one sample document, copies it to the target, verifies the target document, and leaves both collections in place for inspection.
