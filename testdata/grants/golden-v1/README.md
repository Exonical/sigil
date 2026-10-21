# Golden grant fixture

The private key in this directory is a fixed test-only P-256 key used to verify that Go and Rust sign and verify the same deterministic grant bytes. It is public test material and must never be used outside automated tests.

Regenerate the fixture from `backend/` with:

```sh
go test ./internal/grants -run TestGoldenGrantFixture -update
```
