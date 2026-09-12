# Contributing

## Building

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

Live capture (`netscope -i ...`) requires libpcap's development headers
(`libpcap-dev` on Debian/Ubuntu, preinstalled on macOS). Without them,
`netscope_core` and its tests still build; only the `netscope` executable
is skipped, with a warning at configure time.

## Before submitting a change

```bash
cmake -S . -B build -DNETSCOPE_WARNINGS_AS_ERRORS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

If you can, also run the sanitizer build:

```bash
cmake -S . -B build-san -DNETSCOPE_ENABLE_ASAN=ON -DNETSCOPE_ENABLE_UBSAN=ON
cmake --build build-san
ctest --test-dir build-san --output-on-failure
```

Format your changes with the project's `.clang-format`:

```bash
clang-format -i src/**/*.c include/**/*.h tests/*.c
```

`clang-tidy` and `cppcheck` are optional but encouraged for anything
touching a parser:

```bash
clang-tidy -p build src/protocols/dns.c
cppcheck --inline-suppr --enable=warning,performance -I include src/
```

(`--inline-suppr` respects the handful of `cppcheck-suppress` comments in
the codebase, each documenting why the flagged line is a false positive.)

CI (`.github/workflows/ci.yml`) runs the same build+test matrix
(Ubuntu/GCC, Ubuntu/Clang, macOS/Clang), a sanitizer job, and a
`clang-format --dry-run` check on every pull request.

## Adding or changing a protocol parser

Every parser in `src/protocols/` follows the same shape: it takes
`(const uint8_t *data, size_t length, ...)`, reads only through the
bounds-checked helpers in `include/netscope/util.h`, and returns an
`ns_parse_status_t` (`NS_PARSE_OK` / `NS_PARSE_TRUNCATED` /
`NS_PARSE_MALFORMED` / `NS_PARSE_UNSUPPORTED`) rather than crashing on bad
input. See `docs/packet-parsing.md` for the reasoning behind that shape and
the specific edge cases (DNS compression, IPv4/TCP variable header
lengths) already handled.

If you add or touch a parser, add corresponding cases to the matching
`tests/test_*.c`: at minimum a valid packet, a truncated one, and (where
applicable) a structurally invalid one. Malformed/truncated input must
never crash -- that is the property the whole test suite exists to check.

## Commit messages

Describe *why* a change was made when it is not obvious from the diff.
Small, focused commits are preferred over one large one.
