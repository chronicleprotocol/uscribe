<div align="center">

<h1>uScribe</h1>

<a href="">[![Tests][tests-shield]][tests-shield-url]</a>

</div>

uScribe is a universal Oracle using efficient Schnorr multi-signatures.

## Installation

Install module via Foundry:

```bash
$ forge install chronicleprotocol/uscribe
```

## Contributing

The project uses the Foundry toolchain. You can find installation instructions [here](https://getfoundry.sh/).

Setup:

```bash
$ git clone https://github.com/chronicleprotocol/uscribe
$ cd uscribe/
$ forge install
```

Run tests:

```bash
$ forge test                          # Run all tests
$ forge test -vvvv                    # Run all tests with full stack traces
$ FOUNDRY_PROFILE=intense forge test  # Run all tests in intense mode
```

Lint:

```bash
$ forge fmt [--check]
```

## Dependencies

- [chronicleprotocol/chronicle-std@v2](https://github.com/chronicleprotocol/chronicle-std/tree/v2)

## Licensing

The primary license for uScribe is the Business Source License 1.1 (`BUSL-1.1`), see [`LICENSE`](./LICENSE). However, some files are dual licensed under `MIT`:

- All files in `src/libs/` may also be licensed under `MIT` (as indicated in their SPDX headers), see [`src/libs/LICENSE`](./src/libs/LICENSE)
- Several Solidity interface files may also be licensed under `MIT` (as indicated in their SPDX headers)
- Several files in `script/` may also be licensed under `MIT` (as indicated in their SPDX headers)

<!--- Shields -->
[tests-shield]: https://github.com/chronicleprotocol/uscribe/actions/workflows/unit-tests.yml/badge.svg
[tests-shield-url]: https://github.com/chronicleprotocol/uscribe/actions/workflows/unit-tests.yml
