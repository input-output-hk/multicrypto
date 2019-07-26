# multicrypto

A crypto library supporting hashing encoding encryption signing certificates

[![CircleCI](https://circleci.com/gh/input-output-hk/multicrypto/tree/develop.svg?style=svg&circle-token=60423cec170418ca3428b24dbe945bb05cb4be99)](https://circleci.com/gh/input-output-hk/multicrypto/tree/develop)

## Branches

Two main branches will be maintained: `develop` and `master`. `master` contains the latest version of the code that was tested end-to-end. `develop` contains the latest version of the code that runs all the tests (unit and integration tests). Integration tests don't test all the integrations. Hence, any version in `develop` might have bugs when deployed for an end-to-end test.


## Working with the codebase

To build the codebase, `mill __.compile` 
To run the all the test `mill __.test`

To publish the jar locally, `mill src.io.iohk.multicrypto.publishLocal`

In order to keep the code format consistent, we use scalafmt and git hooks, follow these steps to configure it accordingly (otherwise, your changes are going to be rejected by CircleCI):
- Install [coursier](https://github.com/coursier/coursier#command-line), the `coursier` command must work.
- `./install-scalafmt.sh` (might require sudo).
- `cp pre-commit .git/hooks/pre-commit`

Or this will build and test everything:

```bash
mill __.test 
```

To run a single test only

```bash
mill src.io.iohk.multicrypto.test.testOne io.iohk.multicrypto.SigningSpec
```