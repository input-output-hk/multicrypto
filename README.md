# multicrypto

A crypto library supporting hashing encoding encryption signing certificates

[![CircleCI](https://circleci.com/gh/input-output-hk/multicrypto/tree/develop.svg?style=svg&circle-token=60423cec170418ca3428b24dbe945bb05cb4be99)](https://circleci.com/gh/input-output-hk/multicrypto/tree/develop)

## Branches

Two main branches will be maintained: `develop` and `master`. `master` contains the latest version of the code that was tested end-to-end. `develop` contains the latest version of the code that runs all the tests (unit and integration tests). Integration tests don't test all the integrations. Hence, any version in `develop` might have bugs when deployed for an end-to-end test.


### A note on bazel

Bazel distributes the codebase in two types of entities:
 - **package**: a folder containing a `BUILD` file. A package is a collection of files and *rules*
 - **rule**: a rule is something that can be built. A rule is a pure function (in the more 'functional programming' sense) that given some inputs (tipically source files and some kind of compiler(s)) produces an output (an executable, a library, the result of running some tests...). It's important to note that rules are **pure**, that is, given some concrete inputs the whole thing can be replaced with what bazel would build. That is, bazel caches what it produces and if nothing in the input changes it's always going to use the cached version. And that's why tests in bazel must be _idempotent_.

Note: The BUILD file lists the rules of a package (usually one library and/or binary, and a test suite). If you want to see what a package can build, just look at the BUILD file.

Note 2: Bazel is designed from the grown-up for absolutelly reproducible builds, that is: once you have built something you should **_NEVER_** want/need to clean. You can clean (with `bazel clean`, or it's extreme version `bazel clean --expunge`), but you shouldn't.

### Using Bazel from the terminal

I'm going to explain different things that can be done, using this sample situation: we have a build file in `main/io/iohk/cef/codecs/BUILD`, with two rules, an scala library named `codecs` and a set of tests named `tests`. Where the `main` folder is a subfolder of the `workspace`. The workspace is the folder containing the `WORKSPACE` file.

All rules in bazel have a label (similar to a full name in Java/Scala). This labels when writen in full are something like this:

```
//<package_name>:<rule_name>
```

Where `package_name` is the path containing the `BUILD` file. In our example the package_name of our package is `main/io/iohk/cef/codecs`. So the label for the `codecs` rule is `//main/io/iohk/cef/codecs:codecs`. And the label for the `tests` rule is `//main/io/iohk/cef/codecs:tests`.

If the last bit of `package_name` (that is `codecs` in our example) is the same than the rule name, the rule name can be omited. That is, we can label our two packages `//main/io/iohk/cef/codecs` and `//main/io/iohk/cef/codecs:tests` which is quite clean.

There are three relevant command in bazel `build`, `run` and `test`. Usually run this way:

```bash
bazel <command> <label> [<label>...]
```

For example, to build `crypto` you need to run this:

```bash
bazel build //main/io/iohk/crypto
```
For example, to build `encoding` you need to run this:

```bash
bazel build //main/io/iohk/crypto/encoding
```

Or, to run it's associated tests (that is the rule `tests`)

```bash
bazel test //main/io/iohk/crypto
```

Note that, by default only shows a summary of the test results, but not the whole thing. If you want the whole thing, you need this:

```bash
bazel test //main/io/iohk/crypto --test_output=all
```

Or, if you are only interested on the tests that fail:

```bash
bazel test //main/io/iohk/crypto --test_output=errors
```

But the other two accept as many as you need. Or even better, you can use the `...` wildcard. This will run all the tests below `main` (recursively):

```bash
bazel test //main/...
```

Or this will build and test everything:

```bash
bazel test //...
```
