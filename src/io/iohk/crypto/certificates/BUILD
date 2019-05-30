load("//scala:rules.bzl", "scala_library", "scala_test")

scala_library(
    name = "certificates",
    visibility = ["//src/io/iohk/crypto:__subpackages__"],
    deps = [
        "//src/io/iohk/crypto:crypto_package",
        "@decco//src/io/iohk/codecs",
    ],
)

scala_test(
    name = "tests",
    external = ["org.scalacheck:scalacheck%"],
    deps = [
        "certificates",
        "//src/io/iohk/crypto:crypto_package",
        "//src/io/iohk/crypto/certificates/test/data",
        "@decco//src/io/iohk/codecs",
    ],
)
