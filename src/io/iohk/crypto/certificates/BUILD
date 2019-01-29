load("//scala:rules.bzl", "scala_library", "scala_test")

scala_library(
    name = "certificates",
    deps = [
             "//src/io/iohk/crypto:crypto_package",
             "@codecs//src/io/iohk/codecs",
           ],
    visibility = ["//src/io/iohk/crypto:__subpackages__"]
)

scala_test(
    name = "tests",
    deps = [ "certificates",
             "//src/io/iohk/crypto:crypto_package",
             "//src/io/iohk/crypto/certificates/test/data:data",
             "@codecs//src/io/iohk/codecs",
             "//3rdparty/jvm/org/scalacheck:scalacheck",
           ]
)
