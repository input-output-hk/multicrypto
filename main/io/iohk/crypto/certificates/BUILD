load("//scala:rules.bzl", "scala_library", "scala_test")

scala_library(
    name = "certificates",
    deps = [
             "//main/io/iohk/crypto:crypto_package",
             "@codecs//src/io/iohk/codecs",
           ],
    visibility = ["//main/io/iohk/crypto:__subpackages__"]
)

scala_test(
    name = "tests",
    deps = [ "certificates",
             "//main/io/iohk/crypto:crypto_package",
             "//main/io/iohk/crypto/certificates/test/data:data",
             "@codecs//src/io/iohk/codecs",
             "//3rdparty/jvm/org/scalacheck:scalacheck",
           ]
)
