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
             "//3rdparty/jvm/com/github/pureconfig:pureconfig",
             "//3rdparty/jvm/com/github/pureconfig:pureconfig_macros",
             "//3rdparty/jvm/com/github/pureconfig:pureconfig_core",
             "//3rdparty/jvm/com/github/pureconfig:pureconfig_generic",
             "//3rdparty/jvm/com/typesafe/akka:akka_actor",
             "//3rdparty/jvm/com/beachape:enumeratum_macros",
             "//3rdparty/jvm/com/beachape:enumeratum"
           ]
)
