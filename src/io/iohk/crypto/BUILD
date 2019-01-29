load("//scala:rules.bzl", "scala_library", "scala_test")

scala_library(
    name = "crypto_package",
    deps = [ "//src/io/iohk/crypto/encoding",
             "//src/io/iohk/crypto/hashing",
             "//src/io/iohk/crypto/encryption",
             "//src/io/iohk/crypto/signing",
             "@codecs//src/io/iohk/codecs",
             "//src/io/iohk/crypto/error",
             "//3rdparty/jvm/com/github/pureconfig:pureconfig",
             "//3rdparty/jvm/com/typesafe/akka:akka_actor",
             "//3rdparty/jvm/com/beachape:enumeratum" ],
    visibility = ["//src/io/iohk/crypto:__subpackages__"]
)

scala_library(
    name = "crypto",
    srcs = [],
    exports = [
      "//src/io/iohk/crypto:crypto_package",
      "//src/io/iohk/crypto/encoding",
      "//src/io/iohk/crypto/hashing",
      "//src/io/iohk/crypto/encryption",
      "//src/io/iohk/crypto/signing",
      "//src/io/iohk/crypto/certificates",
    ],
)

scala_test(
    name = "tests",
    deps = [ "crypto",
             "@codecs//src/io/iohk/codecs",
             "//src/io/iohk/crypto/error",
             "//src/io/iohk/crypto/test/utils",
             "@codecs//src/io/iohk/codecs/nio/test/utils",
             "//3rdparty/jvm/com/github/pureconfig:pureconfig",
             "//3rdparty/jvm/org/scalacheck:scalacheck",
             "//3rdparty/jvm/com/typesafe/akka:akka_actor",
             "//3rdparty/jvm/com/beachape:enumeratum" ]
)
