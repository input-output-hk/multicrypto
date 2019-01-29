load("//scala:rules.bzl", "scala_library", "scala_test")

scala_library(
    name = "crypto_package",
    deps = [ "//main/io/iohk/crypto/encoding",
             "//main/io/iohk/crypto/hashing",
             "//main/io/iohk/crypto/encryption",
             "//main/io/iohk/crypto/signing",
             "@codecs//src/io/iohk/codecs",
             "//main/io/iohk/crypto/error",
             "//3rdparty/jvm/com/github/pureconfig:pureconfig",
             "//3rdparty/jvm/com/typesafe/akka:akka_actor",
             "//3rdparty/jvm/com/beachape:enumeratum" ],
    visibility = ["//main/io/iohk/crypto:__subpackages__"]
)

scala_library(
    name = "crypto",
    srcs = [],
    exports = [
      "//main/io/iohk/crypto:crypto_package",
      "//main/io/iohk/crypto/encoding",
      "//main/io/iohk/crypto/hashing",
      "//main/io/iohk/crypto/encryption",
      "//main/io/iohk/crypto/signing",
      "//main/io/iohk/crypto/certificates",
    ],
)

scala_test(
    name = "tests",
    deps = [ "crypto",
             "@codecs//src/io/iohk/codecs",
             "//main/io/iohk/crypto/error",
             "//main/io/iohk/crypto/test/utils",
             "@codecs//src/io/iohk/codecs/nio/test/utils",
             "//3rdparty/jvm/com/github/pureconfig:pureconfig",
             "//3rdparty/jvm/org/scalacheck:scalacheck",
             "//3rdparty/jvm/com/typesafe/akka:akka_actor",
             "//3rdparty/jvm/com/beachape:enumeratum" ]
)
