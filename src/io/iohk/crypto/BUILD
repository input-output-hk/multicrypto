load("//scala:rules.bzl", "scala_library", "scala_test")

scala_library(
    name = "crypto_package",
    deps = [ "//src/io/iohk/crypto/encoding",
             "//src/io/iohk/crypto/hashing",
             "//src/io/iohk/crypto/encryption",
             "//src/io/iohk/crypto/signing",
             "@codecs//src/io/iohk/codecs",
             "//src/io/iohk/crypto/error" ],
    external = ["com.typesafe.akka:akka-actor%",
                "com.beachape:enumeratum%",
                "com.beachape:enumeratum-macros%",
                "com.typesafe.akka:akka-slf4j%",
                "com.github.pureconfig:pureconfig%"],
    visibility = ["//src/io/iohk/crypto:__subpackages__"]
)

crypto_content = [
      "//src/io/iohk/crypto:crypto_package",
      "//src/io/iohk/crypto/encoding",
      "//src/io/iohk/crypto/hashing",
      "//src/io/iohk/crypto/encryption",
      "//src/io/iohk/crypto/signing",
      "//src/io/iohk/crypto/certificates",
    ]

scala_library(
    name = "crypto",
    srcs = [],
    exports = crypto_content,
    deps = crypto_content, # This is needed to ensure the fat jar contains anything
)

scala_test(
    name = "tests",
    deps = [ "crypto",
             "@codecs//src/io/iohk/codecs",
             "//src/io/iohk/crypto/error",
             "//src/io/iohk/crypto/test/utils",
             "@codecs//src/io/iohk/codecs/nio/test/utils" ],
    external = [ "org.scalacheck:scalacheck%" ],
)
