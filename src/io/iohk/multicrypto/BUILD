load("//scala:rules.bzl", "scala_library", "scala_test")

scala_library(
    name = "multicrypto_package",
    deps = [ "//src/io/iohk/multicrypto/encoding",
             "//src/io/iohk/multicrypto/hashing",
             "//src/io/iohk/multicrypto/encryption",
             "//src/io/iohk/multicrypto/signing",
             "@decco//src/io/iohk/decco",
             "//src/io/iohk/multicrypto/error" ],
    external = ["com.typesafe.akka:akka-actor%",
                "com.beachape:enumeratum%",
                "com.beachape:enumeratum-macros%",
                "com.typesafe.akka:akka-slf4j%",
                "com.github.pureconfig:pureconfig%"],
    visibility = ["//src/io/iohk/multicrypto:__subpackages__"]
)

multicrypto_content = [
      "//src/io/iohk/multicrypto:multicrypto_package",
      "//src/io/iohk/multicrypto/encoding",
      "//src/io/iohk/multicrypto/hashing",
      "//src/io/iohk/multicrypto/encryption",
      "//src/io/iohk/multicrypto/signing",
      "//src/io/iohk/multicrypto/certificates",
    ]

scala_library(
    name = "multicrypto",
    srcs = [],
    exports = multicrypto_content,
    deps = multicrypto_content, # This is needed to ensure the fat jar contains anything
)

scala_test(
    name = "tests",
    deps = [ "multicrypto",
             "@decco//src/io/iohk/decco",
             "@decco//src/io/iohk/decco/auto",
             "//src/io/iohk/multicrypto/error",
             "//src/io/iohk/multicrypto/test/utils",
             "@decco//src/io/iohk/decco/test/utils",
    ],
    external = [ "org.scalacheck:scalacheck%" ],
)
