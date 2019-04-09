load("//scala:rules.bzl", "scala_library", "scala_test")

scala_library(
    name = "certificates",
    deps = [
             "//src/io/iohk/multicrypto:multicrypto_package",
             "@decco//src/io/iohk/decco",
             "@decco//src/io/iohk/decco/auto",
           ],
    visibility = ["//src/io/iohk/multicrypto:__subpackages__"]
)

scala_test(
    name = "tests",
    deps = [ "certificates",
             "//src/io/iohk/multicrypto:multicrypto_package",
             "//src/io/iohk/multicrypto/encoding",
             "//src/io/iohk/multicrypto/certificates/test/data:data",
             "@decco//src/io/iohk/decco",
             "@decco//src/io/iohk/decco/auto",
           ],
    external = [ "org.scalacheck:scalacheck%" ]
)
