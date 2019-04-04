load("//scala:rules.bzl", "scala_library", "scala_test")

scala_library(
    name = "certificates",
    deps = [
             "//src/io/iohk/multicrypto:multicrypto_package",
             "@decco//src/io/iohk/decco",
           ],
    visibility = ["//src/io/iohk/multicrypto:__subpackages__"]
)

scala_test(
    name = "tests",
    deps = [ "certificates",
             "//src/io/iohk/multicrypto:multicrypto_package",
             "//src/io/iohk/multicrypto/certificates/test/data:data",
             "@decco//src/io/iohk/decco",
           ],
    external = [ "org.scalacheck:scalacheck%" ]
)
