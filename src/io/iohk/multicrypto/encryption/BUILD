load("//scala:rules.bzl", "scala_library", "scala_test")

scala_library(
    name = "encryption",
    deps = [ "//src/io/iohk/multicrypto/encoding" ],
    external = ["com.typesafe.akka:akka-actor%",
                "com.beachape:enumeratum-macros%"],
    visibility = ["//src/io/iohk/multicrypto:__subpackages__"]
)

scala_test(
    name = "tests",
    deps = [ "encryption",
             "//src/io/iohk/multicrypto/encoding",
             "//src/io/iohk/multicrypto/test/utils" ],
    external = [ "org.scalacheck:scalacheck%" ]
)
