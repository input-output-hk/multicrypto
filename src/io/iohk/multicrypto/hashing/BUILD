load("//scala:rules.bzl", "scala_library", "scala_test")

scala_library(
    name = "hashing",
    deps = [ "//src/io/iohk/multicrypto/encoding" ],
    external = ["com.typesafe.akka:akka-actor%",
                "com.beachape:enumeratum%",
                "com.beachape:enumeratum-macros%"],
    visibility = ["//src/io/iohk/multicrypto:__subpackages__"]
)

scala_test(
    name = "tests",
    deps = [ "hashing",
            "//src/io/iohk/multicrypto/test/utils:utils",
           ],
    external = [ "org.scalacheck:scalacheck%" ],
)
