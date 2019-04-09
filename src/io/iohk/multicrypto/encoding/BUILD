load("//scala:rules.bzl", "scala_library", "scala_test")

scala_library(
    name = "encoding",
    deps = [ "@decco//src/io/iohk/decco",
             "@decco//src/io/iohk/decco/auto",
             "//src/io/iohk/multicrypto/error" ],
    external = ["com.typesafe.akka:akka-actor%",
                "com.beachape:enumeratum%"],
    visibility = ["//src/io/iohk/multicrypto:__subpackages__"]
)

scala_test(
    name = "tests",
    deps = [ "encoding" ],
    external = [ "org.scalacheck:scalacheck%" ]
)
