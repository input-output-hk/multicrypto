load("//scala:rules.bzl", "scala_library", "scala_test")

scala_library(
    name = "encoding",
    deps = [ "@codecs//src/io/iohk/codecs",
             "//src/io/iohk/crypto/error" ],
    external = ["com.typesafe.akka:akka-actor%",
                "com.beachape:enumeratum%"],
    visibility = ["//src/io/iohk/crypto:__subpackages__"]
)

scala_test(
    name = "tests",
    deps = [ "encoding" ],
    external = [ "org.scalacheck:scalacheck%" ]
)
