load("//scala:rules.bzl", "scala_library", "scala_test")

scala_library(
    name = "encoding",
    external = [
        "com.typesafe.akka:akka-actor%",
        "com.beachape:enumeratum%",
    ],
    visibility = ["//src/io/iohk/crypto:__subpackages__"],
    deps = [
        "//src/io/iohk/crypto/error",
        "@decco//src/io/iohk/codecs",
    ],
)

scala_test(
    name = "tests",
    external = ["org.scalacheck:scalacheck%"],
    deps = ["encoding"],
)
