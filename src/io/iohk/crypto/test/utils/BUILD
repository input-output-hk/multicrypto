load("//scala:rules.bzl", "scala_library", "scala_test")

scala_library(
    name = "utils",
    external = [
        "org.scalacheck:scalacheck%",
        "com.typesafe.akka:akka-actor%",
    ],
    deps = [
        "//src/io/iohk/crypto",
        "@decco//src/io/iohk/codecs",
    ],
)
