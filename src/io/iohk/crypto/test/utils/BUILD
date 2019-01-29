load("//scala:rules.bzl", "scala_library", "scala_test")

scala_library(
    name = "utils",
    srcs = glob(["**/*.scala"]),
    deps = [ "//src/io/iohk/crypto",
            "@codecs//src/io/iohk/codecs",
             #"//src/io/iohk/cef/test",
             "//3rdparty/jvm/com/typesafe/akka:akka_actor",
             "//3rdparty/jvm/org/scalacheck:scalacheck",
    ],
)

