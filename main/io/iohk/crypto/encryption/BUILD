load("//scala:rules.bzl", "scala_library", "scala_test")

scala_library(
    name = "encryption",
    deps = [ "//main/io/iohk/crypto/encoding",
             "//3rdparty/jvm/com/typesafe/akka:akka_actor",
             "//3rdparty/jvm/com/beachape:enumeratum" ],
    visibility = ["//main/io/iohk/crypto:__subpackages__"]
)

scala_test(
    name = "tests",
    deps = [ "encryption",
             "//main/io/iohk/crypto/encoding",
             "//main/io/iohk/crypto/test/utils",
             "//3rdparty/jvm/org/scalacheck:scalacheck",
             "//3rdparty/jvm/com/typesafe/akka:akka_actor",
             "//3rdparty/jvm/com/beachape:enumeratum" ]
)
