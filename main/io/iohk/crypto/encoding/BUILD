load("//scala:rules.bzl", "scala_library", "scala_test")

scala_library(
    name = "encoding",
    deps = [
            "@codecs//main/io/iohk/codecs",
             "//main/io/iohk/crypto/error",
             "//3rdparty/jvm/com/chuusai:shapeless",
             "//3rdparty/jvm/com/typesafe/akka:akka_actor",
             "//3rdparty/jvm/com/beachape:enumeratum" ],
    visibility = ["//main/io/iohk/crypto:__subpackages__"]
)

scala_test(
    name = "tests",
    deps = [ "encoding",
             "//3rdparty/jvm/org/scalacheck:scalacheck",
             "//3rdparty/jvm/com/typesafe/akka:akka_actor",
             "//3rdparty/jvm/com/beachape:enumeratum" ]
)
