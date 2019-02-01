load("//scala:rules.bzl", "scala_library", "scala_test")

scala_library(
    name = "encoding",
    deps = [
            "@codecs//src/io/iohk/codecs",
             "//src/io/iohk/crypto/error",
             "//3rdparty/jvm/com/chuusai:shapeless_EXT",
             "//3rdparty/jvm/com/typesafe/akka:akka_actor_EXT",
             "//3rdparty/jvm/com/beachape:enumeratum_macros_EXT",
             "//3rdparty/jvm/com/beachape:enumeratum_EXT" ],
    visibility = ["//src/io/iohk/crypto:__subpackages__"]
)

scala_test(
    name = "tests",
    deps = [ "encoding",
             "//3rdparty/jvm/org/scalacheck:scalacheck",
             "//3rdparty/jvm/com/typesafe/akka:akka_actor",
             "//3rdparty/jvm/com/beachape:enumeratum" ]
)
