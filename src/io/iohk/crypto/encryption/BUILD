load("//scala:rules.bzl", "scala_library", "scala_test")

scala_library(
    name = "encryption",
    deps = [ "//src/io/iohk/crypto/encoding",
             "//3rdparty/jvm/com/typesafe/akka:akka_actor_EXT",
             "//3rdparty/jvm/com/beachape:enumeratum_macros_EXT",
             "//3rdparty/jvm/com/beachape:enumeratum_EXT" ],
    visibility = ["//src/io/iohk/crypto:__subpackages__"]
)

scala_test(
    name = "tests",
    deps = [ "encryption",
             "//src/io/iohk/crypto/encoding",
             "//src/io/iohk/crypto/test/utils",
             "//3rdparty/jvm/org/scalacheck:scalacheck",
             "//3rdparty/jvm/com/typesafe/akka:akka_actor",
             "//3rdparty/jvm/com/beachape:enumeratum" ]
)
