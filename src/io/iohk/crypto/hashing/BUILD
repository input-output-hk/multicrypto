load("//scala:rules.bzl", "scala_library", "scala_test")

scala_library(
    name = "hashing",
    deps = [ "//3rdparty/jvm/com/typesafe/akka:akka_actor",
             "//3rdparty/jvm/com/beachape:enumeratum",
             "//3rdparty/jvm/com/beachape:enumeratum_macros",
           ],
    visibility = ["//src/io/iohk/crypto:__subpackages__"]
)

scala_test(
    name = "tests",
    deps = [ "hashing",
            "//src/io/iohk/crypto/test/utils:utils",
             "//3rdparty/jvm/org/scalacheck:scalacheck",
             "//3rdparty/jvm/com/typesafe/akka:akka_actor",
             "//3rdparty/jvm/com/beachape:enumeratum",
             "//3rdparty/jvm/com/beachape:enumeratum_macros",
           ]
)
