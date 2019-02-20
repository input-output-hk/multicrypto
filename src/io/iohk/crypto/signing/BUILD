load("//scala:rules.bzl", "scala_library", "scala_test")

scala_library(
    name = "signing",
    deps = [ "//src/io/iohk/crypto/encoding" ],
    external = ["com.typesafe.akka:akka-actor%",
                "com.beachape:enumeratum%",
                "com.beachape:enumeratum-macros%"],
    visibility = ["//src/io/iohk/crypto:__subpackages__"]
)

scala_test(
    name = "tests",
    deps = [ "signing",
             "//src/io/iohk/crypto/encoding",
             "//src/io/iohk/crypto/test/utils" ],
    external = [ "org.scalacheck:scalacheck%" ],
)
