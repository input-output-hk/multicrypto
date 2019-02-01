load("@io_bazel_rules_scala//scala:scala.bzl", "scala_library")
load("@io_bazel_rules_scala//scala:scala_import.bzl", "scala_import")
scala_import(
    name = "akka_actor_EXT",
    jars = [
        "//external:jar/com/typesafe/akka/akka_actor_2_12"
    ],
    neverlink = 1,
    visibility = [
        "//visibility:public"
    ]
)

scala_import(
    name = "akka_actor",
    jars = [
        "//external:jar/com/typesafe/akka/akka_actor_2_12"
    ],
    runtime_deps = [
        "//3rdparty/jvm/com/typesafe:config",
        "//3rdparty/jvm/org/scala_lang/modules:scala_java8_compat",
        "//3rdparty/jvm/org/scala_lang:scala_library"
    ],
    visibility = [
        "//visibility:public"
    ]
)



scala_import(
    name = "akka_actor_testkit_typed_EXT",
    jars = [
        "//external:jar/com/typesafe/akka/akka_actor_testkit_typed_2_12"
    ],
    neverlink = 1,
    visibility = [
        "//visibility:public"
    ]
)

scala_import(
    name = "akka_actor_testkit_typed",
    jars = [
        "//external:jar/com/typesafe/akka/akka_actor_testkit_typed_2_12"
    ],
    runtime_deps = [
        "//3rdparty/jvm/org/scala_lang:scala_library",
        ":akka_actor_typed",
        ":akka_testkit"
    ],
    visibility = [
        "//visibility:public"
    ]
)



scala_import(
    name = "akka_actor_typed_EXT",
    jars = [
        "//external:jar/com/typesafe/akka/akka_actor_typed_2_12"
    ],
    neverlink = 1,
    visibility = [
        "//visibility:public"
    ]
)

scala_import(
    name = "akka_actor_typed",
    jars = [
        "//external:jar/com/typesafe/akka/akka_actor_typed_2_12"
    ],
    runtime_deps = [
        "//3rdparty/jvm/org/scala_lang:scala_library",
        ":akka_actor"
    ],
    visibility = [
        "//visibility:public"
    ]
)



scala_import(
    name = "akka_slf4j_EXT",
    jars = [
        "//external:jar/com/typesafe/akka/akka_slf4j_2_12"
    ],
    neverlink = 1,
    visibility = [
        "//visibility:public"
    ]
)

scala_import(
    name = "akka_slf4j",
    jars = [
        "//external:jar/com/typesafe/akka/akka_slf4j_2_12"
    ],
    runtime_deps = [
        "//3rdparty/jvm/org/scala_lang:scala_library",
        "//3rdparty/jvm/org/slf4j:slf4j_api",
        ":akka_actor"
    ],
    visibility = [
        "//visibility:public"
    ]
)



scala_import(
    name = "akka_testkit_EXT",
    jars = [
        "//external:jar/com/typesafe/akka/akka_testkit_2_12"
    ],
    neverlink = 1,
    visibility = [
        "//visibility:public"
    ]
)

scala_import(
    name = "akka_testkit",
    jars = [
        "//external:jar/com/typesafe/akka/akka_testkit_2_12"
    ],
    runtime_deps = [
        "//3rdparty/jvm/org/scala_lang:scala_library",
        ":akka_actor"
    ],
    visibility = [
        "//visibility:public"
    ]
)


