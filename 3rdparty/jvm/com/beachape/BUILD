load("@io_bazel_rules_scala//scala:scala.bzl", "scala_library")
load("@io_bazel_rules_scala//scala:scala_import.bzl", "scala_import")
scala_import(
    name = "enumeratum_EXT",
    jars = [
        "//external:jar/com/beachape/enumeratum_2_12"
    ],
    neverlink = 1,
    visibility = [
        "//visibility:public"
    ]
)

scala_import(
    name = "enumeratum",
    jars = [
        "//external:jar/com/beachape/enumeratum_2_12"
    ],
    runtime_deps = [
        "//3rdparty/jvm/org/scala_lang:scala_library",
        ":enumeratum_macros"
    ],
    visibility = [
        "//visibility:public"
    ]
)



scala_import(
    name = "enumeratum_macros_EXT",
    jars = [
        "//external:jar/com/beachape/enumeratum_macros_2_12"
    ],
    neverlink = 1,
    visibility = [
        "//visibility:public"
    ]
)

scala_import(
    name = "enumeratum_macros",
    jars = [
        "//external:jar/com/beachape/enumeratum_macros_2_12"
    ],
    runtime_deps = [
        "//3rdparty/jvm/org/scala_lang:scala_library",
        "//3rdparty/jvm/org/scala_lang:scala_reflect"
    ],
    visibility = [
        "//visibility:public"
    ]
)


