load("@io_bazel_rules_scala//scala:scala.bzl", "scala_library")
load("@io_bazel_rules_scala//scala:scala_import.bzl", "scala_import")
scala_import(
    name = "pureconfig_EXT",
    jars = [
        "//external:jar/com/github/pureconfig/pureconfig_2_12"
    ],
    neverlink = 1,
    visibility = [
        "//visibility:public"
    ]
)

scala_import(
    name = "pureconfig",
    jars = [
        "//external:jar/com/github/pureconfig/pureconfig_2_12"
    ],
    runtime_deps = [
        "//3rdparty/jvm/org/scala_lang:scala_library",
        ":pureconfig_core",
        ":pureconfig_generic"
    ],
    visibility = [
        "//visibility:public"
    ]
)



scala_import(
    name = "pureconfig_core_EXT",
    jars = [
        "//external:jar/com/github/pureconfig/pureconfig_core_2_12"
    ],
    neverlink = 1,
    visibility = [
        "//visibility:public"
    ]
)

scala_import(
    name = "pureconfig_core",
    jars = [
        "//external:jar/com/github/pureconfig/pureconfig_core_2_12"
    ],
    runtime_deps = [
        "//3rdparty/jvm/com/typesafe:config",
        "//3rdparty/jvm/org/scala_lang:scala_library",
        ":pureconfig_macros"
    ],
    visibility = [
        "//visibility:public"
    ]
)



scala_import(
    name = "pureconfig_generic_EXT",
    jars = [
        "//external:jar/com/github/pureconfig/pureconfig_generic_2_12"
    ],
    neverlink = 1,
    visibility = [
        "//visibility:public"
    ]
)

scala_import(
    name = "pureconfig_generic",
    jars = [
        "//external:jar/com/github/pureconfig/pureconfig_generic_2_12"
    ],
    runtime_deps = [
        "//3rdparty/jvm/com/chuusai:shapeless",
        "//3rdparty/jvm/org/scala_lang:scala_library",
        ":pureconfig_core"
    ],
    visibility = [
        "//visibility:public"
    ]
)



scala_import(
    name = "pureconfig_macros_EXT",
    jars = [
        "//external:jar/com/github/pureconfig/pureconfig_macros_2_12"
    ],
    neverlink = 1,
    visibility = [
        "//visibility:public"
    ]
)

scala_import(
    name = "pureconfig_macros",
    jars = [
        "//external:jar/com/github/pureconfig/pureconfig_macros_2_12"
    ],
    runtime_deps = [
        "//3rdparty/jvm/org/scala_lang:scala_library"
    ],
    visibility = [
        "//visibility:public"
    ]
)


