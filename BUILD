licenses(["notice"])  # Apache 2.0

exports_files(["LICENSE"])

cc_library(
    name = "token_bind",
    srcs = [
        "tb_bytestring.h",
        "token_bind_client.c",
        "token_bind_common.c",
        "token_bind_server.c",
    ],
    hdrs = [
        "token_bind_client.h",
        "token_bind_common.h",
        "token_bind_server.h",
    ],
    includes = [
        ".",
    ],
    visibility = [
        "//visibility:public",
    ],
    deps = [
        "@boringssl//:crypto",
        "@boringssl//:ssl",
    ],
)
