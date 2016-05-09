{
    "targets": [{
        "target_name": "cares_wrap",
        "include_dirs": [
            "<!(node -e \"require('nan')\")",
            "deps/cares/include",
            "deps/cares/src"
        ],
        "sources": [
            "src/cares_wrap.cc"
        ],
        "dependencies": [ "deps/cares/cares.gyp:cares" ],
        "conditions": [
            ["OS!='win'", {
                  "libraries": [ "-Wl,-rpath,<!(pwd)/build/Release/" ],
                }
            ],
            ['clang == 0 and gcc_version <= 44', {
                'cflags': [ '-fno-tree-sink' ],  # Work around compiler bug.
            }],
        ]
    }]
}
