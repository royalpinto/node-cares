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
        'cflags_cc!': [ '-fno-tree-sink' ],
        "conditions": [
            ["OS!='win'", {
                  "libraries": [ "-Wl,-rpath,<!(pwd)/build/Release/" ]
                }
            ]
        ]
    }]
}
