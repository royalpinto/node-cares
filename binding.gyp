{
    "targets": [{

        "variables": {
            # Define `gcc_version` if it's not defined already
            # as it is getting used below.
            "gcc_version%": "unknown",
        },

        "target_name": "cares_wrap",

        "include_dirs": [
            "<!(node -e \"require('nan')\")",
            "deps/cares/include",
            "deps/cares/src",
            "deps/utils"
        ],

        "sources": [
            "src/cares_wrap.cc"
        ],

        "dependencies": [ "deps/cares/cares.gyp:cares" ],

        # Exclude `-fno-tree-sink` by default as some older compiler versions
        # does not support this flag.
        # This flag is conditionally getting added again below.
        'cflags!': [ '-fno-tree-sink' ],

        "conditions": [
            ["OS!='win'", {
                  "libraries": [ "-Wl,-rpath,<!(pwd)/build/Release/" ],
                }
            ],
            # Conditionally add `-fno-tree-sink` only for supported versions.
            ['clang == 0 and gcc_version <= 44', {
                'cflags': [ '-fno-tree-sink' ],  # Work around compiler bug.
            }],
        ]
    }]
}
