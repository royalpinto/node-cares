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
        "libraries": [ "-Wl,-rpath,<!(pwd)/build/Release/" ]
    }]
}
