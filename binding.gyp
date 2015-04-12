{
    "targets": [{
        "target_name": "cares_wrap",
        "include_dirs": [
            "<!(node -e \"require('nan')\")",
            "deps/cares/include"
        ],
        "sources": [
            "src/cares_wrap.cc"
        ]
    }]
}
