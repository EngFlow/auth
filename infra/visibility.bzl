"""Contains visibility constants to reduce duplication, increase BUILD file readability"""

# Visibility used for artifacts that get released, which are defined by
# filegroup(s) in the top-level BUILD file.
RELEASE_ARTIFACT = ["//:__pkg__"]
