#!/bin/bash
set -ex

download_zig()
{
    package_version=$1
    package_system=$2
    package_json=$(curl -s https://ziglang.org/download/index.json)
    package_info=$(jq ".$package_version[\"$package_system\"]" <<< $package_json)
    package_tarball=$(jq -n "$package_info" | jq --raw-output ".tarball")
    package_shasum=$(jq -n "$package_info" | jq --raw-output ".shasum")
    package_size=$(jq -n "$package_info" | jq --raw-output ".size")
    package_full_version=$(basename ${package_tarball} .tar.xz)
    destination_dir=$PWD/zig_download
    mkdir -p $destination_dir
    curl ${package_tarball} | tar -xJC $destination_dir
    export PATH="$destination_dir/$package_full_version:$PATH"
}
