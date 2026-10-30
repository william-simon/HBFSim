#!/usr/bin/env python3
"""CPU-only regression: the PTX module bpftime builds from its trampoline and a pass
output must declare a PTX version high enough for the pass output.

bpftime prepends its trampoline PTX (.version 8.1, .target sm_61) to the pass output
and keeps one header of each kind (ptxpass::filter_out_version_headers_ptx), then
HBFSim's compatibility patch raises the version only to the target's minimum
(prepare_ptx_for_target). The pass output can need more: the device helper from nvcc
12.8 carries `.pragma "used_bytes_mask 255"`, which needs PTX 8.3, while sm_89's
minimum is 7.8. Keeping the trampoline's 8.1 then fails in nvPTXCompiler.

The test prepares the ordinary agent's bpftime copy with the patch list that
scripts/build_patched_bpftime.sh passes to cmake/PreparePatchedBpftime.cmake,
extracts the actual filter from ptxpass_core, and compiles it with the actual
trampoline and compatibility header. No CUDA is needed.
"""
import argparse
import pathlib
import re
import subprocess
import tempfile

HARNESS = r'''
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <cstdio>
#include "trampoline_ptx.h"
#include "nv_attach_ptx_compatibility.hpp"
namespace ptxpass {
@FILTER@
}
int main() {
    const std::string module = ".version 8.7\n.target sm_89\n.address_size 64\n\n"
        ".visible .entry k()\n{\n\t.pragma \"used_bytes_mask 255\";\n\tret;\n}\n";
    const auto merged = ptxpass::filter_out_version_headers_ptx(TRAMPOLINE_PTX + module);
    const auto prepared = bpftime::attach::prepare_ptx_for_target(merged, "sm_89");
    std::printf("merged module declares .version %s; for sm_89 it becomes %s\n",
                prepared.original_version.c_str(), prepared.effective_version.c_str());
    const auto dot = prepared.effective_version.find('.');
    const std::pair<int, int> version{std::stoi(prepared.effective_version.substr(0, dot)),
                                      std::stoi(prepared.effective_version.substr(dot + 1))};
    if (version < std::pair<int, int>{8, 7}) {
        std::printf("FAIL: the module's own .version 8.7 was lost in the merge\n");
        return 1;
    }
    std::printf("PASS\n");
    return 0;
}
'''


def builder_patches(root: pathlib.Path) -> list[str]:
    """Return the -D<NAME>=<absolute patch> arguments the builder passes for its source copy."""
    script = (root / "scripts/build_patched_bpftime.sh").read_text()
    paths = dict(re.findall(r'^(BPFTIME_\w*PATCH)="\$HBFSIM_ROOT/([^"]+)"$', script, re.M))
    block = script[script.index('source_copy="$build_dir/_deps/bpftime-hbfsim-src"'):]
    block = block[:block.index('-DOUTPUT_SOURCE="$source_copy"')]
    arguments = []
    for name, variable in re.findall(r'-D(\w+)="\$(\w+)"', block):
        if variable == "BPFTIME_SOURCE":
            continue
        if variable not in paths:
            raise SystemExit(f"builder passes {variable} without a patch path")
        arguments.append(f"-D{name}={root / paths[variable]}")
    if not arguments:
        raise SystemExit("no bpftime patches found in the builder")
    return arguments


def extract_filter(core: str) -> str:
    template = re.search(r"template <typename Fn>\nstatic void for_each_line\(.*?\n}\n", core, re.S)
    if template is None:
        raise SystemExit("for_each_line not found in ptxpass_core")
    starts = [core.find(marker) for marker in (
        "static std::pair<int, int> parse_ptx_version_line",
        "std::string filter_out_version_headers_ptx(const std::string &input)")]
    start = min(index for index in starts if index >= 0)
    end = core.index("\n}\n", core.index("std::string filter_out_version_headers_ptx(const std::string &input)"))
    return template.group(0) + core[start:end + 3]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hbfsim-root", type=pathlib.Path, required=True)
    parser.add_argument("--cxx", default="c++")
    parser.add_argument("--cmake", default="cmake")
    args = parser.parse_args()
    root = args.hbfsim_root.resolve()
    with tempfile.TemporaryDirectory(prefix="hbfsim-merged-ptx-") as scratch:
        source = pathlib.Path(scratch) / "bpftime-hbfsim-src"
        subprocess.run([args.cmake, f"-DBPFTIME_SOURCE={root / 'third_party/bpftime'}",
                        *builder_patches(root), f"-DOUTPUT_SOURCE={source}",
                        "-P", str(root / "cmake/PreparePatchedBpftime.cmake")],
                       check=True, capture_output=True, text=True)
        core = (source / "attach/nv_attach_impl/pass/ptxpass_core/src/core.cpp").read_text()
        harness = pathlib.Path(scratch) / "merged_ptx_version.cpp"
        harness.write_text(HARNESS.replace("@FILTER@", extract_filter(core)))
        binary = pathlib.Path(scratch) / "merged_ptx_version"
        subprocess.run([args.cxx, "-std=c++20", "-I", str(source / "attach/nv_attach_impl"),
                        str(harness), "-o", str(binary)], check=True)
        return subprocess.run([str(binary)]).returncode


if __name__ == "__main__":
    raise SystemExit(main())
