// Checks that OpenSSL SHA256 works where bpftime loads HBFSim's PTX pass, in this
// build environment.
//
// bpftime used to load PTX passes with dlmopen(LM_ID_NEWLM). That namespace has its
// own libc, whose pthread key table is separate from the main namespace's while the
// thread-specific values are shared, so OpenSSL in the pass can read another
// library's value as its own state. On OpenSSL 3.0.13 (Ubuntu 24.04) SHA256 then
// crashes; on 3.5.5 (Ubuntu 26.04) it returns null. A process such as the bpftime
// agent sets many thread-specific values before the pass runs, so --keys sets that
// many in the main namespace, each to a zeroed block.
//
// Every case runs in a child process, so a crash is reported instead of ending the
// probe. Targets: a bare SHA256 library, and the real pass on a PTX file whose
// module identity must equal ptx:sha256:<expected>. Loaders: the one HBFSim's bpftime
// patch 0003 uses (dlopen, RTLD_LOCAL | RTLD_DEEPBIND) and the earlier dlmopen.
// Expected digests come from the caller (CMake computes them), so the probe itself
// never runs OpenSSL in the main namespace.
//
// Exit status: 0 when every case with the patched loader is OK, 1 otherwise, 64 for
// usage errors. dlmopen results are reported, not required.
#include <dlfcn.h>
#include <gnu/libc-version.h>
#include <json.hpp>
#include <pthread.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <map>
#include <string>
#include <vector>

namespace {

struct Options {
    std::map<std::string, std::string> values;
    std::string get(const std::string& key) const
    {
        const auto found = values.find(key);
        return found == values.end() ? std::string() : found->second;
    }
};

constexpr const char* kProbeText = "hbfsim pass loader probe";

void* load(bool use_dlmopen, const std::string& path)
{
    return use_dlmopen ? dlmopen(LM_ID_NEWLM, path.c_str(), RTLD_NOW | RTLD_LOCAL)
                       : dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL | RTLD_DEEPBIND);
}

void set_thread_values(int count)
{
    static std::vector<char> zeroed(4096, 0);
    for (int index = 0; index < count; ++index) {
        pthread_key_t key;
        if (pthread_key_create(&key, nullptr) != 0 ||
            pthread_setspecific(key, zeroed.data()) != 0) {
            std::fprintf(stderr, "pass_loader_probe: pthread key %d failed\n", index);
            _exit(19);
        }
    }
}

std::string hex(const unsigned char* bytes, std::size_t size)
{
    static const char digits[] = "0123456789abcdef";
    std::string text;
    for (std::size_t index = 0; index < size; ++index) {
        text += digits[bytes[index] >> 4];
        text += digits[bytes[index] & 15];
    }
    return text;
}

// Child exit codes: 0 ok, 20 load failed, 21 SHA256 returned null, 22 wrong digest,
// 30 the pass returned an error, 31 wrong or missing module identity.
[[noreturn]] void run_sha256(bool use_dlmopen, int keys, const Options& options)
{
    set_thread_values(keys);
    void* handle = load(use_dlmopen, options.get("--probe-library"));
    if (handle == nullptr) _exit(20);
    using hash_type = int (*)(const char*, unsigned long, unsigned char*);
    auto hash = reinterpret_cast<hash_type>(dlsym(handle, "hbfsim_probe_sha256"));
    if (hash == nullptr) _exit(20);
    unsigned char digest[32];
    if (hash(kProbeText, std::strlen(kProbeText), digest) != 0) _exit(21);
    _exit(hex(digest, sizeof digest) == options.get("--text-sha256") ? 0 : 22);
}

[[noreturn]] void run_pass(bool use_dlmopen, int keys, const Options& options,
                           const std::string& manifest)
{
    set_thread_values(keys);
    std::ifstream input(options.get("--ptx"));
    const std::string ptx{std::istreambuf_iterator<char>(input), {}};
    const nlohmann::json request{
        {"input",
         {{"full_ptx", ptx},
          {"to_patch_kernel", options.get("--kernel")},
          {"global_ebpf_map_info_symbol", "map_info"},
          {"ebpf_communication_data_symbol", "constData"}}},
        {"ebpf_instructions", nlohmann::json::array()},
    };
    setenv("HBFSIM_PASS_MANIFEST_PATH", manifest.c_str(), 1);
    void* handle = load(use_dlmopen, options.get("--pass"));
    if (handle == nullptr) _exit(20);
    using process_type = int (*)(const char*, int, char*);
    auto process = reinterpret_cast<process_type>(dlsym(handle, "process_input"));
    if (process == nullptr) _exit(20);
    std::vector<char> output(16 * 1024 * 1024);
    if (process(request.dump().c_str(), static_cast<int>(output.size()),
                output.data()) != 0) {
        _exit(30);
    }
    std::ifstream written(manifest);
    std::string line;
    if (!std::getline(written, line)) _exit(31);
    const auto module = nlohmann::json::parse(line).value("module_id", "");
    _exit(module == "ptx:sha256:" + options.get("--ptx-sha256") ? 0 : 31);
}

std::string describe(int status)
{
    if (WIFSIGNALED(status)) {
        return "CRASH (signal " + std::to_string(WTERMSIG(status)) + ")";
    }
    switch (WEXITSTATUS(status)) {
    case 0: return "OK";
    case 20: return "LOAD_FAILED";
    case 21: return "SHA256_RETURNED_NULL";
    case 22: return "WRONG_DIGEST";
    case 30: return "PASS_ERROR";
    case 31: return "WRONG_MODULE_IDENTITY";
    default: return "EXIT " + std::to_string(WEXITSTATUS(status));
    }
}

void print_openssl_version(const Options& options)
{
    const pid_t child = fork();
    if (child == 0) {
        void* handle = dlopen(options.get("--probe-library").c_str(), RTLD_NOW | RTLD_LOCAL);
        using version_type = const char* (*)();
        auto version = handle == nullptr ? nullptr
            : reinterpret_cast<version_type>(dlsym(handle, "hbfsim_probe_openssl_version"));
        std::printf("libcrypto: %s\n", version == nullptr ? "unavailable" : version());
        std::fflush(stdout);
        _exit(version == nullptr ? 1 : 0);
    }
    int status = 0;
    waitpid(child, &status, 0);
}

}  // namespace

int main(int argc, char** argv)
{
    Options options;
    for (int index = 1; index + 1 < argc; index += 2) {
        options.values[argv[index]] = argv[index + 1];
    }
    for (const char* key : {"--probe-library", "--text-sha256", "--pass", "--ptx",
                            "--ptx-sha256", "--kernel", "--work-dir"}) {
        if (argc % 2 == 0 || options.get(key).empty()) {
            std::fprintf(stderr,
                "usage: %s --probe-library LIB --text-sha256 HEX --pass LIB --ptx FILE "
                "--ptx-sha256 HEX --kernel NAME --work-dir DIR [--keys N]\n"
                "  --text-sha256 is the SHA-256 of \"%s\"\n", argv[0], kProbeText);
            return 64;
        }
    }
    const int keys = options.get("--keys").empty() ? 64 : std::atoi(options.get("--keys").c_str());
    std::printf("glibc: %s\n", gnu_get_libc_version());
    std::fflush(stdout);
    print_openssl_version(options);
    std::printf("%-7s %-34s %-12s %s\n", "target", "loader", "added keys", "result");
    bool patched_ok = true;
    std::string dlmopen_hazard;
    int case_number = 0;
    for (const bool pass_target : {false, true}) {
        for (const bool use_dlmopen : {false, true}) {
            for (const int added : {0, keys}) {
                const auto manifest = options.get("--work-dir") + "/pass-loader-probe-" +
                    std::to_string(getpid()) + "-" + std::to_string(case_number++) + ".jsonl";
                std::remove(manifest.c_str());
                std::fflush(stdout);
                const pid_t child = fork();
                if (child == 0) {
                    if (pass_target) run_pass(use_dlmopen, added, options, manifest);
                    run_sha256(use_dlmopen, added, options);
                }
                int status = 0;
                waitpid(child, &status, 0);
                std::remove(manifest.c_str());
                const auto result = describe(status);
                std::printf("%-7s %-34s %-12d %s\n", pass_target ? "pass" : "sha256",
                    use_dlmopen ? "dlmopen(LM_ID_NEWLM), before 0003"
                                : "dlopen+RTLD_DEEPBIND, bpftime 0003",
                    added, result.c_str());
                if (!use_dlmopen && result != "OK") patched_ok = false;
                if (use_dlmopen && result != "OK" && dlmopen_hazard.empty()) dlmopen_hazard = result;
            }
        }
    }
    std::printf("verdict: patched pass loader %s\n", patched_ok ? "OK" : "FAILED");
    std::printf("verdict: dlmopen hazard in this environment: %s\n",
        dlmopen_hazard.empty() ? "not observed with these keys (not a proof of safety)"
                               : ("PRESENT, first result " + dlmopen_hazard).c_str());
    return patched_ok ? 0 : 1;
}
