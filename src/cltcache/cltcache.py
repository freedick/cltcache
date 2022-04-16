#!/usr/bin/env python3
"""
A simple clang-tidy caching application. Prefix calls to clang-tidy to cache
their results for faster static code analysis.
"""
import gzip
import hashlib
import os
import pathlib
import re
import subprocess
import sys
import time


def save_to_file_raw(data, filename):
    with open(filename, "wb") as f:
        f.write(data)


def save_to_file(string, filename):
    save_to_file_raw(string.encode("utf-8"), filename)


def compress_to_file(data, filename):
    save_to_file_raw(gzip.compress(data), filename)


def read_from_file_raw(filename):
    with open(filename, "rb") as f:
        return f.read()


def read_from_file(filename):
    return read_from_file_raw(filename).decode("utf-8")


def decompress_from_file(filename):
    return gzip.decompress(read_from_file_raw(filename))


def sha256file(filename):
    with open(filename, "rb") as f:
        m = hashlib.sha256()
        while True:
            contents = f.read(1 << 16)
            if not contents:
                return m.hexdigest()
            m.update(contents)


def sha256(string):
    m = hashlib.sha256()
    m.update(string.encode('utf-8'))
    return m.hexdigest()


def file_age(filepath):
    return time.time() - os.path.getmtime(filepath)


def run_command(command):
    return subprocess.run(command, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=False)


def run_get_stdout(command):
    """
    Run a command and forward its stdout and stderr if exit code is nonzero,
    otherwise return stdout.
    """
    result = run_command(command)
    if result.returncode != 0:
        print(result.stdout.decode("utf-8"),)
        print(result.stderr.decode("utf-8"), file=sys.stderr,)
        print("cltcache failed!", file=sys.stderr)
        sys.exit(result.returncode)
    return result.stdout.decode("utf-8")


def get_preproc_hash(compile_args):
    preproc_filename = sha256(" ".join(compile_args)) + "-cltcache.i"
    if "-o" in compile_args:
        oflag_index = compile_args.index('-o')
        preproc_filename = compile_args[oflag_index + 1] + "-cltcache.i"
    compile_args[oflag_index + 1] = preproc_filename
    preproc_flag = "-E"
    keep_comments_flag = "-CC"
    run_get_stdout(
        ["g++"] + compile_args + [preproc_flag, keep_comments_flag])
    preproc_hash = sha256file(preproc_filename)
    os.remove(preproc_filename)
    return preproc_hash


def compute_cache_key(clang_tidy_call):
    clang_tidy = clang_tidy_call[0]
    if "--" not in clang_tidy_call:
        print("Missing '--' flag in compiler options", file=sys.stderr)
        sys.exit(1)
    forwardflag_index = clang_tidy_call.index("--")
    compile_args = clang_tidy_call[forwardflag_index + 1:]
    clang_tidy_args = clang_tidy_call[1:forwardflag_index]

    preproc_hash = get_preproc_hash(compile_args)

    version_out = run_get_stdout([clang_tidy] + ["--version"])
    version = ",".join(re.findall(r'[0-9]+\.[0-9]+\.?[0-9]*', version_out))
    version_hash = sha256(version)

    enabled_checks = run_get_stdout(
        [clang_tidy] + clang_tidy_args + ["--list-checks"])
    enabled_checks_hash = sha256(enabled_checks)

    return sha256(preproc_hash + enabled_checks_hash + version_hash)[:-16]


def init_cltcache():
    cltcache_path = pathlib.Path().home() / ".cltcache"
    cltcache_path.mkdir(parents=True, exist_ok=True)
    return cltcache_path


def cache_clang_tidy(clang_tidy_call):
    cltcache_path = init_cltcache()
    cache_key = compute_cache_key(clang_tidy_call)
    cat_path = cltcache_path / cache_key[0]
    cache_path = cat_path / cache_key
    err_path = cache_path.with_suffix(".err.gz")
    out_path = cache_path.with_suffix(".out.gz")
    if os.path.exists(cache_path):
        if os.path.exists(out_path):
            clang_tidy_stdout = decompress_from_file(out_path)
            if clang_tidy_stdout:
                print(clang_tidy_stdout.decode("utf-8"),)
        if os.path.exists(err_path):
            clang_tidy_stderr = decompress_from_file(err_path)
            if clang_tidy_stderr:
                print(clang_tidy_stderr.decode("utf-8"), file=sys.stderr,)
        sys.exit(int(read_from_file(cache_path)))

    result = run_command(clang_tidy_call)
    cat_path.mkdir(parents=True, exist_ok=True)

    save_to_file(str(result.returncode), cache_path)
    if result.stdout:
        print(result.stdout.decode("utf-8"),)
        compress_to_file(result.stdout, out_path)
    if result.stderr:
        print(result.stderr.decode("utf-8"), file=sys.stderr,)
        compress_to_file(result.stderr, err_path)
    sys.exit(result.returncode)


def main():
    if len(sys.argv) <= 1:
        command = sys.argv[0]
        helptext = ("Usage:\n"
                    f"    {command}\n"
                    f"    {command} clang-tidy [clang-tidy options] -- "
                    "-o output [compiler options]")
        print(helptext)
    else:
        cache_clang_tidy(sys.argv[1:])


if __name__ == "__main__":
    main()
