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
import configparser
import json


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


def sha256(string):
    m = hashlib.sha256()
    m.update(string.encode('utf-8'))
    return m.hexdigest()


def file_age(filepath):
    return time.time() - os.path.getmtime(filepath)


def run_command(command):
    return subprocess.run(command, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=False)


def run_get_stdout(command, ignore_errors=False):
    """
    Run a command and forward its stdout and stderr if exit code is nonzero,
    otherwise return stdout.
    """
    result = run_command(command)
    if not ignore_errors and result.returncode != 0:
        raise Exception(f"Bad exit code when running: {command}")
    return result.stdout.decode("utf-8")


def remove_o_flag(compile_args):
    if "-o" in compile_args:
        oflag_index = compile_args.index('-o')
        return compile_args[:oflag_index] + compile_args[oflag_index + 2:]
    return compile_args


def postprocess_source(source, config):
    def hash_replace(match):
        return match.group(0).replace(match.group(1), len(match.group(1)) * "0")
    replacements = []
    if config.get("preprocessor", "strip_string_versions", fallback=True):
        replacements.append(
            (r'("[^"^\n]*?)([0-9]+(\.[0-9]+)+)', r'\1<version>'))
    if config.get("preprocessor", "strip_string_hex_hashes", fallback=True):
        replacements.append((r'"[^"^\n]*?([0-9a-fA-F]{5,128})', hash_replace))
    for pattern, replacement in replacements:
        changedSource = re.sub(pattern, replacement, source)
        attempts = 0
        while changedSource != source and attempts < 20:
            source = changedSource
            changedSource = re.sub(pattern, replacement, source)
            attempts += 1
    return source


def get_preproc_hash(compile_args, config):
    compile_args = remove_o_flag(compile_args)
    preproc_flag = "-E"
    keep_comments_flag = config.get(
        "preprocessor", "preserve_comments", fallback="-C")
    preproc_command = config.get("preprocessor", "command", fallback="c++")
    preproc_source = run_get_stdout(
        preproc_command.split() + compile_args + [preproc_flag, keep_comments_flag],
        config.getboolean("preprocessor", "ignore_errors", fallback=False))
    verbose = config.getboolean("behavior", "verbose", fallback=False)
    if verbose:
        print("cltcache length of preproccesed source:", len(preproc_source))
    postproc_source = postprocess_source(preproc_source, config)
    if verbose:
        print("cltcache length of postproccesed source:", len(postproc_source))
    preproc_hash = sha256(postproc_source)
    return preproc_hash


def compute_cache_key(clang_tidy_call, config):
    clang_tidy = clang_tidy_call[0]

    clang_tidy_args_with_value = ["--checks", "--config", "--config-file", "--export-fixes", "--extra-arg", "--extra-arg-before", "--format-style", "--header-filter", "--line-filter", "--load", "--store-check-profile", "--vfsoverlay", "--warnings-as-errors"]
    
    build_path_next_arg = False
    build_path_value = None
    clang_tidy_files = []
    ignore_next_arg = False
    compile_args = None
    arg_index = 0
    for arg in clang_tidy_call[1:]:
        arg_index += 1
        if ignore_next_arg:
            ignore_next_arg = False
            break
        if build_path_next_arg:
            build_path_value = arg
            build_path_next_arg = False
        elif not arg.startswith("-"):
            clang_tidy_files.append(arg)
        elif (arg == "-p"):
            build_path_next_arg = True
        elif arg.startswith("-p="):
            build_path_value = arg[3:]
        elif (arg == "--"):
            compile_args = clang_tidy_call[arg_index + 1:]
            break
        elif arg in clang_tidy_args_with_value:
            ignore_next_arg = True

    if (compile_args is None) and (build_path_value is None):
        raise Exception("Could not read compilation arguments: use either '--' or '-p' mechanisms")

    clang_tidy_args = clang_tidy_call[1:arg_index]

    if build_path_value is not None:
        if not clang_tidy_files:
            raise Exception("No source file found: this is required when using the build patch mechanism")
        if len(clang_tidy_files) != 1 :
            raise Exception("cltcache does not support multiple files processing")
        clang_tidy_file = clang_tidy_files[0]
        compile_commands_file = open(os.path.dirname(build_path_value)+"/compile_commands.json")
        compile_commands = json.load(compile_commands_file)
        for command in compile_commands:
            if command['file'] == clang_tidy_file:
                compile_args = command['command'].split()
                break
        compile_commands_file.close()

    if compile_args is None:
        raise Exception("No compilation found for source file")
    
    preproc_hash = get_preproc_hash(compile_args, config)

    version_out = run_get_stdout([clang_tidy] + ["--version"])
    version = ",".join(re.findall(r'[0-9]+\.[0-9]+\.?[0-9]*', version_out))
    version_hash = sha256(version)

    clang_config = run_get_stdout(
        [clang_tidy] + clang_tidy_args + ["--dump-config"])
    clang_config_hash = sha256(clang_config)

    return sha256(preproc_hash + clang_config_hash + version_hash)[:-16]


def init_cltcache():
    cltcache_path = os.environ.get(
        "CLTCACHE_DIR", pathlib.Path().home() / ".cltcache")
    cltcache_path.mkdir(parents=True, exist_ok=True)
    config = configparser.ConfigParser()
    config.read(cltcache_path / "cltcache.cfg")
    return cltcache_path, config


def cache_clang_tidy(clang_tidy_call):
    cltcache_path, config = init_cltcache()
    cache_path, cat_path, out_path, err_path = (None, None, None, None)
    verbose = config.getboolean("behavior", "verbose", fallback=False)
    if verbose:
        print("cltcache computing cache key")
    try:
        cache_key = compute_cache_key(clang_tidy_call, config)
        if verbose:
            print("cltcache key:", cache_key)
        cat_path = cltcache_path / cache_key[0]
        cache_path = cat_path / cache_key
        out_path = cache_path.with_suffix(".out.gz")
        err_path = cache_path.with_suffix(".err.gz")
        if os.path.exists(cache_path):
            if verbose:
                print("cltcache hit!")
            if os.path.exists(out_path):
                clang_tidy_stdout = decompress_from_file(out_path)
                if clang_tidy_stdout:
                    print(clang_tidy_stdout.decode("utf-8"),)
            if os.path.exists(err_path):
                clang_tidy_stderr = decompress_from_file(err_path)
                if clang_tidy_stderr:
                    print(clang_tidy_stderr.decode("utf-8"), file=sys.stderr,)
            sys.exit(int(read_from_file(cache_path)))
        elif verbose:
            print("cltcache miss...")
    except Exception as e:
        if verbose:
            print("cltcache", e)
            print(
                "cltcache Preprocessing failed! Forwarding call without caching...",
                file=sys.stderr)
    result = run_command(clang_tidy_call)
    clt_success = result.returncode == 0
    preproc_success = cache_path is not None
    cache_results = (clt_success or config.getboolean(
        "behavior", "cache_failure", fallback=True)) and preproc_success
    if cache_results:
        cat_path.mkdir(parents=True, exist_ok=True)
    if result.stdout:
        print(result.stdout.decode("utf-8"),)
        if cache_results:
            compress_to_file(result.stdout, out_path)
    if result.stderr:
        print(result.stderr.decode("utf-8"), file=sys.stderr,)
        if cache_results:
            compress_to_file(result.stderr, err_path)
    if cache_results:
        if verbose:
            print("cltcache caching results...")
        save_to_file(str(result.returncode), cache_path)
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
