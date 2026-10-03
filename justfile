# Hashin — task runner
# list tasks:  just --list

set shell := ["bash", "-uc"]
set positional-arguments

# Python to use. Override: just python=python3.12 run ...
python := "python3"

# Default recipe — runs when you type bare `just`
default:
    @just --list

# Install runtime + dev dependencies
install:
    {{python}} -m pip install --upgrade pip
    {{python}} -m pip install rich ruff mypy pytest

# Run the identifier on a hash: just run '$argon2id$v=19$...'
run *args:
    {{python}} hashin.py "$@"

# Lint with ruff
lint:
    {{python}} -m ruff check .

# Auto-format with ruff
fmt:
    {{python}} -m ruff format .

# Type-check with mypy
typecheck:
    {{python}} -m mypy hashin.py

# Run the test suite
test:
    {{python}} -m pytest -q

# Everything CI should run
check: lint typecheck test

# Smoke-test a few well-known hashes
demo:
    @echo "── argon2id ──"
    {{python}} hashin.py '$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG'
    @echo "── MD5 ──"
    {{python}} hashin.py d41d8cd98f00b204e9800998ecf8427e
    @echo "── MySQL5 ──"
    {{python}} hashin.py '*6BB4837EB74329105EE4568DDA7DC67ED2CA2AD9'

# Remove caches
clean:
    find . -type d -name __pycache__ -prune -exec rm -rf {} +
    rm -rf .pytest_cache .mypy_cache .ruff_cache
