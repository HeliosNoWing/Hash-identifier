# hashin

A tiny hash identifier I'm building to learn Python.

You give it a hash string, it tells you what it's *probably* made with —
MD5, SHA-1, Argon2id, MySQL5, that kind of thing.

Heads up: this does not *crack* anything. It just looks at the shape of a
string and guesses. Hashes are ambiguous by nature, so it returns a list of
candidates with a confidence level, not one definitive answer.

## Why this exists

I'm learning Python. This is a learning project, not a tool you should
actually rely on. I picked "hash identifier" because:

- the domain is small enough to fit in one file
- there are clear right/wrong answers to test against
- it forced me to learn dataclasses, type hints, and CLI argument parsing
- I get to use `rich` and make a colourful table, which is fun

If you're also learning, feel free to read the source. I've tried to leave
comments explaining the *why*, not just the *what*.

## What it can spot

| Pattern | Guesses |
| --- | --- |
| starts with `$argon2id$` / `$argon2i$` | Argon2 family |
| `*` + 40 uppercase hex chars | MySQL5 |
| 13 chars from the crypt(3) alphabet | DES crypt |
| all hex, 16 chars | MySQL323, CRC-64 |
| all hex, 32 chars | MD5, NTLM, MD4, RIPEMD-128 |
| all hex, 40 chars | SHA-1, RIPEMD-160 |
| colon-separated, 6+ fields | NetNTLMv1 / NetNTLMv2 |
| `$algo$...` | generic PHC string |
| starts with `eyJ` | JWT (not a hash, sorry) |
| contains `+ / =` and is long | probably base64, not a hash |

Most of these are ambiguous. A 32-char hex string could be MD5 *or* NTLM
*or* MD4 *or* RIPEMD-128 — the string alone can't tell you which. So the
tool ranks them.

## Running it

Needs Python 3.10+ (I use `slots=True` on a dataclass) and `rich`.

```sh
pip install rich
python3 hashin.py d41d8cd98f00b204e9800998ecf8427e
python3 hashin.py '*6BB4837EB74329105EE4568DDA7DC67ED2CA2AD9'
python3 hashin.py --top 3 5d41402abc4b2a76b9719d911017c592
