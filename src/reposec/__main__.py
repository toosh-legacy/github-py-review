"""Allow `python -m reposec` as well as the installed `reposec` command.

Useful from a source checkout, and in containers where the console script's
shebang would point at the wrong interpreter.
"""
from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
