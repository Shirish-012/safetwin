"""Write the example shop: a synthetic `customers` and `orders` table with planted personal data.

    python examples/shop/generate.py OUT_DIR [--customers N] [--csv]

The generator is `safetwin.demo` (also behind `safetwin demo DIR`); its docstring says what the data holds.
Never commit the output: examples/ holds the generator and the policy, not the data.
"""

from safetwin.demo import generate, main, write

__all__ = ["generate", "main", "write"]

if __name__ == "__main__":
    raise SystemExit(main())
