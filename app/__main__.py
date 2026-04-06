"""CTF-Agent entry point for `python -m app`"""
import asyncio
from app.cli import main

if __name__ == "__main__":
    asyncio.run(main())
