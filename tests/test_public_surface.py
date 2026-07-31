from __future__ import annotations

import struct
from html.parser import HTMLParser
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).parents[1]
SOCIAL_IMAGE_URL = (
    "https://gyubin02.github.io/control-assurance-lab/social-preview.png"
)


class _HeadMetadata(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.meta: dict[str, str] = {}

    def handle_starttag(
        self,
        tag: str,
        attributes: list[tuple[str, str | None]],
    ) -> None:
        if tag != "meta":
            return
        values = dict(attributes)
        key = values.get("property") or values.get("name")
        content = values.get("content")
        if key is not None and content is not None:
            self.meta[key] = content


def _png_dimensions(path: Path) -> tuple[int, int]:
    payload = path.read_bytes()
    assert payload.startswith(b"\x89PNG\r\n\x1a\n")
    assert payload[12:16] == b"IHDR"
    return struct.unpack(">II", payload[16:24])


def test_public_pages_share_one_exact_social_card() -> None:
    assert _png_dimensions(REPOSITORY_ROOT / "site/social-preview.png") == (1280, 640)

    for relative in ("site/index.html", "web/index.html"):
        parser = _HeadMetadata()
        parser.feed((REPOSITORY_ROOT / relative).read_text())
        assert parser.meta["og:title"] == (
            "Nothing left the system. The first control still failed."
        )
        assert parser.meta["og:image"] == SOCIAL_IMAGE_URL
        assert parser.meta["og:image:alt"] == (
            "Control Assurance Lab launch card beside the change desk interface"
        )
        assert parser.meta["og:image:width"] == "1280"
        assert parser.meta["og:image:height"] == "640"
        assert parser.meta["twitter:card"] == "summary_large_image"


def test_readme_images_keep_their_documented_capture_sizes() -> None:
    assert _png_dimensions(
        REPOSITORY_ROOT / "docs/assets/control-plane-hero.png"
    ) == (1600, 900)
    assert _png_dimensions(REPOSITORY_ROOT / "docs/assets/readme-hero.png") == (
        1440,
        960,
    )
