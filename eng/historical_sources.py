# SPDX-License-Identifier: AGPL-3.0-only
"""Fetch locations of renamed historical repositories.

Committed policy and provenance records name the repository identity that a pinned commit was
recorded against, and those records stay immutable. On 2026-10-12 (ArcForges-Design AD-0001) the
historical design repository `ArcForges/ArcForges-Design` was renamed to
`ArcForges/ArcForges-Design-Parallel`, frozen at main 64173614, and the old name now belongs to a
new design repository that does not contain the historical commits. Pinned historical commits are
therefore fetched from the renamed repository. This is the only place that maps a recorded identity
to a different fetch location; every other identity is fetched from itself.
"""

from __future__ import annotations

FETCH_LOCATIONS = {
    'ArcForges/ArcForges-Design': 'ArcForges/ArcForges-Design-Parallel',
}


def fetch_repository(identity: str) -> str:
    """Return the `owner/name` repository that holds the commits recorded under `identity`."""
    return FETCH_LOCATIONS.get(identity, identity)


def fetch_url(identity: str) -> str:
    return f'https://github.com/{fetch_repository(identity)}.git'


def origin_urls(identity: str) -> set[str]:
    """Origins accepted for a checkout of `identity`: the recorded identity or its fetch location."""
    names = {identity, fetch_repository(identity)}
    return {url for name in names
            for url in (f'https://github.com/{name}', f'https://github.com/{name}.git', f'git@github.com:{name}.git')}
