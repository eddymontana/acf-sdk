"""
Data models for the ACF SDK.

Decision  — ALLOW | SANITISE | BLOCK enum returned by all hook calls.
SanitiseResult — returned on SANITISE decisions; contains sanitised payload and targets.
ChunkResult    — returned by on_context; per-chunk decision and sanitised text.
"""
