# PoC: EWF media extraction via pyewf, against the real `forensic2` evidence

## Versions pinned (verified live, not assumed)

- `pyewf` (package `libewf-python==20240506`) -- already installed in
  `celery-worker-plaso`, a transitive dependency of `dfvfs` (20260731),
  which Plaso (`plaso==20260512`, `docker/Dockerfile.plaso-worker`) already
  requires. **No new dependency was added.** Confirmed live:
  ```
  docker exec docker-celery-worker-plaso-1 python3 -c \
      "import pyewf; print(pyewf.get_version())"
  20240506
  ```
- `volatility3==2.28.0` (already pinned, `src/external/parsers/volatility.py`).

## Docs used

No official pyewf usage doc was reachable from this sandboxed environment
(no outbound internet from `celery-worker-plaso`). The exact installed
module's own introspected API was used as ground truth for this exact
pinned version instead:

```
docker exec docker-celery-worker-plaso-1 python3 -c "
import pyewf
print([x for x in dir(pyewf) if not x.startswith('_')])
h = pyewf.handle()
print([x for x in dir(h) if not x.startswith('_')])
"
```

This surfaced `pyewf.handle()`, `.open([filenames])`, `.read(size)`,
`.get_media_size()`, and `pyewf.glob()` -- the real API this PoC (and the
shipped `EwfContainerParser`) uses.

## Real evidence used

Case `43097ab0-aae3-4968-915b-8f0229ac3865`, evidence
`ab9a6e5d-4982-4d81-997d-1085170e2e39` ("forensic2") -- downloaded from
the real dev MinIO (`kronos-evidence-kronos-dev` bucket, key
`kronos-dev/43097ab0-aae3-4968-915b-8f0229ac3865/ab9a6e5d-4982-4d81-997d-1085170e2e39/forensic2`).
Real header bytes confirmed earlier this session: `45 56 46 09 0D 0A FF 00`
= genuine EWF/E01 magic.

## Real, decisive finding

`pyewf.glob()` requires a filename **with** a real EWF extension (`.E01`
etc.) to determine the segment-naming pattern -- it raises `OSError`
against the real evidence bytes, because KronOS's own MinIO storage
convention keys objects by UUID with no extension at all. Opening the
single real filename directly (`handle.open([path])`, no glob) works for
this single-segment EWF.

Extraction itself succeeded perfectly: `pyewf.handle.get_media_size()`
reported `615516160` bytes, and exactly that many bytes were read back out
via `.read()`.

**The real media payload is NOT memory.** Inspecting the first 512 bytes
of the extracted media shows a genuine POSIX `ustar` tar header:
- Bytes 0-100 (tar filename field): `b"image.dd\x00\x00..."`
- Bytes 257-263 (tar magic, the real fixed POSIX offset): `b"ustar "`
- Bytes 100-108 (tar mode field): `b"0000770\x00"`
- Bytes 124-136 (tar size field, octal): `b"00454000000\x00"`

Running volatility3's own real automagic (the exact `automagic.available`/
`choose_automagic`/`plugins.construct_plugin` pattern from
`poc/volatility_multiplugin/run_poc.py`) directly against these extracted
bytes finds **zero** `WindowsIntelStacker` DTB hits and fails with
`UnsatisfiedException` -- decisive, since this is a genuinely different
(and more informative) negative result than the already-diagnosed
`ch2.dmp`/`contact_me.dmp` case (which DOES find a real DTB but fails
later, at kernel-PDB-scan). Zero DTB hits here confirms the extracted
bytes are not raw memory at all.

This exact incident -- `forensic2.E01`-named evidence whose real payload
is a tar of `image.dd` + `memory.dmp` -- is **already a documented,
previously-fixed incident in this codebase**: `TarArchiveParser`'s own
module docstring (`src/external/parsers/tar_archive.py`) describes it
verbatim (roadmap E1). `TarArchiveParser` already correctly unwraps a raw
tar file and re-dispatches `image.dd` (to `PlasoParser`) and `memory.dmp`
(to `VolatilityModule`, extension-matched) -- **the only genuinely missing
piece is one layer higher**: nothing today unwraps an *EWF container whose
own media is itself a tar* before handing it to Plaso's disk-image walker.

## What this PoC proves is real and ready to build on

1. `pyewf` extraction works against the real evidence, with no new
   dependency.
2. The extracted bytes are byte-for-byte identical to what a bare tar
   upload's own header would look like (confirmed via the same offset-257
   `ustar` check `TarArchiveParser.supports()` already uses) -- so
   re-dispatching the extracted media through the existing `ParserRegistry`
   will correctly hand it to `TarArchiveParser`, no new container-detection
   logic needed beyond "ask the registry."
3. `src/external/parsers/ewf_container.py` (`EwfContainerParser`) implements
   exactly this: unwrap EWF, ask the registry what the real media matches,
   redispatch if it's a recognised container, else fall back to
   `PlasoParser` on the original EWF bytes unchanged (preserving today's
   correct behaviour for a genuine EWF disk image).

## How to reproduce

```
docker cp run_poc.py docker-celery-worker-plaso-1:/tmp/ewf_run_poc.py
docker exec docker-celery-worker-plaso-1 python3 /tmp/ewf_run_poc.py \
    /tmp/forensic2 /tmp/forensic2_extracted.raw
```

(Requires the real `forensic2` evidence bytes to be present at
`/tmp/forensic2` inside the container -- not committed to git, real
user-owned investigative data, same convention as every other PoC that
uses this org's real uploaded evidence.)

See `output.txt` for the full real captured output of the last run.
