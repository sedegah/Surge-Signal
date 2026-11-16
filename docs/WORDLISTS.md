# Wordlist library and candidate preparation

## Design goal

A serious Wi-Fi password audit needs more than one giant list. SURGE Signal uses a
modular library with provenance, category priority, safe import, WPA length
filtering, exact deduplication and candidate caps. The application **does not
bundle** third-party corpora or silently download leaked credentials.

## Managed layout

```text
%LOCALAPPDATA%\SurgeSignal\wordlists\
├── common\          rockyou, common password collections
├── wifi\            Wi-Fi-specific patterns and default keys
├── default\         vendor/default credentials
├── regional\        approved language and regional lists
├── comprehensive\   SecLists, Weakpass, CrackStation, Probable-Wordlists
├── custom\          engagement-specific lists
├── leaked\          lawfully held exposed-password corpus
├── prepared\        generated, deduplicated audit candidate files
└── metadata\
    └── wordlist-index.json
```

Each indexed list records name, absolute path, category, priority, line count,
minimum/maximum candidate length, size, SHA-256, source, catalog id, prepared status
and last scan time.

## Curated catalog — 13 entries

| # | Collection | Category | Priority | Essential | Intended use |
|---|---|---|---|---|---|
| 1 | RockYou | Common | 30 | Yes | Baseline common-password corpus |
| 2 | SecLists | Comprehensive | 60 | Yes | Broad maintained security lists; import only needed files |
| 3 | Weakpass | Comprehensive | 60 | Yes | Large curated password collections |
| 4 | Probable-Wordlists | Common | 30 | Yes | Probability-ordered likely candidates |
| 5 | CrackStation | Comprehensive | 60 | Yes | Large human-only breach-derived dictionary |
| 6 | Wi-Fi password patterns | Wi-Fi specific | 10 | Yes | SSID/location/router-derived candidate patterns |
| 7 | Default router credentials | Default credentials | 20 | Yes | Factory/vendor credentials for lab gear |
| 8 | Default Wi-Fi keys | Wi-Fi specific | 10 | Yes | Known factory WPA keys and patterns |
| 9 | Ghana contextual passwords | Regional | 40 | Yes | Approved Ghanaian names, places and patterns |
| 10 | West Africa contextual passwords | Regional | 40 | Yes | Approved regional names and language patterns |
| 11 | Language packs | Regional | 40 | No | Language-specific dictionaries and transliterations |
| 12 | Custom contextual list | Custom | 50 | Yes | Engagement-specific approved context |
| 13 | Pwned Passwords corpus | Leaked | 70 | No | Lawfully held breach corpus / HIBP range checking |

Ten entries are marked essential, matching the recommendation to start with 10
curated lists and expand to 15 as the practice matures. The catalog is metadata only;
the official source links, licensing notes and guidance are shown in the
**Curated catalog** tab.

### Acquisition rules

1. Download only from the official source, not from random mirrors.
2. Review the licence and any data-protection obligations before import.
3. Import only the files relevant to the authorised engagement.
4. Do not import personal data without a lawful basis.
5. Do not redistribute corpora unless the licence permits it.
6. Treat wordlists as sensitive assessment material and keep them under the
   application's per-user data directory.

## Import behaviour

- Supported files: `.txt`, `.lst`, `.dic`, `.csv`, `.gz`.
- `.gz` is decompressed into a managed `.txt` copy with a 2 GB decompressed limit.
- Files are copied into the selected category, hashed and inspected in one pass.
- Blank lines are counted as skipped; line count and min/max length describe actual
  candidates.
- The library index (`metadata/wordlist-index.json`) is regenerated after import,
  scan or removal.

## Candidate preparation

Select one or more lists and choose **Prepare candidate list**. The pipeline:

1. **Orders sources by category priority**:
   Wi-Fi (10) → Default (20) → Common (30) → Regional (40) → Custom (50) →
   Comprehensive (60) → Leaked (70).
2. **Reads** every candidate as bytes, rejects invalid UTF-8 and control characters.
3. **Filters by length**; the default WPA policy is 8–63 characters.
4. **Deduplicates exactly** using a 128-bit BLAKE2 digest in a temporary SQLite
   staging table. Original case and characters are preserved.
5. **Caps** output at the configured candidate budget (default 1,000,000) to keep
   runtime predictable.
6. **Writes** a prepared UTF-8 file in insertion order, so high-priority categories
   are tested first.
7. **Hashes and records** the prepared list, source list names and statistics.
8. **Prunes** older prepared files according to the retention setting.

Progress reports scanned candidates, accepted candidates, rate and ETA. A prepared
file can be reused across audits until it is pruned or removed.

### Why deduplicate?

Overlapping lists waste time and produce misleading candidate counts. Deduplication
gives a truthful budget and ensures a high-priority list is not delayed behind
thousands of duplicate common passwords.

### Candidate caps and engine choice

| Engine | Best use | Candidate throughput | Notes |
|---|---|---|---|
| Local WPA2 verifier | Focused authorised test, no Kali | Dozens/second | Pure Python PBKDF2 + MIC verification; complete msg1/msg2 handshake required |
| Aircrack-ng in Kali | Large lists | Much higher | Requires configured WSL/SSH Kali and aircrack-ng; local paths mapped to `/mnt/...` |

The local verifier's cap is configurable in Settings and in the audit screen. Use the
ETA rather than assuming a large list will finish quickly.

## Selection strategy

A practical authorised assessment might use:

1. **Wi-Fi patterns** and **default Wi-Fi keys** — smallest, most likely for lab gear.
2. **Custom contextual** — engagement-specific approved terms.
3. **RockYou / Probable-Wordlists** — broad human-chosen passwords.
4. **Regional** — only where relevant to the organisation and lawful.
5. **Comprehensive** — only when the engagement explicitly permits the runtime.
6. **Leaked corpus** — only with a lawful basis and a specific objective.

Do not blindly merge every list. Record why each source was selected in the
assessment notes or evidence.

## Removal and retention

**Remove record** removes the index entry; the file remains on disk. Delete files
manually if your retention policy requires it. Prepared lists are pruned
automatically; the prepared directory should be reviewed at the end of an
engagement.

The application sets a restrictive Windows ACL on its data directory but does not
encrypt wordlist files at rest. Use BitLocker/EFS or organisational controls where
required.

