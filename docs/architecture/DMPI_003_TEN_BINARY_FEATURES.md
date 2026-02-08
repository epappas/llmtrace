# DMPI-003: 10 Binary Features Instead of 15 Mixed

**Status:** Done
**Deviation:** DMPI-003, DMPI-005 (see TODO.md, FEATURE_ROADMAP.md section 3.4.1a)
**Paper:** DMPI-PMHFE (arXiv 2506.06384), Appendix A

---

## 1. Problem Statement

The DMPI-PMHFE paper specifies exactly **10 binary (0/1) features** in the heuristic feature vector. The previous implementation had 15 features (8 binary + 7 numeric), deviating from the paper in three ways:

1. **7 extra numeric features** (injection count, max confidence, PII count, secret leakage count, text length, special char ratio, avg word length) have no paper equivalent.
2. **3 missing paper features** (`is_ignore`, `is_format_manipulation`, `is_immoral`) were not implemented.
3. **Feature ordering** did not match the paper's Appendix A table.

Training on this 15-dim architecture would not reproduce paper results.

---

## 2. Scope

### In Scope (DMPI-003 + DMPI-005)

- Change `HEURISTIC_FEATURE_DIM` from 15 to 10
- Remove `MAX_TEXT_LENGTH` and `INJECTION_TYPES` constants
- Replace `ATTACK_CATEGORIES` with `FINDING_BASED_FEATURES` mapping (index, finding_type)
- Add 3 keyword arrays: `IGNORE_KEYWORDS`, `FORMAT_MANIPULATION_KEYWORDS`, `IMMORAL_KEYWORDS`
- Add `text_contains_any_keyword()` helper
- Rewrite `extract_heuristic_features()`: 7 finding-based + 3 keyword-based, all binary
- Remove all numeric feature code (indices 8-14)
- Rewrite tests for new feature layout
- Update `fusion_classifier.rs` doc comments and `test_fusion_input_dim`

### Out of Scope

- Changes to `lib.rs` regex patterns (unchanged)
- Feature naming alignment (DMPI-006, deferred)
- Repetition threshold change (DMPI-004, separate)
- Training or fine-tuning weights

---

## 3. Architecture

### Before (15 mixed features)

| Index | Feature | Type |
|-------|---------|------|
| 0 | Flattery attack present | Binary |
| 1 | Urgency attack present | Binary |
| 2 | Roleplay attack present | Binary |
| 3 | Impersonation attack present | Binary |
| 4 | Covert attack present | Binary |
| 5 | Excuse attack present | Binary |
| 6 | Many-shot attack present | Binary |
| 7 | Repetition attack present | Binary |
| 8 | Number of injection patterns | Numeric |
| 9 | Max injection confidence score | Numeric |
| 10 | PII pattern count | Numeric |
| 11 | Secret leakage count | Numeric |
| 12 | Text length (normalised) | Numeric |
| 13 | Special character ratio | Numeric |
| 14 | Average word length | Numeric |

### After (10 binary features, paper-aligned)

| Index | Paper Name | Detection Method |
|-------|-----------|-----------------|
| 0 | is_ignore | Keyword-in-text: ignore, reveal, disregard, forget, overlook, regardless |
| 1 | is_urgent | Finding: is_urgent |
| 2 | is_incentive | Finding: is_incentive |
| 3 | is_covert | Finding: is_covert |
| 4 | is_format_manipulation | Keyword-in-text: encode, disguising, morse, binary, hexadecimal |
| 5 | is_hypothetical | Finding: is_hypothetical |
| 6 | is_systemic | Finding: is_systemic |
| 7 | is_immoral | Keyword-in-text: hitting, amoral, immoral, deceit, irresponsible, offensive, violent, unethical, smack, fake, illegal, biased |
| 8 | is_shot_attack | Finding: is_shot_attack |
| 9 | is_repeated_token | Finding: is_repeated_token |

---

## 4. Design Decisions

### Keyword-in-text checks (not regex patterns in lib.rs)

The 3 new features (`is_ignore`, `is_format_manipulation`, `is_immoral`) use simple keyword matching in `feature_extraction.rs` rather than adding new regex patterns to `lib.rs`. Rationale:

- **Paper-faithful:** the paper tokenizes text and checks for keyword presence. These are classifier INPUT signals, not security findings.
- **Self-contained:** all changes stay in `feature_extraction.rs`.
- **Avoids polluting** the SecurityFinding pipeline with low-confidence keyword matches.

### Keyword matching semantics

- Case-insensitive
- Whitespace-split tokenization
- Punctuation stripped (non-alphanumeric chars removed from each token)
- Exact match only: "ignore" matches "ignore" and "Ignore!" but NOT "ignoring"

### is_immoral (formerly excuse_attack) stays in lib.rs

Its regex patterns still emit findings for the pipeline; they just no longer feed the feature vector. DMPI-006 (rename) resolved.

---

## 5. Dimension Impact

| Component | Before | After |
|-----------|--------|-------|
| `HEURISTIC_FEATURE_DIM` | 15 | 10 |
| `FUSION_INPUT_DIM` | 783 | 778 |
| fc1 layer | Linear(783, 256) | Linear(778, 256) |
| Feature types | 8 binary + 7 numeric | 10 binary |

---

## 6. File Changes

| File | Change |
|------|--------|
| `feature_extraction.rs` | Rewrote: dim 15->10, removed numeric features, added keyword detection, reordered to paper spec |
| `fusion_classifier.rs` | Updated doc comments (15-dim->10-dim, 783->778), updated `test_fusion_input_dim` |

### Unchanged Files

- `ensemble.rs` -- calls `extract_heuristic_features(findings, text)`, passes result to `predict()`. Both signature and flow unchanged.
- `lib.rs` -- regex patterns unchanged, finding types unchanged, export of `HEURISTIC_FEATURE_DIM` auto-reflects new value.

---

## 7. Testing

| Test | Validates |
|------|-----------|
| `test_feature_dim_constant` | `HEURISTIC_FEATURE_DIM == 10` |
| `test_empty_findings_empty_text` | Zero vector for empty input |
| `test_finding_based_features_indices` | Each finding maps to correct index |
| `test_keyword_ignore_case_insensitive` | Case-insensitive keyword matching |
| `test_keyword_ignore_with_punctuation` | Punctuation stripped before matching |
| `test_keyword_no_partial_match` | "ignoring" does NOT match "ignore" |
| `test_keyword_format_manipulation` | Format manipulation keywords detected |
| `test_keyword_immoral` | Immoral keywords detected |
| `test_combined_findings_and_keywords` | Findings + keywords produce correct vector |
| `test_all_features_active` | All 10 features can be 1.0 simultaneously |
| `test_all_values_binary` | Every feature is exactly 0.0 or 1.0 |
| `test_unrelated_findings_ignored` | Non-mapped findings produce zero vector |
| `test_fusion_input_dim` | `768 + 10 = 778` |

---

## 8. Risk Assessment

| Risk | Mitigation |
|------|-----------|
| Breaking trained weights | No trained weights exist (random initialization only) |
| Numeric feature information loss | Paper does not use these features; they are not part of the trained architecture |
| Keyword false positives | Exact whole-word match only; no partial/stemmed matching |
| is_immoral naming | Finding type renamed from excuse_attack to is_immoral per DMPI-006. |

---

## 9. Paper Reference

DMPI-PMHFE (arXiv 2506.06384), Appendix A:

> Table A.1: Heuristic Feature Vector -- 10 binary features extracted from tokenized and lemmatized input text. Features 1-8 are semantic-based (keyword presence via WordNet synonym expansion), features 9-10 are structure-based (pattern matching with threshold >= 3).
