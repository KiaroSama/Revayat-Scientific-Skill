# Research evidence and adoption boundaries

## Further skill review — 2026-09-24

The following public repositories were inspected for reusable procedures. Their
code, examples, corpora, prompts, models and templates were not copied into this
package. The bundled `term-brief` and source-evidence guidance are independently
written for this project's existing ledger and any original source language.

| Primary source | Useful method | Boundary and decision |
| --- | --- | --- |
| [Persian skill](https://github.com/Mojtaba-Alehosseini/persian-skill) | Select only glossary entries that occur in a source; review Persian register, typography and idioms separately from source fidelity. | MIT repository, English–Persian focus. Adopt the source-filtered *method* through native `term-brief`; do not import its banks or automatic digit normalization, which could alter equations and original quotations. |
| [Scientific writing](https://github.com/K-Dense-AI/scientific-agent-skills/blob/main/skills/scientific-writing/SKILL.md), [library paper](https://arxiv.org/abs/2609.00065) | Locate claims and numbers in the original, distinguish verified evidence from search leads and missing details, and check confidentiality. | MIT skill; its manuscript drafting and optional Python 3.11 tools are outside this Python 3.10+ translation package. Adapt source-bound review guidance, not scripts or a claim of human verification. |
| [Academic paper engineering](https://github.com/Hongyuan-Lu/academic-paper-engineering) | Maintain section-specific translation/style memory and never silently change scientific numbers, formulas or references. | MIT repository; published translation direction is Chinese→English, not Chinese→Persian. Adopt section-role checks for any source language; do not bundle its publisher templates or pdflatex workflow. |
| [PARME](https://github.com/DOLMA-NLP/PARME), [license](https://github.com/DOLMA-NLP/PARME/blob/main/LICENSE) | English–Persian–regional-language alignment covers seven named low-resource languages; the Zazaki material instead pairs with English/Kurmanji. | MIT repository, general-domain sentences. Verify the exact variety, direction, corpus provenance and reuse terms for each job; no sentence is bundled or treated as reviewed Persian scientific gold. |

Kassis, T., Agarwal, V., He, Y., Patel, D., and Brueckner, A. M. (2026).
*Scientific Agent Skills: A Library of Procedural Knowledge for Research Agents*.
arXiv:2609.00065. [DOI](https://doi.org/10.48550/arXiv.2609.00065).

Initial review: 2026-09-14. The added skill review above is dated 2026-09-24.
These primary sources informed the skill's translation,
review and document-preservation rules. Lessons below are independently written;
no external model, library implementation, corpus or evaluation examples were
imported by this research. Repository and dataset licenses are separate checks.

A resource covering a language pair does not establish this skill's accuracy for
that pair, discipline or document format. Published scores belong to the systems
and evaluation sets in their papers. A reported issue is evidence to investigate,
not a reproduced defect in every version or renderer.

## Persian scientific prose and terminology

| Source | Verified lesson | Scope or license caveat | Adoption in this skill |
| --- | --- | --- | --- |
| [Persian writing: academic register](https://github.com/ali2000hos/persian-writing/blob/main/references/academic.md), [register selection](https://github.com/ali2000hos/persian-writing/blob/main/references/writing-style.md) | Academic register permits measured passive constructions and familiar Persian technical terms. Select register from the deliverable, not the conversational request. | [MIT](https://github.com/ali2000hos/persian-writing/blob/main/LICENSE); authoring guidance is not a translation contract. Its [evaluation prompts](https://github.com/ali2000hos/persian-writing/blob/main/evals/evals.json) do not establish bilingual scientific accuracy. | Judge scholarly verbs in context; preserve claims and source structure. Do not import blanket word bans, invented examples, bibliography reordering or automatic numeral conversion. |
| [QuantEcon Persian glossary](https://github.com/QuantEcon/action-translation/blob/main/glossary/fa.json), [glossary contract](https://github.com/QuantEcon/action-translation/blob/main/docs/user/glossary.md) | Scientific equivalents need discipline context; drafting and review must use the same selected glossary. An unreadable explicit glossary must not silently fall back. | [MIT](https://github.com/QuantEcon/action-translation/blob/main/LICENSE); individual entries are candidates, not universal terminology rulings. | Carry the selected `terms.tsv` revision through drafting, correction and resumption; prefer established Persian concepts in journal prose. |
| [Persian ML glossary: bias discussion](https://github.com/erfannoury/persian-ml-glossary/issues/2) | Selection bias, estimator bias and neural-network bias cannot be resolved by a context-free word replacement. | [MIT](https://github.com/erfannoury/persian-ml-glossary/blob/master/LICENSE); discussion contains proposals and disagreement. | Record separate concept/sense decisions; mark uncertain equivalents and retain a lookup designation where useful. |
| [Persian algorithm article](https://github.com/2077DevWave/cp-algorithms-fa/blob/main/src/num_methods/binary_search.md) | The article marks its AI-generated translation status and keeps mathematical notation distinct from Persian explanation. | [CC BY-SA 4.0](https://github.com/2077DevWave/cp-algorithms-fa/blob/main/LICENSE); this AI-tagged article is not a reviewed gold reference. | Report which sections were drafted and which actually received source-based review; retain figure-specific provenance. |
| [Kaman academic translator source](https://github.com/Mohammad-Hasan-Kaman/kaman-ai-translator/blob/main/translator_app_v2.py) | Page text extraction and image-based input recovery are different operations from translation. | [MIT](https://github.com/Mohammad-Hasan-Kaman/kaman-ai-translator/blob/main/LICENSE); inspected text/preview output does not verify translated page geometry or image fidelity. | Inspect extraction quality before translation; do not equate a readable preview with a verified final document. |

## Scientific evaluation and multilingual discovery

| Source | Verified lesson | Scope or license caveat | Adoption in this skill |
| --- | --- | --- | --- |
| [Esposito paper](https://aclanthology.org/2024.lrec-main.557/), [dataset card](https://huggingface.co/datasets/universitytehran/ESPOSITO) | English–Persian scientific parallel data differs from generic translation corpora; the paper also describes a manually validated scientific test set. | Dataset card: CC BY-NC-SA 4.0. Reading the paper does not grant unrestricted reuse of its dataset. No corpus is bundled. | Select comparable scientific domain and register when evaluating terminology or translation quality. |
| [EPOQUE paper](https://aclanthology.org/2024.lrec-main.550/), [dataset card](https://huggingface.co/datasets/universitytehran/EPOQUE) | English–Persian quality estimation uses human direct assessments; the paper describes three annotators per translated sentence. | Dataset card: CC BY-NC-SA 4.0. This is an assessment dataset, not proof of this skill's performance or a substitute for its reviewers. | Record concrete review evidence and unresolved errors; never present a model score or edit distance alone as scientific correctness. |
| [Tatoeba Challenge pair inventory](https://github.com/Helsinki-NLP/Tatoeba-Challenge/blob/master/data/README.md) | Inspected pair rows include Persian with Arabic, German, English, French, Italian, Japanese, Portuguese, Russian, Spanish, Turkish and Chinese. | [Repository data license](https://github.com/Helsinki-NLP/Tatoeba-Challenge/blob/master/LICENSE): CC BY-NC-SA 4.0. Pair sizes and domains differ; no corpus is bundled. | Use the exact pair as a research lead; inspect source variety, domain and sample quality before borrowing terminology. |
| [FLORES-200 documentation](https://github.com/facebookresearch/flores/blob/main/flores200/README.md), [FLORES+ dataset](https://huggingface.co/datasets/openlanguagedata/flores_plus) | Aligned multilingual evaluation distinguishes language and script identifiers, including Persian, Dari and Tajik. | General-domain evaluation; the archived repository and maintained successor have release-specific data terms. No dataset is bundled. | Identify the actual variety and script. Transliteration and a shared script do not establish semantic equivalence. |
| [Natural Instructions task catalog](https://github.com/allenai/natural-instructions/blob/master/tasks/README.md), [Japanese–Persian task](https://github.com/allenai/natural-instructions/blob/master/tasks/task1098_ted_translation_ja_fa.json) | The catalog exposes concrete Persian-target tasks, including Japanese, Spanish, Arabic, Italian, Portuguese, Hebrew, Polish and Galician. | Repository Apache-2.0 does not cover every underlying example; the inspected Japanese–Persian task declares its instance license Unknown. No task instances are copied. | Treat pair entries as discovery evidence, not permission to redistribute or proof of journal translation quality. |
| [Arabic-script biomedical translation](https://github.com/arasheslamii/biomed-mt-arabic-script) | Biomedical transfer experiments address Dari/Urdu targets using Arabic/Persian resources. | Direction matters: this is not validated Urdu-to-Persian scientific translation. Code, adapters and corpora have separate terms. | Verify translation direction and domain before citing a repository as support for a language profile. |

## Original quotations and shared scripts

| Source | Verified lesson | Scope or license caveat | Adoption in this skill |
| --- | --- | --- | --- |
| [Hazm normalizer](https://github.com/roshan-research/hazm/blob/master/hazm/normalizer.py), [tests](https://github.com/roshan-research/hazm/blob/master/tests/test_normalizer.py) | Normalization can change letter forms, remove diacritics and alter digits, separators or quotations. Some transformations precede optional steps. | [MIT](https://github.com/roshan-research/hazm/blob/master/LICENSE); intended NLP normalization is not original-text preservation. | Normalize translated Persian prose only; preserve quoted source text and exact technical spans. |
| [DadmaTools normalizer](https://github.com/Dadmatech/DadmaTools/blob/main/dadmatools/normalizer.py), [character rules](https://github.com/Dadmatech/DadmaTools/blob/main/dadmatools/utils/patterns.py) | Full cleaning can delete numbers and links; whitespace rejoining and broad character folding can damage structured or multilingual text. | No implementation imported; license text was not verified during this review. | Keep raw source intact and limit any cleanup to explicitly selected prose spans. |
| [PALI repository](https://github.com/sinaahmadi/PersoArabicLID), [paper](https://aclanthology.org/2023.vardial-1.8/) | Similar scripts and unconventional spellings complicate language identification. | Language-identification corpora are not scientific translation benchmarks; short and mixed-language spans need contextual review. | Detect language from evidence beyond the script and review mixed-language passages separately. |
| [ScriptNormalization](https://github.com/sinaahmadi/ScriptNormalization), [paper](https://aclanthology.org/2023.acl-long.809/) | Character normalization is a separate task; the real-data study uses Sorani social-media text written with Persian/Arabic conventions. | No verified reuse license; no code/data imported. Findings do not establish Arabic/Urdu-to-Persian scientific accuracy. | Record normalization decisions and preserve originals; do not infer universal cleanup rules from shared glyphs. |
| [Unicode Arabic-script specification](https://www.unicode.org/versions/Unicode17.0.0/core-spec/chapter-9/), [normalization FAQ](https://www.unicode.org/faq/normalization.html) | Urdu letter distinctions and combining marks may carry meaning; compatibility normalization can lose distinctions. | Character standards explain encoding, not the intended language or translation of a passage. | Preserve genuine foreign quotations, diacritics, identifiers and notation; a targeted documented checker exception must not disable unrelated checks. |

## Context, completeness and review

| Source | Verified lesson | Scope or license caveat | Adoption in this skill |
| --- | --- | --- | --- |
| [Translation-agent](https://github.com/andrewyng/translation-agent) | Draft, reflection and revision benefit from context; evaluation must distinguish sentence metrics from document judgments. | MIT; no runtime imported. Repeated passes by one model are not independent reviewers. | Separate source-fidelity review from Persian fluency review and identify the actual review arrangement. |
| [Translate-book issue 7](https://github.com/deusyu/translate-book/issues/7) | A reader reports name and gender drift across chunks. | Reported experience, not a universal measured failure rate; no source copied. | Carry neighboring context, referents and term decisions across chunks without duplicating overlap in output. |
| [Translation validation](https://github.com/Chael-Chael/zotero-translate-skill/blob/main/skills/zotero-translate/scripts/validate_translations.py), [Co-op Translator](https://github.com/Azure/co-op-translator) | Stable IDs, source hashes and missing/duplicate segment checks help expose incomplete or stale output. | Zotero skill AGPL-3.0; Co-op Translator MIT. Implementations are not imported. | Keep source-location IDs and source revisions; repeated identical paragraphs remain separate locations. Never mark a truncated part complete. |
| [WMT MQM evaluation](https://github.com/google/wmt-mqm-human-evaluation) | Review records can identify an error span, category and severity separately. | Published professional evaluation does not certify this skill or its host model. | Record accuracy, terminology, fluency and presentation errors with evidence; unresolved meaning-changing errors block completion. |
| [wtpsplit](https://github.com/segment-any-text/wtpsplit), [XLIFF 2.1](https://docs.oasis-open.org/xliff/xliff-core/v2.1/xliff-core-v2.1.html) | Segmentation depends on language/domain, while aligned source/target units need stable identity and state. | No segmentation model or XLIFF implementation imported. | Use semantic boundaries and model context limits; update coverage/review state when source segments change. |

## Page geometry and image fidelity

| Source | Verified lesson | Scope or license caveat | Adoption in this skill |
| --- | --- | --- | --- |
| [PyMuPDF images](https://pymupdf.readthedocs.io/en/latest/recipes-images.html), [page API](https://pymupdf.readthedocs.io/en/latest/page.html) | Original image extraction differs from rasterized clipping; rotated page rectangles and PDF page boxes can differ. | Resolution metadata alone does not prove retained detail. | Inventory physical page boxes/orientation and image pixels; prefer original/vector assets and use source-aware sampling when cropping. |
| [PLOS figure guidance](https://journals.plos.org/plosone/s/figures) | Raising nominal resolution does not restore missing image information. | Publication guidance, not permission to reconstruct scientific evidence. | Seek a better original or rerender vector artwork before enhancing a derivative; preserve aspect ratio and compare scientific marks against the original. |
| [TeX geometry](https://ctan.org/pkg/geometry), [CSS page size](https://developer.mozilla.org/en-US/docs/Web/CSS/Reference/At-rules/@page/size) | Both output paths can specify physical page dimensions. | Mixed-size documents and renderer behavior still require output inspection. | Set dimensions from source inventory and verify the resulting pages; never silently substitute A4 for a different book size. |
| [PDFMathTranslate Persian/Arabic report](https://github.com/PDFMathTranslate/PDFMathTranslate/issues/1175), [BabelDOC](https://github.com/funstory-ai/BabelDOC) | Layout-preserving translation can still encounter script shaping/direction problems; formula/context handling does not establish Persian rendering. | Reported issue and project-specific tested scope; no AGPL runtime imported. | Inspect final Persian shaping, searchable text, equations and figure placement with the actual chosen renderer. |

## Using new evidence

For each encountered source language, confirm the language variety, translation
direction, scientific domain and license of the specific material. Add only a
verified lesson that changes a real translation decision. Keep unresolved resource
gaps explicit. Source fidelity, original scientific figures and complete coverage
remain required even when a draft reads smoothly or passes mechanical checks.
