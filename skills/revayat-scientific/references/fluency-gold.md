# Fluency gold paragraphs

Constructed calibration targets for the register in `scientific-style.md`.
When changing register rules or the fluency-reader brief, re-read these
and confirm a good draft still matches them. They are **voice examples
across software/science genres**, not a product-specific style guide and
not a checklist for `check-fa.py`.

The skill applies to scientific papers and scholarly/technical books across
disciplines and source languages. Infer genre and terminology from each source;
the software examples do not define journal register.

Placeholders use `\en{…}` as in print TeX. In fluency-reader prompts,
strip isolates to `‹EN›`.

## G1 — Error handling (tutorial / system-docs)

> وقتی `\en{client}` می‌خواهد به یک `\en{URI}` برسد که یکی از این
> خطاها را می‌دهد (مثلاً `\en{file}`ای که روی `\en{server}` نیست و
> خطای `\en{404}` می‌گیرد)، برنامه باید صفحهٔ مربوط به آن کد خطا را
> نشان بدهد. ولی `\en{error page}` را مستقیم برای `\en{client}`
> نمی‌فرستد؛ به‌جایش با `\en{URI}` جدید یک `\en{request}` کاملاً تازه
> شروع می‌کند.

Reject wording that changes the described operation or copies an unreadable source
sentence structure. Judge verbs in context; no individual scholarly verb is banned.

## G2 — Library / API docs

> اگر آرگومان `\en{None}` باشد، تابع `\en{ValueError}` می‌دهد. برای
> ادامه، `\en{batch}` را به `\en{DataLoader}` بدهید و یک `\en{epoch}`
> `\en{train}` کنید.

Reject: literary padding («مبادرت به آموزش مدل نمایید») or Persianising
kept library terms.

## G3 — Hedge preserved (paper)

> این نتیجه ممکن است به اندازهٔ نمونه بستگی داشته باشد و هنوز
> نمی‌توان اثر علّی را قطعی دانست.

Reject: hardening to «ثابت می‌کند» or dropping «ممکن است». A first-use original
designation is optional for lookup; repeated English jargon is not more accurate.

## G4 — Job lexicon kept English (system-docs)

> برای هر `\en{deployment}` یک `\en{replica}` جدا `\en{configure}`
> کنید و `\en{request}`ها را از طریق `\en{Service}` بفرستید.

Reject: استقرار / رونوشت as calques for those kept terms; also reject
«اقدام به ارسال درخواست نمایید».

## G5 — Ordinary prose not over-Englished

> امنیت را با محدود کردن دسترسی افزایش دهید؛ اگر فایل پیکربندی
> موجود نباشد، فرایند متوقف می‌شود.

Here `security` is ordinary prose → امنیت. Keep `\en{file}` only when
`terms.tsv` locks the tooling sense; otherwise Persian is fine — stay
consistent with `terms.tsv`.

## G6 — Database / query reference

> `\en{query}` را روی `\en{index}` اجرا کنید؛ اگر ردیفی نباشد،
> `\en{NULL}` برمی‌گردد و در `\en{log}` نوشته می‌شود.

Reject: mega-sentence calques; «مبادرت به اجرای پرس‌وجو نمایید».

## G7 — Collocation: return / send / call

> اگر کلید نباشد، `\en{404}` برمی‌گرداند. سپس یک `\en{request}` تازه
> می‌فرستد و `\en{callback}` را صدا می‌زند.

Reject: «مبادرت به بازگرداندن ۴۰۴ می‌کند» / «درخواست را ارسال می‌نماید».

## How to use

1. Fluency reader brief points here as the gold standard beside Canonical
   manner.
2. After a register/ensemble edit, score a draft of G1–G3 (or the
   bake-off span) and expect `OK` on gold-like prose.
3. Pick the gold id that matches the book's genre; do not force web-server
   wording onto an ML or database text.
4. Do not paste this whole file into every translator prompt — only the
   relevant gold id when calibrating.

## G8 — Negative finding is not equivalence (journal)

> تفاوت آماری معناداری مشاهده نشد. این نتیجه به‌تنهایی هم‌ارزی دو روش را
> ثابت نمی‌کند و باید محدودیت اندازهٔ نمونه را در تفسیر آن در نظر گرفت.

Reject: «دو روش یکسان‌اند». The limitation belongs only when present in the source;
never add it automatically to every negative result.

## G9 — Familiar scholarly register (journal)

> در این مطالعه، یک پیاده‌سازی مرجع ارائه می‌کنیم و عملکرد آن را با دو روش
> موجود مقایسه می‌کنیم. نتایج، بهبود دقت را در شرایط بررسی‌شده نشان می‌دهند.

Reject: forcing پیاده‌سازی مرجع into English or replacing شرایط بررسی‌شده with a
universal claim. ارائه می‌کنیم is appropriate here; casual chat tone is not required.

## G10 — Method, observation and interpretation stay distinct

> نمونه‌ها در دمای یکسان نگهداری شدند. پس از اندازه‌گیری، افزایش سیگنال
> مشاهده شد؛ علت این افزایش با داده‌های موجود روشن نیست.

Reject: inventing an actor for the passive, supplying an unreported temperature,
or replacing the unresolved interpretation with a causal explanation.

## G11 — Cross-language meaning calibration

These short source sentences and Persian renderings were constructed for this
skill. They are review exercises, not corpus quotations or independently certified
gold translations. Preserve the stated distinction even when choosing other wording.

| Source language and sentence | Faithful Persian | Reject |
| --- | --- | --- |
| German: Ein kausaler Zusammenhang kann nicht ausgeschlossen werden. | وجود رابطهٔ علّی را نمی‌توان رد کرد. | رابطهٔ علّی ثابت شده است. |
| French: Cette association ne prouve pas un lien causal. | این ارتباط، رابطهٔ علّی را ثابت نمی‌کند. | این ارتباط، علت را ثابت می‌کند. |
| Russian: Отсутствие значимого различия не доказывает эквивалентность. | نبود تفاوت معنادار، هم‌ارزی را ثابت نمی‌کند. | دو روش هم‌ارزند. |
| Arabic: قد يرتبط هذا التغير بحجم العينة. | این تغییر ممکن است با اندازهٔ نمونه مرتبط باشد. | اندازهٔ نمونه علت قطعی این تغییر است. |
| Chinese: 未发现统计学显著差异。 | تفاوت آماری معناداری مشاهده نشد. | هیچ تفاوتی وجود ندارد. |
| Japanese: この結果だけでは因果関係を示せない。 | با این نتیجه به‌تنهایی نمی‌توان رابطهٔ علّی را نشان داد. | این نتیجه رابطهٔ علّی را ثابت می‌کند. |
| Turkish: Bu sonuç bir ilişki olabileceğini düşündürmektedir. | این نتیجه احتمال وجود ارتباط را مطرح می‌کند. | این نتیجه وجود ارتباط را قطعی می‌داند. |

## G12 — Concept rather than spelling

> سوگیری انتخاب نمونه با سوگیری برآوردگر یک مفهوم نیست. معادل هر اصطلاح
> باید با تعریف آن در همین متن سازگار باشد.

Reject one global replacement for every occurrence of bias across unrelated senses.
An existing glossary entry is evidence only when its concept and context match.
