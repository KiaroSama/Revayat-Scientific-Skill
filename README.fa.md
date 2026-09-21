<div dir="rtl">

# روایت علمی — Revayat Scientific

[![CI](https://github.com/KiaroSama/Revayat-Scientific-Skill/actions/workflows/ci.yml/badge.svg)](https://github.com/KiaroSama/Revayat-Scientific-Skill/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-GPL--3.0--or--later-blue)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](skills/revayat-scientific/requirements.txt)

**منبع علمی را از هر زبان به فارسی دقیق ترجمه کنید؛ با حفظ قطع صفحه و کیفیت تصاویر، متن قابل‌ویرایش و PDF بررسی‌شده تحویل بگیرید.**

اسکیلی برای Claude Code، Claude Desktop، Codex، Kiro، Cursor، Cline،
Hermes، OpenCode، Antigravity و هر ایجنتی که بتواند فایل `SKILL.md` را بخواند.
اصطلاحات در طول سند ثابت می‌مانند، میزان قطعیت ادعاها حفظ می‌شود و شکل‌ها،
فرمول‌ها و خروجی فارسی پیش از تحویل بررسی می‌شوند.

<div align="right"><a href="LICENSE">مجوز GPL-3.0</a></div>
<div align="left"><a href="README.md">English</a></div>

---

## چه چیزی آن را از یک مترجم معمولی جدا می‌کند

| | |
| --- | --- |
| **ثبت ساختار منبع پیش از ترجمه** | بخش‌ها، شکل‌ها، جدول‌ها، فرمول‌ها، یادداشت‌ها و منابع ثبت می‌شوند تا حذف‌شدن آن‌ها مشخص باشد. |
| **حفظ معنای ادعاهای علمی** | نفی، عدم قطعیت، مقدارها و واحدها با منبع مقایسه می‌شوند؛ روان‌سازی نباید معنای آن‌ها را عوض کند. |
| **یک صورت ترجیحی برای هر مفهوم** | دفتر اصطلاحات مخصوص همان سند است. مقاله از سطح `journal` و راهنمای عملیاتی از `system-docs` استفاده می‌کند. |
| **حفظ شکل‌های اصلی** | شکل‌ها از منبع آماده می‌شوند، با صفحهٔ اصلی مقایسه می‌شوند و حضورشان در خروجی بررسی می‌شود. |
| **صفحه‌آرایی واقعی راست‌به‌چپ** | فارسی به ترتیب منطقی نوشته می‌شود؛ متن اصلیِ حفظ‌شده جهت خط خودش را دارد و فرمول‌ها و عددها در محدودهٔ کامل چپ‌به‌راست قرار می‌گیرند. |
| **ترجمه از زبان‌های مختلف** | زبان و خط مبدأ تشخیص داده می‌شود؛ اصطلاحات مبهم پژوهش و معنا از روی اصل سند بازبینی می‌شود. مفاهیم علمی جاافتاده در سطح مقاله فارسی می‌شوند. |
| **حفظ قطع کتاب و کیفیت تصاویر** | ابعاد فیزیکی صفحه، پیکسل‌های اصلی و نسبت تصویر حفظ می‌شود؛ بهبود تصویر باید وفادارانه باشد. برش تصویری وضوح بالاتر منبع را پایین نمی‌آورد. |
| **کنترل‌های مکانیکی** | نویسه‌ها، اصطلاحات، جهت متن، تصویرهای مفقود، فونت‌ها، تعداد صفحات و تصویر نمونهٔ صفحات بررسی می‌شوند. |
| **سنجش استخراج متن** | عبارت‌های فارسیِ نرمال‌شده با استخراج PyMuPDF مقایسه می‌شوند؛ محدودیت هر بررسی اعلام می‌شود. |
| **یک فرمان چندسکویی** | فرمان Python در Windows از PowerShell و در Linux/macOS از Bash استفاده می‌کند؛ ترجمه کار مدل همان ایجنت است. |
| **ابزارهای داخلی DOCX و PDF** | بررسی، ساخت و ویرایش هدفمند Word؛ استخراج متن، جدول و تصویر PDF، بررسی و پرکردن فرم، ادغام صفحات و OCR اختیاری با حفظ فایل اصلی. |
| **ترجمه و ویرایش موازی اختیاری** | پس از رضایت کاربر، بخش‌های مستقل با واژه‌نامهٔ مشترک و لاگ جداگانه به ساب‌ایجنت‌ها سپرده می‌شوند؛ ادغام و بازبینی نهایی با هماهنگ‌کننده است. |

## نصب

<div dir="ltr">

```bash
git clone https://github.com/KiaroSama/Revayat-Scientific-Skill.git
cd Revayat-Scientific-Skill
python -m pip install -r skills/revayat-scientific/requirements.txt
```

</div>

سپس اسکیل را برای ایجنت‌هایی که استفاده می‌کنید نصب کنید:

<div dir="ltr">

```bash
# macOS / Linux
./install/install.sh

# Windows
powershell -NoProfile -ExecutionPolicy Bypass -File .\install\install.ps1
```

</div>

پیش‌فرض، نصب برای ایجنت‌های شناسایی‌شده است: Claude Code، Codex، Kiro،
Cursor، Cline، Hermes، OpenCode و Antigravity. برای یک ایجنت از
`--agent claude` و برای یک پروژه از `--scope project --path <dir>` استفاده کنید.
گزینه‌های دو نصب‌کننده یکسان‌اند و پوشهٔ واقعی می‌سازند. جایگزینی نسخهٔ موجود
به `--force` نیاز دارد؛ نسخهٔ تازه ابتدا کامل آماده می‌شود و نسخهٔ قبلی
بیرون از مسیر شناسایی اسکیل نگه داشته می‌شود. [جزئیات نصب](docs/installation.md).

### به‌عنوان پلاگین Claude Code

<div dir="ltr">

```text
/plugin marketplace add KiaroSama/Revayat-Scientific-Skill
/plugin install revayat-scientific@revayat-scientific-skill
```

</div>

فرمان‌های `/translate-paper`، `/revayat-scientific-resume` و
`/revayat-scientific-qa` نیز در دسترس قرار می‌گیرند. فایل‌های معرفی پلاگین
Cursor و Codex هم موجودند. نام صریح خود اسکیل در Codex برابر
`$revayat-scientific` است.

### بررسی نصب

**Python 3.10 یا جدیدتر** روی Linux، macOS یا Windows لازم است.
محیط مجازی موجودِ پروژه را ترجیح دهید. نصب‌کننده و بررسی متن از کتابخانهٔ
استاندارد استفاده می‌کنند؛ آماده‌سازی تصویر و بررسی استخراج PDF به وابستگی‌های
ثبت‌شده نیاز دارند.

<div dir="ltr">

```bash
python skills/revayat-scientific/scripts/revayat-scientific.py doctor
```

</div>

پیش از وعدهٔ PDF، گزارش را بخوانید:

| مورد گزارش | کاربرد |
| --- | --- |
| Docker/Podman + XeLaTeX / xepersian | ساخت ایزولهٔ TeX؛ مراحل نصب در راهنمای PDF آمده است |
| Edge، Chrome یا WeasyPrint | مسیر ساخت از HTML |
| فونت فارسی | نمایش خوانای فارسی؛ فونت ترجیحی Vazirmatn است |
| Poppler و PyMuPDF | بررسی صفحات، فونت‌ها، تصاویر نمونه و متن استخراج‌شده |
| Pillow | آماده‌سازی شکل‌ها |

کمبود هر ابزار فقط مراحل وابسته به آن را محدود می‌کند. نصب پیش‌نیازها با اجازهٔ
کاربر انجام می‌شود؛ نصب‌کننده و doctor آن‌ها را خودکار نصب نمی‌کنند.

## استفاده

ایجنت در شروع کار می‌پرسد آیا **ترجمه و ویرایش با چند ساب‌ایجنت به‌صورت موازی**
انجام شود. این قابلیت اختیاری است و فقط با پاسخ مثبت فعال می‌شود؛ پاسخ منفی یا
بی‌پاسخ‌ماندن یعنی ادامهٔ ترتیبی. هر عامل بخش یا اصلاحات مشخصی را با لاگ جداگانه
آماده می‌کند؛ عامل هماهنگ‌کننده خروجی‌ها را با واژه‌نامهٔ مشترک ادغام و بازبینی
می‌کند. کار موازی ممکن است توکن بیشتری مصرف کند.
[قواعد و محدودیت‌های کار موازی](skills/revayat-scientific/references/parallel-work.md).

به ایجنت بگویید:

> `paper.pdf` را به فارسی ترجمه کن، فرمول‌ها و شکل‌ها را حفظ کن و PDF بررسی‌شده بده.

یا از فرمان پلاگین استفاده کنید: `/translate-paper ./paper.pdf`.

ایجنت نه مرحلهٔ `SKILL.md` را دنبال می‌کند. خواندن، ترجمه، سنجش معنای علمی
و دیدن صفحات خروجی کار ایجنت است؛ اسکریپت‌ها فایل‌ها را آماده و کنترل می‌کنند.
مدل ثابت یا API ترجمه لازم نیست.

### یا خودتان مرحله‌به‌مرحله اجرا کنید

<div dir="ltr">

```bash
PY=python   # or python3; use the same interpreter throughout
SKILL=skills/revayat-scientific
WORK=work

"$PY" "$SKILL/scripts/revayat-scientific.py" doctor
# Preserve the source; write inventory.md, terms.tsv and manifest.txt.
# Translate into work/doc.tex, then review meaning and fluency.
"$PY" "$SKILL/scripts/revayat-scientific.py" figures "$WORK/figures" --check
"$PY" "$SKILL/scripts/revayat-scientific.py" lint "$WORK/doc.tex" --level journal --terms "$WORK/terms.tsv" --manifest "$WORK/manifest.txt" --strict
"$PY" "$SKILL/scripts/revayat-scientific.py" build "$WORK/doc.tex" article --level journal --output-dir "$WORK/output" --verify
"$PY" "$SKILL/scripts/revayat-scientific.py" text-order "$WORK/output/article.pdf" --source "$WORK/doc.tex"
```

</div>

فرمان شکل‌ها زمانی اجرا می‌شود که سند شکل داشته باشد. manifest سند بدون شکل
فقط یک توضیح دارد. در PowerShell پیش از مسیر نقل‌قول‌شدهٔ برنامه، `&` بگذارید.

**ورودی:** مقاله، پایان‌نامه، کتاب فنی یا مرجع به‌صورت فایل محلی، پیوست،
صفحهٔ قابل‌دسترسی یا متن منبع. PDF به استخراج متن یا خواندن دیداری/OCR نیاز دارد.

**خروجی:** متن قابل‌ویرایش TeX یا HTML همراه با PDF بررسی‌شده؛ یا متن بازبینی‌شده
وقتی کاربر فقط متن بخواهد.

**زبان منبع:** از خود سند تشخیص داده می‌شود؛ سند می‌تواند چندزبانه باشد.
**زبان مقصد:** فارسی علمی. راهنمای زبان‌های بررسی‌شده و روش پژوهش برای دیگر
زبان‌ها در اسکیل آمده است؛ کیفیت به توانایی زبانی ایجنت و بازبینی واقعی منبع
وابسته است، نه صرفاً وجود نام زبان در یک فهرست.

## بدون پوسته

ایجنت همچنان می‌تواند اسکیل و مراجعش را بخواند، اصطلاحات را تعیین کند، متن را
ترجمه کند و یافته‌های بازبینی را ثبت کند. پردازش فایل، ساخت PDF و بررسی آن
به محیطی نیاز دارند که بتواند ابزارها را اجرا کند. این مراحل تا زمان اجرای واقعی
انجام‌نشده محسوب می‌شوند؛ وجود متن فارسی به معنی ساخته‌شدن PDF نیست.

## معماری

<div dir="ltr">

```text
source → inventory → terms → figures → translation
                                      ↓
                        fidelity → fluency → strict lint
                                      ↓
                            build → inspect → deliver
```

```text
commands/                    translate-paper, resume and QA entry points
install/                     shared installer + Bash/PowerShell launchers
skills/revayat-scientific/
  SKILL.md                   ordered stages and decisions
  agents/openai.yaml         Codex discovery metadata
  assets/                    TeX/HTML templates and terms header
  references/                stage-specific policies
  scripts/                   portable command and deterministic helpers
tests/                       fixtures and public-command regressions
tools/                       package construction and source validation
docs/                        installation and architecture
```

</div>

هر ترجمه پوشهٔ کاری مستقل با منبع، `inventory.md`، `terms.tsv`،
`manifest.txt`، `progress.md` و متن قابل‌ویرایش دارد. شکست بررسی یا ساخت،
PDF تحویل‌شدهٔ قبلی را حفظ می‌کند. مسیر پیش‌فرض `$HOME/Documents/books` است
و `--output-dir` آن را عوض می‌کند. [معماری و مسئولیت‌ها](docs/architecture.md).

## آنچه صادقانه باید گفت

- عبور از بررسی مکانیکی، صحت علمی را اثبات نمی‌کند؛ معنا و روانی باید واقعاً خوانده شوند.
- اسکن و PDF چندستونی به بررسی دیداری/OCR نیاز دارند. برش شکل‌ها تقریبی است و باید با منبع مقایسه شود.
- بعضی فونت‌ها یا رندررهای HTML متن دشواری برای استخراج می‌سازند. معیار این ابزار خروجی نرمال‌شدهٔ PyMuPDF است، نه رفتار کپی در همهٔ نمایشگرها.
- بازسازی دقیق صفحه‌آرایی ناشر تضمین نمی‌شود؛ محتوای علمی و خوانایی اولویت دارند.
- CI ابزارها را با نمونه‌های آزمایشی می‌سنجد؛ کیفیت ترجمهٔ یک مقالهٔ دلخواه و رابط شناسایی همهٔ میزبان‌ها را ارزیابی نمی‌کند.

## مستندات

- [SKILL.md](skills/revayat-scientific/SKILL.md) — گردش کار کامل و مرتب
- [سیاست ترجمه](skills/revayat-scientific/references/translation-policy.md) — دستور مترجم و بازبین
- [استخراج](skills/revayat-scientific/references/extraction.md) — ثبت منبع و آماده‌سازی شکل‌ها
- [زبان‌های مبدأ](skills/revayat-scientific/references/source-languages.md) — ترجمهٔ مستقیم، راهنمای زبان و پژوهش
- [ابعاد و کیفیت تصاویر](skills/revayat-scientific/references/layout-and-images.md) — حفظ قطع کتاب، وضوح و بهبود وفادارانهٔ تصاویر
- [اصطلاحات](skills/revayat-scientific/references/terminology.md) — تصمیم‌های مفهومی و سطح واژگان
- [سبک علمی](skills/revayat-scientific/references/scientific-style.md) — فارسی علمی روشن
- [راست‌به‌چپ](skills/revayat-scientific/references/rtl-bidi.md) — محدوده‌های کامل چپ‌به‌راست
- [بازبینی](skills/revayat-scientific/references/review.md) — دقت، روانی و کامل‌بودن
- [خروجی PDF](skills/revayat-scientific/references/pdf-output.md) — موتور، فونت و بررسی خروجی
- [عیب‌یابی](skills/revayat-scientific/references/troubleshooting.md) — خطاها و راه بازیابی
- [شواهد پژوهشی](skills/revayat-scientific/references/research-sources.md) — مخازن بررسی‌شده، یافته‌های به‌کاررفته و محدودیت‌ها

## توسعه

<div dir="ltr">

```bash
python -m unittest discover -s tests -p 'test_*.py' -v
bash tests/upstream.sh
python tools/validate.py
python tools/package.py
```

</div>

[CI](https://github.com/KiaroSama/Revayat-Scientific-Skill/actions/workflows/ci.yml)
روی Python 3.10 در Linux، نسخهٔ 3.14 در macOS و نسخهٔ 3.13 در Windows
اجرا می‌شود؛ ساخت واقعی Windows، تست‌های بررسی متن و ساخت واقعی XeLaTeX در
محیط ایزوله، WeasyPrint و OCR را پوشش می‌دهد. بررسی امنیت گردش‌کار و ممیزی
وابستگی‌های Python نیز در CI اجرا می‌شود. CodeQL و بازبینی وابستگی‌ها فعال‌اند؛
Dependabot پکیج‌های Python، Actions و تصویر پایهٔ کانتینر را دنبال می‌کند. بستهٔ
`dist/revayat-scientific.skill` اعلان‌های مجوز را همراه دارد و وابستگی‌های
اجرایی در آن کپی نمی‌شوند.

### گزارش‌های اجرا

هر ایجنتی که از این اسکیل استفاده می‌کند باید **کنار فایل ترجمه** یک فایل لاگ
بسازد و در طول کار آن را به‌روز کند: مراحل ترجمه، تصمیم‌های اصطلاحات، یافته‌های
بازبینی، اصلاحات و دلیلشان، نتیجهٔ بررسی‌ها، خطاها و تحویل نهایی. ایجنت با ابزار
عادی نوشتن فایل این کار را انجام می‌دهد؛ حتی اگر هیچ اسکریپتی اجرا نشود.
هر اجرا فایل تازه‌ای با نام `<translation-stem>_YYYY-MM-DD_HH-mm-ss_UTC.log`
دارد و لاگ همراه ترجمه تحویل داده می‌شود. این الزام داخل `SKILL.md` نوشته شده است.

گزارش‌های ابزارهای کمکی که در ادامه آمده‌اند، جدا از لاگ روند ترجمه‌اند.
گزارش فرمان اصلی در `logs/` داخل اسکیل و گزارش نصب و بسته‌بندی در
`logs/` ریپو قرار می‌گیرد. نام هر اجرا
`<command>_YYYY-MM-DD_HH-mm-ss_UTC.log` است و برخورد نام با پسوند حل می‌شود.
گزارش UTF-8 شامل زمان UTC، سطح، عملیات، مدت و کد خروج است؛ متن سند،
آرگومان‌ها و خروجی ابزارها در آن کپی نمی‌شوند. اگر ایجاد فایل ممکن نباشد،
پیام در stderr نمایش داده می‌شود. گزارش‌ها محلی می‌مانند تا حذف شوند.
فایل‌های موقت TeX پس از تأیید پاک‌سازی کانتینر حذف می‌شوند؛ اگر پاک‌سازی
تأیید نشود، شواهد بازیابی حفظ و انتشار خروجی متوقف می‌شود.

ابزارهای سند، شکل، فونت و رندر در `scripts/logs/` گزارش می‌نویسند.
متغیر `REVAYAT_LOG_LEVEL` سطح `DEBUG`، `INFO` (پیش‌فرض)، `WARNING` یا `ERROR`
را انتخاب می‌کند. این گزارش‌های فنی جایگزین لاگ کنار فایل ترجمه نیستند.

## حمایت مالی

اگر این پروژه برای شما مفید است، می‌توانید از توسعهٔ آن حمایت کنید.

</div>

| Currency | Network | Address |
| --- | --- | --- |
| Bitcoin (BTC) | Bitcoin | `bc1qmth5m03pu5hujw5xw5jmywam3jj3sqwqupesdt` |
| USDT, BNB, USDC, etc. | BEP20 | `0x0Bd0BA443a8B9cf15922bf7f0Bb0a4b495fD06Ef` |
| USDT, TRX, USDC, etc. | TRC20 | `TWBA3xFTqgZAeAYMxqo85xWnzvty3DcAhw` |
| Ethereum (ETH) | ERC20 | `0x0Bd0BA443a8B9cf15922bf7f0Bb0a4b495fD06Ef` |
| TON | TON | `UQCN8Umo_OfOWqImZetQsrNStPcmLkMAKajFyiCOhso23NDb` |
| Litecoin (LTC) | LTC | `ltc1qntqnnrunadurnw4cshv3qgspywrueyyeyngwuy` |
| Solana (SOL) | Solana | `7B2wkczUjmkDhETwQuknBL8sUsbuV7nErxc317TmQuwR` |
| Polygon (POL) | Polygon | `0x0Bd0BA443a8B9cf15922bf7f0Bb0a4b495fD06Ef` |

<div dir="rtl">

## نویسنده

نویسنده: Kiaro Sama  
گیت‌هاب: [KiaroSama](https://github.com/KiaroSama)

## مجوز

[مجوز عمومی گنو، نسخهٔ ۳ یا بالاتر](LICENSE). وابستگی‌های اختیاری و اسناد
منبع مجوز مستقل خود را دارند.

</div>
