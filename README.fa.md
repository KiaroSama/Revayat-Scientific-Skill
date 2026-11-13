<div dir="rtl">

# روایت علمی — Revayat Scientific

<div align="center">

[![CI status on main](https://github.com/KiaroSama/Revayat-Scientific-Skill/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/KiaroSama/Revayat-Scientific-Skill/actions/workflows/ci.yml)
[![CodeQL status on main](https://github.com/KiaroSama/Revayat-Scientific-Skill/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/KiaroSama/Revayat-Scientific-Skill/actions/workflows/codeql.yml)
[![GPL-3.0-or-later license](https://img.shields.io/badge/License-GPL--3.0--or--later-blue?style=flat-square)](LICENSE)
[![Plugin version 2.0.0](https://img.shields.io/badge/Plugin-2.0.0-blue?style=flat-square)](.codex-plugin/plugin.json)
<br>
[![Rust migration CI](https://github.com/KiaroSama/Revayat-Scientific-Skill/actions/workflows/ci.yml/badge.svg?branch=rewrite%2Frust-complete)](https://github.com/KiaroSama/Revayat-Scientific-Skill/actions?query=branch%3Arewrite%2Frust-complete)
[![Rust 1.99.1](https://img.shields.io/badge/Rust-1.99.1-dea584?style=flat-square&logo=rust)](rust-toolchain.toml)
[![Windows, macOS and Linux](https://img.shields.io/badge/Platforms-Windows%20%7C%20macOS%20%7C%20Linux-287c91?style=flat-square)](.github/workflows/ci.yml)
[![English and Persian docs](https://img.shields.io/badge/Docs-EN%20%7C%20FA-6f42c1?style=flat-square)](README.md)
[![Agent Skills format](https://img.shields.io/badge/Format-Agent%20Skills-6f42c1?style=flat-square)](skills/revayat-scientific/SKILL.md)
<br>
[![Installable skill ZIP](https://img.shields.io/badge/Package-.skill%20ZIP-6f42c1?style=flat-square)](docs/installation.md)
[![Any source language to Persian](https://img.shields.io/badge/Languages-Any%20source%20to%20Persian-287c91?style=flat-square)](skills/revayat-scientific/references/source-languages.md)
[![Native DOCX and PDF tools](https://img.shields.io/badge/Documents-DOCX%20%7C%20PDF-287c91?style=flat-square)](docs/architecture.md)
[![Isolated Docker or Podman TeX](https://img.shields.io/badge/TeX-Docker%20%7C%20Podman-287c91?style=flat-square)](skills/revayat-scientific/references/pdf-output.md)
<br>
[![Codex, Claude Code and Cursor support](https://img.shields.io/badge/Agents-Codex%20%7C%20Claude%20Code%20%7C%20Cursor-287c91?style=flat-square)](docs/installation.md)
[![GitHub stars](https://img.shields.io/github/stars/KiaroSama/Revayat-Scientific-Skill?style=flat-square)](https://github.com/KiaroSama/Revayat-Scientific-Skill/stargazers)
[![Support donations](https://img.shields.io/badge/Support-donations-d04a9a)](README.md#donate)

</div>

**ترجمهٔ علمی از هر زبان به فارسی، همراه با منبع ویرایش‌پذیر، حفظ اجزای سند و PDF بررسی‌شده.**

روایت یک اسکیل ایجنت و یک برنامهٔ بومی Rust است. ترجمه و بازبینی علمی را مدل همان ایجنت انجام می‌دهد؛ برنامه، یکپارچگی فایل‌ها، اصطلاحات، تصاویر، حروف‌چینی و تحویل را بررسی می‌کند. Codex، Claude Code، Cursor، Kiro، Cline، Hermes، OpenCode، Antigravity و میزبان‌های پشتیبان `SKILL.md` قابل استفاده‌اند.

[English](README.md)

**وضعیت بازنویسی Rust:** این راهنما شاخهٔ `rewrite/rust-complete` را توصیف می‌کند، نه پیاده‌سازی فعلی `main`. برابری رفتاری تست‌ها و CI میزبانی‌شده هنوز در حال بررسی است؛ ثبت نام تست اثبات اجرای assertionهای اصلی یا موفقیت کنترل بومی نیست. نشان‌های دارای برچسب `main` وضعیت شاخهٔ اصلی را نشان می‌دهند و نشان Rust migration CI مربوط به شاخهٔ این PR است. نشان CI به‌تنهایی برابری assertionها را اثبات نمی‌کند. آرشیو را از اجرای CI بازبینی‌شدهٔ همان نسخه بگیرید؛ بستهٔ میانی را release نهایی امضاشده معرفی نکنید.

## تفاوت با ترجمهٔ عمومی

| قابلیت | رفتار |
| --- | --- |
| وفاداری علمی | ثبت ادعاها، عدم قطعیت، نفی، کمیت‌ها، فرمول‌ها، تصاویر و ارجاع‌ها پیش از ترجمه. |
| اصطلاحات یکدست | واژه‌نامهٔ TSV محلی، محل وقوع اصطلاح و سطح ثابت `journal` یا `system-docs`. |
| تایپوگرافی فارسی | ترتیب منطقی یونیکد، بندهای راست‌به‌چپ و جداسازی کامل عبارت‌های چپ‌به‌راست. |
| پردازش بومی سند | بررسی و ویرایش بخش پشتیبانی‌شدهٔ DOCX/OPC و PDF با کنترل اجزای دست‌نخورده. |
| تصویر و ابعاد صفحه | حفظ اثر اصلی، اندازهٔ صفحه، پیکسل‌ها، نسبت تصویر و تراکم برش. |
| تحویل قابل بررسی | بررسی منبع، فونت، صفحه، ترتیب استخراج متن و خروجی واقعی رندر. |
| بازیابی تغییرات | آماده‌سازی همهٔ مقصدها، نگهداری نسخهٔ قبلی و حفظ شواهد بازیابی در شکست حل‌نشده. |

## نصب

برای ساخت از منبع، [Rust](https://rustup.rs/) را نصب کنید؛ نسخهٔ دقیق در `rust-toolchain.toml` ثبت شده است.

<div dir="ltr">

```console
git clone --branch rewrite/rust-complete https://github.com/KiaroSama/Revayat-Scientific-Skill.git
cd Revayat-Scientific-Skill
cargo build --locked --release --workspace --bins
cargo run --locked --release --bin revayat-scientific -- install --agent codex
```

</div>

گزینهٔ `--agent all` میزبان‌های شناسایی‌شده، `--scope project --path <directory>` پروژه و `--dest <directory>` مقصد سفارشی را انتخاب می‌کند. جایگزینی با `--force` فقط برای نصب دارای هویت روشن روایت مجاز است. همهٔ مقصدها پیش از فعال‌سازی آماده می‌شوند و نسخهٔ قبلی در `skill-backups` می‌ماند. [جزئیات نصب](docs/installation.md).

jobهای CI برای هر سیستم‌عامل فایل اجرایی و آرشیو `.skill` می‌سازند؛ پذیرش نهایی بازنویسی هنوز تأیید نشده است. در Linux/macOS، دو فایل `bin/revayat-scientific` و `bin/revayat-process-owner` را از همان build و revision کنار هم نگه دارید. Windows فقط `bin/revayat-scientific.exe` را لازم دارد. آرشیو شامل اسکیل، مراجع، assetهای مجاز، فرادادهٔ ایجنت، مجوز و اعلان‌ها نیز هست. نصب ساخته‌شده به مفسر زبان دیگری نیاز ندارد، اما موتورهای پردازش سند جدا هستند.

پیش از نصب، بسته‌بندی یا استفاده از فرمان‌های سورس، همهٔ binaryها را با فرمان بالا بسازید. `cargo run --bin revayat-scientific` به‌تنهایی sibling یونیکس را دوباره نمی‌سازد. companion مفقود، لینک‌شده یا غیرعادی رد می‌شود؛ کنارهم‌بودن و بایت‌های جمع‌آوری‌شده بررسی می‌شوند، نه اصالت امضاشده یا سازگاری نسخهٔ دو برنامه.

<div dir="ltr">

```text
/plugin marketplace add KiaroSama/Revayat-Scientific-Skill
/plugin install revayat-scientific@revayat-scientific-skill
```

</div>

پلاگین سه فرمان `/translate-paper`، `/revayat-scientific-resume` و `/revayat-scientific-qa` را می‌دهد. در Codex از `$revayat-scientific` استفاده کنید. نصب پلاگین از سورس به ساخت برنامه یا دریافت خروجی CI همان سیستم‌عامل نیاز دارد.

## استفاده

در ریپو، پیش از فرمان‌ها `cargo run --locked --release --bin revayat-scientific --` بگذارید. در اسکیل نصب‌شده از `bin/revayat-scientific` و در Windows از `bin/revayat-scientific.exe` استفاده کنید.

<div dir="ltr">

```console
revayat-scientific doctor
revayat-scientific fonts job/fonts
revayat-scientific term-brief job/source.txt --terms job/terms.tsv --language en
revayat-scientific lint job/doc.tex --level journal --terms job/terms.tsv --manifest job/manifest.txt --strict
revayat-scientific build job/doc.tex --out delivery/article.pdf --engine tex --level journal --verify
revayat-scientific text-order delivery/article.pdf --source job/doc.tex
revayat-scientific docx --help
revayat-scientific pdf --help
```

</div>

گزینهٔ `--engine weasyprint` خودِ موتور اختیاری WeasyPrint را داخل image ایزولهٔ اسناد اجرا می‌کند. آداپتر Rust منابع مجاز را بررسی و آماده می‌کند و همان quota محدود خروجی و پاک‌سازی مالکانهٔ TeX را به کار می‌گیرد. WeasyPrint و وابستگی‌های Python آن بسته‌های خارجی داخل image هستند؛ ریپازیتوری برنامهٔ Python متعلق به پروژه ندارد و نصب Python روی میزبان لازم نیست. برای ورودی TeX باید فایل هم‌نام `.html` موجود باشد. کشف خودکار به ترتیب TeX، Chromium و WeasyPrint انجام می‌شود و هویت موتورها مستقل است.

طرح دقیق هر فرمان با `--help` مشخص است. منابع، واژه‌نامه، تصاویر و گزارش ترجمه را بیرون از اسکیل نگه دارید. برای تقسیم ترجمه بین ایجنت‌های بیشتر رضایت بگیرید. زبان منبع، مخاطب، سطح اصطلاحات و نتیجهٔ واقعی بررسی‌ها را ثبت کنید.

| ابزار اختیاری | کاربرد لازم |
| --- | --- |
| Chrome/Chromium/Edge با sandbox فعال | رندر HTML با مشتری بومی DevTools |
| WeasyPrint در image ایزولهٔ اسناد | اجرای موتور WeasyPrint و رندر HTML هنگام نبود Chromium |
| Docker یا Podman با محدودیت مؤثر | ساخت ایزولهٔ TeX؛ XeLaTeX میزبان جایگزین این مرز نیست |
| Poppler | بررسی متن، فونت و رستر PDF |
| Tesseract و دادهٔ زبان | OCR اختیاری |
| LibreOffice Writer | رندر مستقل DOCX در CI علمی |

## بدون پوسته

ریپو یا آرشیو `.skill` را به ایجنت بدهید و اجرای نه مرحلهٔ [SKILL.md](skills/revayat-scientific/SKILL.md) را بخواهید. ابزار فایل برای ترجمه و ثبت واژه‌نامه کافی است؛ بررسی‌های اجرایی به برنامهٔ بومی و پیش‌نیازهای اعلام‌شده نیاز دارند. بررسی انجام‌نشده را موفق اعلام نکنید.

## معماری

نه مرحله شامل آمادگی ابزار، استخراج، اصطلاحات، آماده‌سازی اجزا، ترجمه، بازبینی معنا و روانی، تایپوگرافی، ساخت و بررسی، و بازرسی و تحویل است. مدل میزبان ترجمه می‌کند. ماژول‌های Rust مدل منبع، تجزیهٔ محدود، فرمان‌ها، مالکیت فرایندها، DOCX/PDF، رندر، نصب و ابزار CI را اجرا می‌کنند. [معماری](docs/architecture.md).

## آنچه صادقانه باید گفت

بررسی مکانیکی، صحت علمی، همهٔ نمایشگرها، همهٔ افزونه‌های PDF/OOXML یا ایمنی هسته را تضمین نمی‌کند. ساختار پشتیبانی‌نشده، رمزدار یا امضاشده ممکن است پیش از تبدیل رد شود. قفل و اثرانگشت بعضی رقابت‌ها را تشخیص می‌دهند؛ تراکنش پوشه قابل بازیابی است و اتمیک سراسری نیست. شکست یا نبود پیش‌نیاز مهار باید مرحلهٔ اجباری CI را ناموفق کند.

## مستندات

- [نصب و بسته‌بندی بومی](docs/installation.md)
- [معماری](docs/architecture.md)
- [یکپارچگی نصب](docs/installation-integrity.md)
- [تست امنیت](docs/security-testing.md)
- [اسکیل نه‌مرحله‌ای](skills/revayat-scientific/SKILL.md)
- [خروجی PDF](skills/revayat-scientific/references/pdf-output.md)
- [DOCX](skills/revayat-scientific/references/docx.md) و [پردازش PDF](skills/revayat-scientific/references/pdf-processing.md)

## توسعه

CI در هر push و pull request خودکار اجرا می‌شود و اجرای دستی هم دارد. شاخهٔ مرجع `rewrite/rust-native` است و ادامهٔ آن در `rewrite/rust-complete` انجام می‌شود. [راهنمای توسعه و راستی‌آزمایی مهاجرت](docs/development.md) فرمان‌های محلی و شرط‌های پذیرش باقی‌مانده را توضیح می‌دهد.

<div dir="ltr">

```console
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo build --locked --workspace --all-targets
cargo build --locked --release --workspace --bins
cargo run --locked --bin revayat-test-runner -- --tier portable --profile debug --output execution/portable-debug.json --timeout 1800
cargo run --locked --bin revayat-test-runner -- --tier portable --profile release --output execution/portable-release.json --timeout 1800
cargo run --locked --bin revayat-scientific -- migration-check
cargo run --locked --bin revayat-scientific -- validate
cargo run --locked --release --bin revayat-scientific -- package
```

</div>

فرمان‌های runner به اطلاعات اجرای GitHub Actions و تطابق SHA با checkout نیاز دارند؛ این‌ها فرمان‌های نوشته‌شدهٔ CI هستند، نه دستور پذیرش محلی. caseهای مجهز و قرارداد جمع‌بندی یازده scope در [تست امنیت](docs/security-testing.md) آمده‌اند. collector بومی اکنون harnessهای واقعی Windows و caseهای worker ایزولهٔ Linux را پس از احراز پیش‌نیازها اجرا می‌کند. شاهد bootstrap و دیگر censusهای تو‌در‌تو هنوز کامل نیست؛ برابری کامل ادعا نمی‌شود.

نگاشت مهاجرت ۵۸۳ شناسهٔ تست عمومی قبلی را نگه می‌دارد؛ فهرست‌های جداگانه نیز ۳۷ بررسی بالادستی و ۴۱ سناریوی مستقل امنیتی را ثبت می‌کنند. این تعدادها و counterpartهای ثبت‌شدهٔ Rust، **برابری assertionها یا اجرای واقعی را اثبات نمی‌کنند**. مرحله‌های bootstrap ویندوز، check/helperهای هم‌پوشان و caseهای مستقل oracle رجیستری به شاهد رفتاری و بومی جدا نیاز دارند؛ استفادهٔ پیاده‌سازی قبلی از زبان دیگر مجوز حذف این تعهدها نیست.

قرارداد CI شامل buildهای debug/release و تست portable روی Linux، macOS و Windows، اجرای مجهز علمی برای caseهای اجباری ignored، امنیت Linux/Windows، CodeQL، بازبینی وابستگی، بررسی workflow و گزارش جمعی fail-closed است. اتصال workflow و شاهد اجرای واقعی هنوز در حال تکمیل است. بازگردانی کامل تشخیص‌های بومی Windows و اثبات کامل حذف کد مرده یا تکراری هنوز کامل نشده‌اند. ممیزی سورس، طبقه‌بندی و سقف ۷۹۹ خط برای هر فایل را کنترل و اندازهٔ قابل‌مقایسهٔ سورس و تست را گزارش می‌کند؛ پایین‌تر بودن مجموع از baseline قبلی شرط نیست. کیفیت به شاهد بازبینی حذف و حفظ رفتار و اجرای واقعی تست نیاز دارد، نه صرفاً تعداد خط کمتر. برابری کامل بومی ادعا نمی‌شود. گزارش کامل job/case و SHA آزمایش‌شدهٔ همان run را بررسی کنید؛ این راهنما موفقیت همهٔ CI یا برابری کامل تست‌ها را ادعا نمی‌کند. Dependabot وابستگی‌های Cargo، Actions و کانتینر را دنبال می‌کند؛ ممیزی سخت‌گیرانهٔ Cargo، rustfmt، Clippy، actionlint و zizmor اجباری‌اند.

گزارش ترجمه را کنار سند و در تمام نه مرحله تکمیل کنید. برنامه گزارش عملیاتی جداگانه با زمان UTC در `./logs` می‌نویسد؛ `REVAYAT_LOG_DIR` محل و `REVAYAT_LOG_LEVEL` یکی از `DEBUG`، `INFO`، `WARNING` یا `ERROR` را تعیین می‌کند. این گزارش فقط نام دستهٔ فرمان، دسته و کد خروج و مدت اجرا را ثبت می‌کند و شامل آرگومان، خروجی ابزار یا مسیر خصوصی نیست. تشخیص‌ها و دفتر بازیابی محلی‌اند.

## حمایت مالی

اگر این پروژه به کارتان آمده، حمایت مالی قدردانی می‌شود. نشانی‌ها و شبکه‌ها در [بخش حمایت انگلیسی](README.md#donate) آمده‌اند.

## نویسنده

Kiaro Sama — [KiaroSama](https://github.com/KiaroSama)

## مجوز

[GNU GPL نسخهٔ ۳ یا بالاتر](LICENSE). ابزارهای اختیاری و اسناد منبع مجوز خود را دارند.

</div>
