<div dir="rtl">

# روایت علمی — Revayat Scientific

<div align="center">

[![CI status on main](https://github.com/KiaroSama/Revayat-Scientific-Skill/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/KiaroSama/Revayat-Scientific-Skill/actions/workflows/ci.yml)
[![CodeQL status on main](https://github.com/KiaroSama/Revayat-Scientific-Skill/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/KiaroSama/Revayat-Scientific-Skill/actions/workflows/codeql.yml)
[![GPL-3.0-or-later license](https://img.shields.io/badge/License-GPL--3.0--or--later-blue?style=flat-square)](LICENSE)
[![Plugin version 2.0.0](https://img.shields.io/badge/Plugin-2.0.0-blue?style=flat-square)](.codex-plugin/plugin.json)
<br>
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

## وضعیت snapshot آماده‌سازی

این snapshot شاخهٔ `rewrite/rust-native` آماده‌سازی hosted محدود lock/notices است، نه مهاجرت کامل یا release تأییدشده. نشان‌ها مربوط به `main` هستند؛ برابری کامل native و CI نهایی همان SHA هنوز تأیید نشده‌اند.

در Linux/macOS، فراخوانی ابزار به `revayat-process-owner` کنار برنامه و از همان build/revision نیاز دارد. همهٔ binaryها را با `cargo build --locked --release --workspace --bins` بسازید؛ `cargo run --bin revayat-scientific` sibling را دوباره نمی‌سازد. Windows از Job بومی استفاده می‌کند. تغییرات package/install همراه companion هنوز در این snapshot نیست؛ آرشیو `.skill` را payload کامل یونیکس فرض نکنید. موتورهای سند جدا هستند.

برای آماده‌سازی hosted تأییدشده، workflow موجود CI را روی revision بازبینی‌شده انتخاب کنید، SHA کامل `base_ref` را بدهید و `prepare_artifacts=true` بگذارید؛ پیش‌فرض `false` است. artifact با نام `prepared-lock-notices-<sha>-<run_id>-<attempt>` فقط `Cargo.lock` و `skills/revayat-scientific/references/third-party-licenses.txt` دارد. عضویت دقیق و revision/run/attempt را پیش از import بررسی کنید. jobهای عادی و status publisherها در این حالت اجرا نمی‌شوند؛ موفقیت آماده‌سازی، پذیرش مهاجرت یا CI کامل نیست. [جزئیات نصب](docs/installation.md).

## نصب

برای ساخت از منبع، [Rust](https://rustup.rs/) را نصب کنید؛ نسخهٔ دقیق در `rust-toolchain.toml` ثبت شده است.

<div dir="ltr">

```console
git clone https://github.com/KiaroSama/Revayat-Scientific-Skill.git
cd Revayat-Scientific-Skill
cargo build --locked --release --workspace --bins
cargo run --locked --release --bin revayat-scientific -- install --agent codex
```

</div>

گزینهٔ `--agent all` میزبان‌های شناسایی‌شده، `--scope project --path <directory>` پروژه و `--dest <directory>` مقصد سفارشی را انتخاب می‌کند. جایگزینی با `--force` فقط برای نصب دارای هویت روشن روایت مجاز است. همهٔ مقصدها پیش از فعال‌سازی آماده می‌شوند و نسخهٔ قبلی در `skill-backups` می‌ماند. [جزئیات نصب](docs/installation.md).

CI برای Linux، macOS و Windows فایل اجرایی و آرشیو `.skill` می‌سازد. آرشیو بومی شامل برنامه، اسکیل، مراجع، قالب‌ها، مجوز و اعلان‌هاست. Rust برای کامپایل لازم است؛ اجرای فایل ساخته‌شده به مفسر زبان دیگری نیاز ندارد.

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

طرح دقیق هر فرمان با `--help` مشخص است. منابع، واژه‌نامه، تصاویر و گزارش ترجمه را بیرون از اسکیل نگه دارید. برای تقسیم ترجمه بین ایجنت‌های بیشتر رضایت بگیرید. زبان منبع، مخاطب، سطح اصطلاحات و نتیجهٔ واقعی بررسی‌ها را ثبت کنید.

| ابزار بومی اختیاری | کاربرد لازم |
| --- | --- |
| Chrome/Chromium/Edge با sandbox فعال | رندر HTML با مشتری بومی DevTools |
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

<div dir="ltr">

```console
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo build --locked --workspace --all-targets
cargo test --locked --workspace --all-targets -- --test-threads=1
cargo run --locked --bin revayat-scientific -- migration-check
cargo run --locked --bin revayat-scientific -- validate
cargo run --locked --release --bin revayat-scientific -- package
```

</div>

فهرست مهاجرت، هر ۵۸۳ تست عمومی قبلی را به سناریوی ثبت‌شدهٔ Rust نگاشت می‌کند. هر ۳۷ بررسی مستقل علمی بالادستی و ۴۱ سناریوی مستقل امنیتی نیز با فهرست‌های جداگانه حفظ شده‌اند؛ از جمله مصرف‌کنندهٔ مستقل OPC ویندوز و فراخوان‌های واقعی مسیر junction. تست رندر دارای پیش‌نیاز صریح است و CI علمی آن را با `--include-ignored` واقعاً اجرا می‌کند. مرحله‌های امنیت Linux و Windows، CodeQL، بازبینی وابستگی، سه سیستم‌عامل، رندر علمی، کیفیت و گزارش جمعی حفظ شده‌اند. هر سیستم‌عامل بیلد release و آرشیو خودش را تولید می‌کند. Dependabot وابستگی‌های Cargo، Actions و کانتینر را دنبال می‌کند؛ ممیزی سخت‌گیرانهٔ Cargo، rustfmt، Clippy، actionlint و zizmor اجباری‌اند.

گزارش ترجمه را کنار سند و در تمام نه مرحله تکمیل کنید. برنامه گزارش عملیاتی جداگانه با زمان UTC در `./logs` می‌نویسد؛ `REVAYAT_LOG_DIR` محل و `REVAYAT_LOG_LEVEL` یکی از `DEBUG`، `INFO`، `WARNING` یا `ERROR` را تعیین می‌کند. این گزارش فقط نام دستهٔ فرمان، دسته و کد خروج و مدت اجرا را ثبت می‌کند و شامل آرگومان، خروجی ابزار یا مسیر خصوصی نیست. تشخیص‌ها و دفتر بازیابی محلی‌اند.

## حمایت مالی

اگر این پروژه به کارتان آمده، حمایت مالی قدردانی می‌شود. نشانی‌ها و شبکه‌ها در [بخش حمایت انگلیسی](README.md#donate) آمده‌اند.

## نویسنده

Kiaro Sama — [KiaroSama](https://github.com/KiaroSama)

## مجوز

[GNU GPL نسخهٔ ۳ یا بالاتر](LICENSE). ابزارهای اختیاری و اسناد منبع مجوز خود را دارند.

</div>
