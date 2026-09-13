# Revayat Scientific — روایت علمی

[English](README.md) · [راهنمای اسکیل](skills/revayat-scientific/SKILL.md)

[![CI](https://github.com/KiaroSama/Revayat-Scientific-Skill/actions/workflows/ci.yml/badge.svg)](https://github.com/KiaroSama/Revayat-Scientific-Skill/actions/workflows/ci.yml)

اسکیل ترجمهٔ مقاله، پایان‌نامه، کتاب فنی و مستندات علمی از انگلیسی به فارسی. ادعاها، میزان قطعیت، عددها، فرمول‌ها، شکل‌ها و ارجاع‌ها حفظ می‌شوند. ساختار پروژه با خانوادهٔ Revayat هماهنگ است.

## قابلیت‌ها

| قابلیت | رفتار |
| --- | --- |
| دقت علمی | حفظ معنا، عدم قطعیت، واحدها، فرمول‌ها و منابع |
| اصطلاحات | یک معادل ترجیحی برای هر مفهوم و قواعد جداگانه برای مقاله و مستندات |
| فارسی روان | بازبینی دقت و روانی متن با ثبت پوشش واقعی |
| خروجی چاپ | اولویت XeLaTeX؛ بررسی جداگانهٔ ظاهر و ترتیب متن قابل کپی |
| چندسکویی | Windows، macOS و Linux؛ بدون وابستگی به مدل یا API مشخص |

## نصب

Python 3.10 یا جدیدتر لازم است. نصب‌کننده و بررسی متن از کتابخانهٔ استاندارد استفاده می‌کنند. وابستگی‌های پردازش تصویر و استخراج PDF اختیاری‌اند:

```bash
git clone https://github.com/KiaroSama/Revayat-Scientific-Skill.git
cd Revayat-Scientific-Skill
python -m pip install -r skills/revayat-scientific/requirements.txt
bash install/install.sh
```

در Windows:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ./install/install.ps1
```

هر دو نصب‌کننده گزینه‌های یکسان دارند. پیش‌فرض، نصب برای ایجنت‌های شناسایی‌شده است. برای نصب محدود به پروژه:

```bash
python install/install.py --agent codex --scope project --path "/path/to/project"
```

برای جایگزینی نسخهٔ موجود `--force` لازم است؛ نسخهٔ قبلی به‌صورت پشتیبان باقی می‌ماند. هیچ وابستگی یا تنظیم ایجنتی خودکار تغییر نمی‌کند. [مسیرهای نصب](docs/installation.md).

### پلاگین

```text
/plugin marketplace add KiaroSama/Revayat-Scientific-Skill
/plugin install revayat-scientific@revayat-scientific-skill
```

فایل‌های معرفی پلاگین برای Claude Code، Cursor و Codex موجودند. برای میزبان‌هایی که فایل اسکیل می‌پذیرند، `python tools/package.py` بستهٔ `dist/revayat-scientific.skill` را می‌سازد. شناسایی در رابط هر برنامه جدا از صحت بسته است.

## استفاده

به ایجنت بگو: «با revayat-scientific این مقاله را به فارسی ترجمه کن، فرمول‌ها و شکل‌ها را حفظ کن و PDF تأییدشده بده.»

در Codex نام صریح `$revayat-scientific` است. ورودی می‌تواند فایل محلی، پیوست یا لینک قابل‌دسترسی باشد. خود ایجنت متن را می‌خواند و ترجمه می‌کند؛ اسکریپت‌ها کار مکانیکی را انجام می‌دهند.

```bash
python skills/revayat-scientific/scripts/revayat-scientific.py doctor
python skills/revayat-scientific/scripts/revayat-scientific.py lint work/doc.tex --level journal --terms work/terms.tsv --manifest work/manifest.txt --strict
python skills/revayat-scientific/scripts/revayat-scientific.py build work/doc.tex article --level journal --verify --output-dir work/output
```

این فرمان‌ها در هر سه سیستم‌عامل یکسان‌اند. برای جزئیات `build --help` را اجرا کن. فرمان‌های `crop`، `figures`، `pages`، `fonts` و `text-order` نیز موجودند.

## گردش کار

ثبت ساختار منبع ← تثبیت اصطلاحات ← آماده‌سازی شکل‌ها ← ترجمهٔ بخش‌ها ← بازبینی دقت و روانی ← بررسی مکانیکی ← ساخت PDF ← بررسی دیداری ← تحویل.

فایل‌های `terms.tsv` و `manifest.txt` برای بررسی سخت‌گیرانه لازم‌اند. اگر شکل وجود ندارد، manifest فقط یک توضیح دارد. برای ادامهٔ کار، منبع قابل‌ویرایش و دفتر پیشرفت نگه داشته می‌شوند.

خروجی پیش‌فرض در `$HOME/Documents/books` است؛ `--output-dir` مسیر را عوض می‌کند. شکست بررسی یا ساخت، PDF تحویل‌شدهٔ قبلی را دست‌نخورده نگه می‌دارد. `--verify` به Poppler نیاز دارد و تصویر نمونهٔ صفحات را تولید می‌کند؛ ایجنت باید آن‌ها را ببیند.

## محدودیت‌ها

- عبور از بررسی مکانیکی، صحت علمی ترجمه را اثبات نمی‌کند.
- اسکن و PDF چندستونی به خواندن دیداری یا OCR و تطبیق با منبع نیاز دارند؛ برش شکل‌ها نیز باید بررسی شود.
- PDF حاصل از HTML ممکن است ظاهر درست ولی متن قابل‌کپی معکوس داشته باشد؛ اولویت با XeLaTeX است.
- بازسازی دقیق صفحه‌آرایی ناشر تضمین نمی‌شود؛ هدف حفظ محتوای علمی و خوانایی است.
- تست‌های CI کیفیت ترجمهٔ یک مقالهٔ دلخواه یا فعال‌شدن در رابط همهٔ ایجنت‌ها را تأیید نمی‌کنند.

## گزارش اجرا

گزارش‌های UTF-8 فرمان اصلی در `skills/revayat-scientific/logs/` و گزارش نصب و بسته‌بندی در `logs/` هستند. نام هر فایل زمان UTC دارد و اجرای قبلی بازنویسی نمی‌شود. نام عملیات، مدت و کد خروج ثبت می‌شوند؛ متن سند، آرگومان‌ها و خروجی ابزارها در این گزارش‌ها کپی نمی‌شوند. اگر ساخت گزارش ممکن نباشد، پیام در stderr نمایش داده می‌شود. گزارش‌ها محلی‌اند و تا حذف دستی باقی می‌مانند. TeX گزارش مستقل خود را کنار سند می‌نویسد.

## مستندات و توسعه

[گردش کار اسکیل](skills/revayat-scientific/SKILL.md)، [معماری](docs/architecture.md)، [اصطلاحات](skills/revayat-scientific/references/terminology.md)، [سبک علمی](skills/revayat-scientific/references/scientific-style.md) و [بازبینی](skills/revayat-scientific/references/review.md).

```bash
python -m unittest discover -s tests -p 'test_*.py' -v
bash tests/upstream.sh
python tools/validate.py
python tools/package.py
```

CI روی Linux، macOS و Windows اجرا می‌شود و ساخت واقعی PDF با Windows و XeLaTeX روی Linux را بررسی می‌کند. نمونه‌های تست ساختگی و موقت‌اند؛ مقالهٔ واقعی کاربر محسوب نمی‌شوند.

## قدردانی

مبتنی بر [اسکیل اصلی isArman](https://github.com/isArman/scientific-fa-translation-skill)، با حفظ مجوز MIT و [انتساب](skills/revayat-scientific/NOTICE.md). ساختار بسته‌بندی از قراردادهای خانوادهٔ [Revayat Comic](https://github.com/KiaroSama/Revayat-Comic-Skill) و [Revayat Novel](https://github.com/KiaroSama/Revayat-Novel-Skill) پیروی می‌کند.

## حمایت مالی

If this project helps you, donations are appreciated.

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

## نویسنده

Kiaro Sama - [GitHub](https://github.com/KiaroSama)

## مجوز

[GPL-3.0-or-later](LICENSE), with the scientific upstream MIT notice retained. Optional dependencies and source documents retain their own licenses.
