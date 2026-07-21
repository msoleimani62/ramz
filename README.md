<div align="center">

# ramz

**رمز · Secure, cross-platform file archiving — compress and encrypt in one command**

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2021-orange.svg)](https://www.rust-lang.org)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Android%20(Termux)-lightgrey.svg)](#installation)
[![Tests](https://img.shields.io/badge/tests-46%20passing-brightgreen.svg)](#testing)

[English](#-english) · [فارسی](#-فارسی)

</div>

---

## 🇬🇧 English

### Table of contents

- [What is ramz](#what-is-ramz)
- [Features](#features)
- [Security design](#security-design)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Command reference](#command-reference)
- [Backends explained](#backends-explained)
- [Uninstall](#uninstall)
- [Architecture](#architecture)
- [Testing](#testing)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

### What is ramz

`ramz` is a command-line tool that compresses and encrypts a file or folder
in a single step, then verifies the result before ever touching your
original data. It wraps well-audited, existing cryptography (never
hand-rolled) behind one simple interface: `pack`, `verify`, `extract`.

### Features

- 🔒 **Modern encryption by default** — [age](https://age-encryption.org)
  passphrase encryption (ChaCha20-Poly1305), a simple and audited format,
  no external binary required.
- 🧂 **Optional Argon2id KDF** (`--argon2id`) — memory-hard key derivation
  as a hardened alternative to age's built-in scrypt-based KDF.
- 🧬 **Optional ML-KEM-768 hybrid hardening** (`--mlkem`) — see
  [Security design](#security-design) below for exactly what this does
  and does not protect against; the honest wording matters here.
- 🔁 **Compatibility mode** — a `7z`-backed backend for when the
  recipient doesn't have `ramz` and needs a format their own tools can
  open.
- ✅ **Verify before delete** — the archive is independently re-read and
  checked before the original source is ever removed. No verify, no
  delete.
- 📦 **File-type-aware compression** — already-compressed formats (jpg,
  mp4, pdf, zip, etc.) are stored instead of wasting time re-compressing
  them.
- 📊 **Live progress** — real byte-accurate progress bar with elapsed
  time and ETA.
- 🔍 **Dry-run mode** (`--dry-run`) — preview the estimated output size
  and settings before actually creating the archive.
- 🧩 **Modular by design** — every backend is a self-contained crate
  behind one shared `Backend` trait; adding a new backend never touches
  the CLI or core logic.
- 📱 **Built for constrained environments** — developed and tested on
  Termux/Kali NetHunter (proot/chroot) in addition to standard Linux.

### Security design

Two encryption modes are available beyond the age default, and it's
important to understand exactly what each one buys you:

**`--argon2id`** replaces age's internal scrypt-based key derivation with
Argon2id (64 MiB memory, 3 iterations, parallelism 4). This makes
password-guessing attacks meaningfully more expensive for an attacker,
independent of ML-KEM.

**`--mlkem`** adds a *hybrid hardening* layer, not a recipient-key
system. Concretely: a fresh ML-KEM-768 keypair is generated per archive,
self-encapsulated, and the resulting shared secret is combined
(SHA-256) with the Argon2id-derived key to form the final encryption
key. The ML-KEM decapsulation key itself is stored in the archive,
encrypted under the same Argon2id key.

**What this means in practice:** `--mlkem` provides defense-in-depth
against a hypothetical structural flaw in how the final key is derived
or used (key separation). It does **not** provide extra protection
against someone guessing your password — if the password is
compromised, the ML-KEM secret is trivially recoverable right alongside
it. This is an honest, deliberate design choice: a true post-quantum
guarantee would require a separate recipient-key workflow (see
[Roadmap](#roadmap)), which doesn't exist yet.

Both flags currently apply to the `age` backend only. The `7z` backend
does not support them.

### Installation

#### Build from source (recommended for now)

Requires the [Rust toolchain](https://rustup.rs):

```bash
git clone https://github.com/msoleimani62/ramz.git
cd ramz
cargo build --release
```

The binary is at `target/release/ramz`. Optionally install it onto your
`PATH`:

```bash
cargo install --path cli
```

#### 7z backend requirement

The `--backend seven-z` mode shells out to a system `7z`/`7zz`/`7za`
binary. Install one of these if you plan to use it:

```bash
# Debian / Kali / Ubuntu
sudo apt install 7zip

# Arch Linux
sudo pacman -S p7zip
```

The default `age` backend needs nothing extra.

#### Prebuilt binaries

Not published yet — see [Roadmap](#roadmap).

### Quick start

```bash
# Pack a file or folder with the default age backend, prompts for a password
ramz pack /path/to/folder --password "your-password"

# Pack with Argon2id key derivation
ramz pack /path/to/file.pdf --password "your-password" --argon2id

# Pack with ML-KEM hybrid hardening (implies Argon2id, see Security design)
ramz pack /path/to/file.pdf --password "your-password" --mlkem

# Preview the archive without creating it
ramz pack /path/to/folder --password "your-password" --dry-run

# Delete the source only after the archive is verified successfully
ramz pack /path/to/folder --password "your-password" --delete-source

# Use the 7z-compatible backend instead
ramz pack /path/to/folder --password "your-password" --backend seven-z

# Verify an existing archive
ramz verify /path/to/folder.age.tar.zst --password "your-password"

# Extract an archive
ramz extract /path/to/folder.age.tar.zst --output /path/to/destination --password "your-password"
```

### Command reference

```
Usage: ramz <COMMAND>

Commands:
  pack     Pack files into an encrypted archive
  verify   Verify archive integrity
  extract  Extract archive contents
  help     Print this message or the help of the given subcommand(s)
```

**`ramz pack <SOURCE>`**

| Flag | Description |
|---|---|
| `-o, --output <DIR>` | Output directory (default: same as source) |
| `-p, --password <PASSWORD>` | Password for encryption |
| `-c, --confirm-password` | Confirm password interactively |
| `-l, --compression-level <N>` | Compression level (1–22 for age, 0–9 for 7z) |
| `-d, --delete-source` | Delete source after successful verification |
| `-f, --force` | Force overwrite of an existing archive |
| `-b, --backend <age\|seven-z>` | Backend to use [default: `age`] |
| `--argon2id` | Use Argon2id instead of age's default KDF |
| `--mlkem` | Enable ML-KEM hybrid hardening — see [Security design](#security-design) |
| `--dry-run` | Preview output without creating the archive |
| `--resume` | ⚠️ Partially implemented — see [ROADMAP.md](ROADMAP.md) |

**`ramz verify <ARCHIVE>`**

| Flag | Description |
|---|---|
| `-p, --password <PASSWORD>` | Password for decryption |

**`ramz extract <ARCHIVE>`**

| Flag | Description |
|---|---|
| `-o, --output <DIR>` | Output directory |
| `-p, --password <PASSWORD>` | Password for decryption |

### Backends explained

| Backend | Flag | Extension | External binary | Best for |
|---|---|---|---|---|
| age (default) | `--backend age` | `.age.tar.zst` | No | You control both ends, or the recipient also has `ramz`/`age` |
| 7z compatibility | `--backend seven-z` | `.7z` | Yes (`7z`/`7zz`/`7za`) | Sending an archive to someone with only 7-Zip/WinRAR/etc. |

### Uninstall

```bash
# If installed via cargo install
cargo uninstall ramz

# Remove the cloned source
rm -rf ~/ramz
```

### Architecture

```
ramz/
├── core/            shared types, Backend trait, tar/dry-run/resume helpers
├── backends-age/     age backend — Argon2id, ML-KEM hybrid, zstd compression
├── backends-7z/      7z backend (compatibility mode)
├── cli/              command-line interface (binary: ramz)
```

Every backend implements the same `Backend` trait. Adding a new one means
writing a new crate — the CLI and core logic never change.

### Testing

```bash
cargo test --workspace
```

46 tests currently cover path detection, tar packing/unpacking, dry-run
estimation, resume-state checksums, ML-KEM roundtrips, Argon2id key
derivation, and full pack → verify → extract round-trips for every mode
(default age, `--argon2id`, `--mlkem`), including wrong-password
rejection for each.

### Roadmap

See [TODO.md](TODO.md) and [ROADMAP.md](ROADMAP.md) for the full,
up-to-date, detailed list. Highlights:

- Wiring `--resume` to actually resume interrupted archives
- A real recipient-key workflow for ML-KEM (true post-quantum guarantee,
  not just hybrid hardening)
- Confirmed CI pipeline and prebuilt cross-platform binaries
- Zeroizing derived keys in memory

### Contributing

This is currently a personal project under active development. Issues
and pull requests are welcome once the repository stabilizes.

### License

[MIT](LICENSE)

---

## 🇮🇷 فارسی

### فهرست مطالب

- [ramz چیست](#ramz-چیست)
- [ویژگی‌ها](#ویژگی‌ها)
- [طراحی امنیتی](#طراحی-امنیتی)
- [نصب](#نصب)
- [شروع سریع](#شروع-سریع)
- [مرجع دستورات](#مرجع-دستورات)
- [توضیح بک‌اندها](#توضیح-بکاندها)
- [حذف نصب](#حذف-نصب)
- [معماری](#معماری)
- [تست](#تست)
- [نقشه راه](#نقشه-راه)
- [مشارکت](#مشارکت)
- [مجوز](#مجوز)

### ramz چیست

`ramz` یک ابزار خط‌فرمان هست که یک فایل یا پوشه رو در یک مرحله فشرده و
رمزگذاری می‌کنه، و قبل از این‌که به فایل اصلی شما دست بزنه، نتیجه رو تایید
می‌کنه. این ابزار رمزنگاری‌های موجود و audited (نه دست‌نویس) رو پشت یک
رابط ساده با سه دستور اصلی قرار می‌ده: `pack`, `verify`, `extract`.

### ویژگی‌ها

- 🔒 **رمزگذاری مدرن به‌صورت پیش‌فرض** — رمزگذاری passphrase-based
  [age](https://age-encryption.org) (ChaCha20-Poly1305)، یک فرمت ساده و
  audited، بدون نیاز به باینری خارجی.
- 🧂 **KDF اختیاری Argon2id** (`--argon2id`) — اشتقاق کلید memory-hard
  به‌عنوان جایگزین سخت‌شده‌ی KDF داخلی scrypt-based خودِ age.
- 🧬 **سخت‌سازی hybrid با ML-KEM-768** (`--mlkem`) — برای این‌که دقیقاً
  بدونی این فلگ چی رو محافظت می‌کنه و چی رو نه، بخش
  [طراحی امنیتی](#طراحی-امنیتی) رو حتماً بخون؛ صداقت اینجا مهمه.
- 🔁 **حالت سازگاری** — یک بک‌اند مبتنی بر `7z` برای وقتی که طرف مقابل
  `ramz` نداره و به فرمتی نیاز داره که ابزار خودش بازش کنه.
- ✅ **تایید قبل از حذف** — آرشیو به‌طور مستقل دوباره خونده و بررسی
  می‌شه قبل از این‌که مبدا اصلی حذف بشه. بدون تایید، حذفی هم در کار نیست.
- 📦 **فشرده‌سازی هوشمند بر اساس نوع فایل** — فرمت‌های از قبل فشرده
  (jpg، mp4، pdf، zip و مشابه) دوباره فشرده نمی‌شن، فقط ذخیره می‌شن.
- 📊 **پیشرفت زنده** — نوار پیشرفت دقیق بر اساس بایت واقعی، با زمان
  سپری‌شده و زمان تخمینی باقی‌مانده.
- 🔍 **حالت dry-run** (`--dry-run`) — پیش‌نمایش سایز تخمینی و تنظیمات
  خروجی قبل از ساخت واقعی آرشیو.
- 🧩 **ماژولار از پایه** — هر بک‌اند یک crate مستقل پشت یک trait مشترک
  `Backend` هست؛ اضافه‌کردن بک‌اند جدید هیچ‌وقت به CLI یا منطق اصلی دست
  نمی‌زنه.
- 📱 **ساخته‌شده برای محیط‌های محدود** — علاوه بر لینوکس استاندارد، روی
  Termux/Kali NetHunter (proot/chroot) هم توسعه و تست شده.

### طراحی امنیتی

دو تا حالت رمزگذاری اضافه بر حالت پیش‌فرض age در دسترسه، و مهمه دقیقاً
بدونی هرکدوم چی می‌ده:

**`--argon2id`** به‌جای KDF داخلی scrypt-based خودِ age، از Argon2id (۶۴
مگابایت حافظه، ۳ iteration، parallelism ۴) استفاده می‌کنه. این کار حمله‌ی
حدس‌زدن پسورد رو برای مهاجم به‌طور معناداری گرون‌تر می‌کنه، مستقل از
ML-KEM.

**`--mlkem`** یه لایه‌ی *سخت‌سازی hybrid* اضافه می‌کنه، نه یه سیستم
recipient-key. دقیقاً: به ازای هر آرشیو، یه جفت‌کلید تازه‌ی ML-KEM-768
تولید می‌شه، به خودش self-encapsulate می‌شه، و secret مشترک حاصل با
کلید مشتق‌شده از Argon2id ترکیب می‌شه (SHA-256) تا کلید نهایی ساخته بشه.
خودِ decapsulation key هم داخل آرشیو، رمزشده با همون کلید Argon2id،
ذخیره می‌شه.

**معنای عملی این طراحی:** `--mlkem` در برابر یه ضعف ساختاری فرضی در
نحوه‌ی اشتقاق یا استفاده از کلید نهایی (جداسازی کلید) دفاع اضافه می‌ده.
این فلگ در برابر حدس‌زدن پسورد **هیچ محافظت اضافه‌ای نمی‌ده** — اگه
پسورد لو بره، secret مربوط به ML-KEM هم دقیقاً کنارش به‌راحتی قابل
بازیابیه. این یه تصمیم طراحی صادقانه و عمدیه: یه تضمین واقعی
post-quantum نیاز به یه workflow جداگانه‌ی recipient-key داره (به
[نقشه راه](#نقشه-راه) نگاه کن) که هنوز وجود نداره.

هر دو فلگ فعلاً فقط روی بک‌اند `age` کار می‌کنن. بک‌اند `7z` ازشون
پشتیبانی نمی‌کنه.

### نصب

#### ساخت از سورس (فعلاً روش پیشنهادی)

نیاز به نصب [Rust](https://rustup.rs):

```bash
git clone https://github.com/msoleimani62/ramz.git
cd ramz
cargo build --release
```

باینری در مسیر `target/release/ramz` قرار می‌گیره. برای نصب اختیاری روی
`PATH`:

```bash
cargo install --path cli
```

#### پیش‌نیاز بک‌اند 7z

حالت `--backend seven-z` از باینری سیستمی `7z`/`7zz`/`7za` استفاده
می‌کنه. اگه قصد استفاده ازش رو داری، یکی از این‌ها رو نصب کن:

```bash
# دبیان / کالی / اوبونتو
sudo apt install 7zip

# آرچ لینوکس
sudo pacman -S p7zip
```

بک‌اند پیش‌فرض `age` به هیچ چیز اضافه‌ای نیاز نداره.

#### باینری از پیش کامپایل‌شده

هنوز منتشر نشده — به بخش [نقشه راه](#نقشه-راه) نگاه کن.

### شروع سریع

```bash
# رمزگذاری یک پوشه با بک‌اند پیش‌فرض age
ramz pack /path/to/folder --password "your-password"

# رمزگذاری با اشتقاق کلید Argon2id
ramz pack /path/to/file.pdf --password "your-password" --argon2id

# رمزگذاری با سخت‌سازی hybrid از طریق ML-KEM (شامل Argon2id هم می‌شه)
ramz pack /path/to/file.pdf --password "your-password" --mlkem

# پیش‌نمایش آرشیو بدون ساخت واقعیش
ramz pack /path/to/folder --password "your-password" --dry-run

# حذف مبدا فقط پس از تایید موفقیت‌آمیز آرشیو
ramz pack /path/to/folder --password "your-password" --delete-source

# استفاده از بک‌اند سازگار با 7z
ramz pack /path/to/folder --password "your-password" --backend seven-z

# تایید یک آرشیو موجود
ramz verify /path/to/folder.age.tar.zst --password "your-password"

# استخراج یک آرشیو
ramz extract /path/to/folder.age.tar.zst --output /path/to/destination --password "your-password"
```

### مرجع دستورات

```
Usage: ramz <COMMAND>

Commands:
  pack     بسته‌بندی فایل‌ها در یک آرشیو رمزشده
  verify   تایید یکپارچگی آرشیو
  extract  استخراج محتوای آرشیو
  help     نمایش این پیام یا راهنمای هر ساب‌کامند
```

**`ramz pack <SOURCE>`**

| فلگ | توضیح |
|---|---|
| `-o, --output <DIR>` | پوشه‌ی خروجی (پیش‌فرض: همون پوشه‌ی مبدا) |
| `-p, --password <PASSWORD>` | پسورد رمزگذاری |
| `-c, --confirm-password` | تایید تعاملی پسورد |
| `-l, --compression-level <N>` | سطح فشرده‌سازی (۱ تا ۲۲ برای age، ۰ تا ۹ برای 7z) |
| `-d, --delete-source` | حذف مبدا پس از تایید موفقیت‌آمیز |
| `-f, --force` | بازنویسی اجباری آرشیو موجود |
| `-b, --backend <age\|seven-z>` | بک‌اند مورد استفاده [پیش‌فرض: `age`] |
| `--argon2id` | استفاده از Argon2id به‌جای KDF پیش‌فرض age |
| `--mlkem` | فعال‌سازی سخت‌سازی hybrid با ML-KEM — به [طراحی امنیتی](#طراحی-امنیتی) نگاه کن |
| `--dry-run` | پیش‌نمایش خروجی بدون ساخت واقعی آرشیو |
| `--resume` | ⚠️ پیاده‌سازی ناقص — به [ROADMAP.md](ROADMAP.md) نگاه کن |

**`ramz verify <ARCHIVE>`**

| فلگ | توضیح |
|---|---|
| `-p, --password <PASSWORD>` | پسورد رمزگشایی |

**`ramz extract <ARCHIVE>`**

| فلگ | توضیح |
|---|---|
| `-o, --output <DIR>` | پوشه‌ی خروجی |
| `-p, --password <PASSWORD>` | پسورد رمزگشایی |

### توضیح بک‌اندها

| بک‌اند | فلگ | پسوند | نیاز به باینری خارجی | مناسب برای |
|---|---|---|---|---|
| age (پیش‌فرض) | `--backend age` | `.age.tar.zst` | خیر | خودت هر دو طرف رو کنترل می‌کنی، یا طرف مقابل هم `ramz`/`age` داره |
| سازگاری با 7z | `--backend seven-z` | `.7z` | بله (`7z`/`7zz`/`7za`) | فرستادن آرشیو برای کسی که فقط 7-Zip/WinRAR و مشابه داره |

### حذف نصب

```bash
# اگه با cargo install نصب کردی
cargo uninstall ramz

# حذف پوشه‌ی سورس کلون‌شده
rm -rf ~/ramz
```

### معماری

```
ramz/
├── core/             تایپ‌های مشترک، trait اصلی Backend، ابزارهای tar/dry-run/resume
├── backends-age/      بک‌اند age — Argon2id، سخت‌سازی hybrid با ML-KEM، فشرده‌سازی zstd
├── backends-7z/       بک‌اند 7z (حالت سازگاری)
├── cli/               رابط خط فرمان (باینری: ramz)
```

هر بک‌اند همون trait مشترک `Backend` رو پیاده می‌کنه. اضافه‌کردن یک
بک‌اند جدید یعنی نوشتن یک crate جدید — CLI و منطق اصلی هیچ‌وقت تغییر
نمی‌کنن.

### تست

```bash
cargo test --workspace
```

الان ۴۶ تست، تشخیص مسیر، بسته‌بندی/باز‌کردن tar، تخمین dry-run، چک‌سام
حالت resume، چرخه‌ی ML-KEM، اشتقاق کلید Argon2id، و چرخه‌ی کامل pack →
verify → extract برای هر سه حالت (age پیش‌فرض، `--argon2id`، `--mlkem`)
رو پوشش می‌ده — شامل تست رد رمز عبور غلط برای هرکدوم.

### نقشه راه

فهرست کامل و به‌روز رو توی [TODO.md](TODO.md) و [ROADMAP.md](ROADMAP.md)
ببین. مهم‌ترین‌ها:

- وایر کردن واقعی `--resume` تا آرشیوهای ناقص رو واقعاً ادامه بده
- یه workflow واقعی recipient-key برای ML-KEM (تضمین واقعی
  post-quantum، نه فقط سخت‌سازی hybrid)
- تأیید pipeline واقعی CI و باینری‌های از پیش کامپایل‌شده‌ی کراس‌پلتفرم
- Zeroize کردن کلیدهای مشتق‌شده در حافظه

### مشارکت

این فعلاً یک پروژه‌ی شخصی در حال توسعه‌ی فعاله. بعد از پایدارشدن ریپو، از
issue و pull request استقبال می‌شه.

### مجوز

[MIT](LICENSE)
