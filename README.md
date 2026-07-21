<div align="center">

# ramz

**رمز · Secure, cross-platform file archiving — compress and encrypt in one command**

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2021-orange.svg)](https://www.rust-lang.org)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Android%20(Termux)-lightgrey.svg)](#installation)
[![Tests](https://img.shields.io/badge/tests-19%20passing-brightgreen.svg)](#testing)

[English](#-english) · [فارسی](#-فارسی)

</div>

---

## 🇬🇧 English

### Table of contents

- [What is ramz](#what-is-ramz)
- [Features](#features)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Command reference](#command-reference)
- [Engines explained](#engines-explained)
- [Uninstall](#uninstall)
- [Architecture](#architecture)
- [Testing](#testing)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

### What is ramz

`ramz` is a command-line tool that compresses and encrypts a file or folder in
a single step, then verifies the result before ever touching your original
data. It wraps well-audited, existing cryptography (never hand-rolled) behind
one simple interface, instead of forcing you to remember different flags for
different tools.

### Features

- 🔒 **Modern encryption by default** — [age](https://age-encryption.org)
  (X25519 + ChaCha20-Poly1305), a simple and audited encryption format, no
  external binary required.
- 🔁 **Compatibility mode** — a `7z`-backed engine for when the recipient
  doesn't have `ramz` and needs a format their own tools can open.
- ✅ **Verify before delete** — the archive is independently re-read and
  checked before the original source is ever removed. No verify, no delete.
- 📊 **Live progress** — real byte-accurate progress bar with elapsed time
  and ETA, for both engines.
- 🧩 **Modular by design** — every engine is a self-contained crate behind
  one shared `Backend` trait; adding a new engine never touches the CLI or
  core logic.
- 📱 **Built for constrained environments** — developed and tested on
  Termux/Kali NetHunter (proot/chroot) in addition to standard Linux.

### Installation

#### Build from source (recommended for now)

Requires the [Rust toolchain](https://rustup.rs):

```bash
git clone https://github.com/msoleimani62/ramz.git
cd ramz
cargo build --release
```

The binary is at `target/release/ramz`. Optionally install it onto your `PATH`:

```bash
cargo install --path cli
```

#### Compatibility mode requirement

The `--engine compat7z` mode shells out to a system `7z`/`7zz`/`7za` binary.
Install one of these if you plan to use it:

```bash
# Debian / Kali / Ubuntu
sudo apt install 7zip

# Arch Linux
sudo pacman -S p7zip
```

The default `age` engine needs nothing extra.

#### Prebuilt binaries

Not published yet — see [Roadmap](#roadmap).

### Quick start

```bash
# Encrypt a folder with the default engine (age), prompts for a password
ramz /path/to/folder

# Encrypt a single file
ramz /path/to/file.pdf

# Delete the source only after the archive is verified successfully
ramz --delete-source /path/to/folder

# Use the 7z-compatible engine instead
ramz --engine compat7z /path/to/folder

# Skip encryption, compress only (must be explicit)
ramz --no-password /path/to/file.pdf

# Choose a specific output folder and compression level
ramz --output /path/to/backups --compression 6 /path/to/folder
```

### Command reference

```
Usage: ramz [OPTIONS] <PATH>

Arguments:
  <PATH>  Path to the source file or directory

Options:
  -e, --engine <ENGINE>            Encryption engine to use [default: age]
                                    [possible values: age, compat7z]
  -o, --output <OUTPUT>            Output directory (default: same as source)
  -d, --delete-source              Delete the source after successful verification
      --no-password                Disable encryption, compression only (must be explicit)
  -c, --compression <COMPRESSION>  Compression level, zero to nine [default: 9]
  -f, --force                      Overwrite the output archive if it already exists
  -h, --help                       Print help
  -V, --version                    Print version
```

### Engines explained

| Engine | Flag | Extension | Needs external binary | Best for |
|---|---|---|---|---|
| age (default) | `--engine age` | `.ramz-age` | No | You encrypt and decrypt it yourself, or send it to someone else who has `ramz`/`age` |
| 7z compatibility | `--engine compat7z` | `.7z` | Yes (`7z`/`7zz`/`7za`) | Sending an archive to someone who only has 7-Zip/WinRAR/etc. |

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
├── core/            shared types, Backend trait, tar packing helpers
├── backends-age/     age engine (default)
├── backends-7z/      7z engine (compatibility mode)
├── cli/              command-line interface (binary: ramz)
```

Every engine implements the same `Backend` trait. Adding a new one (e.g. a
future post-quantum hybrid mode) means writing a new crate — the CLI and
core logic never change.

### Testing

```bash
cargo test --workspace
```

19 unit tests currently cover path detection, tar packing, password
confirmation, output-path safety, and both engines' pack/verify round-trip
(including a wrong-password rejection test).

### Roadmap

See [TODO.md](TODO.md) for the full, up-to-date list. Highlights:

- Argon2id key derivation
- Post-quantum hybrid encryption option
- File-type-aware compression (skip already-compressed files)
- CI pipeline and prebuilt cross-platform binaries

### Contributing

This is currently a personal project under active development. Issues and
pull requests are welcome once the repository stabilizes.

### License

[MIT](LICENSE)

---

## 🇮🇷 فارسی

### فهرست مطالب

- [ramz چیست](#ramz-چیست)
- [ویژگی‌ها](#ویژگی‌ها)
- [نصب](#نصب)
- [شروع سریع](#شروع-سریع)
- [مرجع دستورات](#مرجع-دستورات)
- [توضیح موتورها](#توضیح-موتورها)
- [حذف نصب](#حذف-نصب)
- [معماری](#معماری)
- [تست](#تست)
- [نقشه راه](#نقشه-راه)
- [مشارکت](#مشارکت)
- [مجوز](#مجوز)

### ramz چیست

`ramz` یک ابزار خط‌فرمان هست که یک فایل یا پوشه رو در یک مرحله فشرده و
رمزگذاری می‌کنه، و قبل از این‌که به فایل اصلی شما دست بزنه، نتیجه رو تایید
می‌کنه. این ابزار به‌جای این‌که مجبورت کنه فلگ‌های متفاوت هر ابزار رو حفظ
کنی، رمزنگاری‌های موجود و audited (نه دست‌نویس) رو پشت یک رابط ساده قرار
می‌ده.

### ویژگی‌ها

- 🔒 **رمزگذاری مدرن به‌صورت پیش‌فرض** — موتور
  [age](https://age-encryption.org) (X25519 + ChaCha20-Poly1305)، یک فرمت
  رمزنگاری ساده و audited، بدون نیاز به باینری خارجی.
- 🔁 **حالت سازگاری** — یک موتور مبتنی بر `7z` برای وقتی که طرف مقابل
  `ramz` نداره و به فرمتی نیاز داره که ابزار خودش بازش کنه.
- ✅ **تایید قبل از حذف** — آرشیو به‌طور مستقل دوباره خونده و بررسی می‌شه
  قبل از این‌که مبدا اصلی حذف بشه. بدون تایید، حذفی هم در کار نیست.
- 📊 **پیشرفت زنده** — نوار پیشرفت دقیق بر اساس بایت واقعی، با زمان
  سپری‌شده و زمان تخمینی باقی‌مانده، برای هر دو موتور.
- 🧩 **ماژولار از پایه** — هر موتور یک crate مستقل پشت یک trait مشترک
  `Backend` هست؛ اضافه‌کردن موتور جدید هیچ‌وقت به CLI یا منطق اصلی دست
  نمی‌زنه.
- 📱 **ساخته‌شده برای محیط‌های محدود** — علاوه بر لینوکس استاندارد، روی
  Termux/Kali NetHunter (proot/chroot) هم توسعه و تست شده.

### نصب

#### ساخت از سورس (فعلاً روش پیشنهادی)

نیاز به نصب [Rust](https://rustup.rs):

```bash
git clone https://github.com/msoleimani62/ramz.git
cd ramz
cargo build --release
```

باینری در مسیر `target/release/ramz` قرار می‌گیره. برای نصب اختیاری روی `PATH`:

```bash
cargo install --path cli
```

#### پیش‌نیاز حالت سازگاری

حالت `--engine compat7z` از باینری سیستمی `7z`/`7zz`/`7za` استفاده می‌کنه.
اگه قصد استفاده ازش رو داری، یکی از این‌ها رو نصب کن:

```bash
# دبیان / کالی / اوبونتو
sudo apt install 7zip

# آرچ لینوکس
sudo pacman -S p7zip
```

موتور پیش‌فرض `age` به هیچ چیز اضافه‌ای نیاز نداره.

#### باینری از پیش کامپایل‌شده

هنوز منتشر نشده — به بخش [نقشه راه](#نقشه-راه) نگاه کن.

### شروع سریع

```bash
# رمزگذاری یک پوشه با موتور پیش‌فرض (age)، درخواست رمز عبور
ramz /path/to/folder

# رمزگذاری یک فایل تکی
ramz /path/to/file.pdf

# حذف مبدا فقط پس از تایید موفقیت‌آمیز آرشیو
ramz --delete-source /path/to/folder

# استفاده از موتور سازگار با 7z
ramz --engine compat7z /path/to/folder

# غیرفعال کردن رمزگذاری، فقط فشرده‌سازی (باید صراحتاً درخواست بشه)
ramz --no-password /path/to/file.pdf

# انتخاب پوشه خروجی و سطح فشرده‌سازی مشخص
ramz --output /path/to/backups --compression 6 /path/to/folder
```

### مرجع دستورات

```
Usage: ramz [OPTIONS] <PATH>

Arguments:
  <PATH>  مسیر فایل یا پوشه‌ی مبدا

Options:
  -e, --engine <ENGINE>            موتور رمزنگاری [پیش‌فرض: age]
                                    [مقادیر ممکن: age, compat7z]
  -o, --output <OUTPUT>            پوشه‌ی خروجی (پیش‌فرض: همون پوشه‌ی مبدا)
  -d, --delete-source              حذف مبدا پس از تایید موفقیت‌آمیز
      --no-password                غیرفعال کردن رمزگذاری، فقط فشرده‌سازی
  -c, --compression <COMPRESSION>  سطح فشرده‌سازی، صفر تا نه [پیش‌فرض: 9]
  -f, --force                      بازنویسی آرشیو خروجی در صورت وجود
  -h, --help                       نمایش راهنما
  -V, --version                    نمایش نسخه
```

### توضیح موتورها

| موتور | فلگ | پسوند | نیاز به باینری خارجی | مناسب برای |
|---|---|---|---|---|
| age (پیش‌فرض) | `--engine age` | `.ramz-age` | خیر | خودت رمزگذاری/رمزگشایی می‌کنی، یا برای کسی می‌فرستی که `ramz`/`age` داره |
| سازگاری با 7z | `--engine compat7z` | `.7z` | بله (`7z`/`7zz`/`7za`) | فرستادن آرشیو برای کسی که فقط 7-Zip/WinRAR و مشابه داره |

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
├── core/             تایپ‌های مشترک، trait اصلی Backend، ابزار بسته‌بندی tar
├── backends-age/      موتور age (پیش‌فرض)
├── backends-7z/       موتور 7z (حالت سازگاری)
├── cli/               رابط خط فرمان (باینری: ramz)
```

هر موتور همون trait مشترک `Backend` رو پیاده می‌کنه. اضافه‌کردن یک موتور
جدید (مثلاً حالت hybrid کوانتوم-مقاوم در آینده) یعنی نوشتن یک crate جدید —
CLI و منطق اصلی هیچ‌وقت تغییر نمی‌کنن.

### تست

```bash
cargo test --workspace
```

الان ۱۹ تست واحد، تشخیص مسیر، بسته‌بندی tar، تایید رمز عبور، ایمنی مسیر
خروجی، و چرخه‌ی کامل pack/verify هر دو موتور (شامل تست رد رمز عبور غلط) رو
پوشش می‌ده.

### نقشه راه

فهرست کامل و به‌روز رو توی [TODO.md](TODO.md) ببین. مهم‌ترین‌ها:

- اشتقاق کلید با Argon2id
- گزینه‌ی رمزگذاری hybrid کوانتوم-مقاوم
- فشرده‌سازی هوشمند بر اساس نوع فایل (رد کردن فایل‌های از قبل فشرده)
- pipeline یکپارچگی مداوم (CI) و باینری‌های از پیش کامپایل‌شده کراس‌پلتفرم

### مشارکت

این فعلاً یک پروژه‌ی شخصی در حال توسعه‌ی فعاله. بعد از پایدارشدن ریپو، از
issue و pull request استقبال می‌شه.

### مجوز

## Features

- **Dual Backends**: `age` (X25519 + ChaCha20-Poly1305 + zstd) and `7z` (system binary)
- **Argon2id KDF**: Memory-hard password hashing (optional, replaces scrypt)
- **Post-Quantum ML-KEM**: Hybrid encryption combining X25519 with ML-KEM-768
- **File-type-aware Compression**: Skips already-compressed files (jpg, mp4, pdf, etc.)
- **Resume Support**: Continue interrupted large archives
- **Dry-run Mode**: Preview output size before running
- **Integrity Verification**: Mandatory verification before source deletion
- **Cross-platform**: Linux, macOS, Windows, Android (Termux)

## New in v0.2.0

- Argon2id key derivation option (`--argon2id`)
- Post-quantum ML-KEM hybrid encryption (`--mlkem`)
- File-type-aware compression (auto-detects already-compressed files)
- Resume support for interrupted archives
- Dry-run mode (`--dry-run`)
- Integration tests (round-trip for both backends)
- GitHub Actions CI/CD with cross-compiled releases


[MIT](LICENSE)
