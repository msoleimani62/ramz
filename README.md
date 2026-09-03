<div align="center">

# ramz

**رمز · Secure, cross-platform file archiving — compress and encrypt in one command**

[![CI](https://github.com/msoleimani62/ramz/workflows/CI/badge.svg)](https://github.com/msoleimani62/ramz/actions)
[![Release](https://img.shields.io/github/v/release/msoleimani62/ramz)](https://github.com/msoleimani62/ramz/releases)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Rust](https://img.shields.io/badge/rust-2021-orange.svg)](https://www.rust-lang.org)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Android%20(Termux)%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)](#installation)
[![Tests](https://img.shields.io/badge/tests-84%20passing-brightgreen.svg)](#testing)

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
- [Archive & identity formats](#archive--identity-formats)
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
hand-rolled) behind one simple interface: `pack`, `verify`, `extract`, and
`keygen`.

### Features

- 🔒 **Modern encryption by default** — [age](https://age-encryption.org)
  passphrase encryption (ChaCha20-Poly1305), a simple and audited format,
  no external binary required.
- 🧂 **Optional Argon2id KDF** (`--argon2id`) — memory-hard key derivation
  as a hardened alternative to age's built-in scrypt-based KDF, with
  fully configurable parameters.
- 🧬 **ML-KEM hybrid hardening** (`--mlkem`) — defense-in-depth on top of
  a password. See [Security design](#security-design) for exactly what
  this does and does not protect against.
- 🔑 **Recipient-based post-quantum encryption** (`ramz keygen`,
  `--recipient`, `--identity`) — a genuine post-quantum guarantee that
  doesn't depend on password strength at all. See
  [Security design](#security-design).
- 🔁 **Compatibility mode** — a `7z`-backed backend for when the
  recipient doesn't have `ramz` and needs a format their own tools can
  open.
- ✅ **Verify before delete** — the archive is independently re-read and
  checked before the original source is ever removed. No verify, no
  delete.
- 🧹 **Secure delete** (`--secure-delete`) — multi-pass overwrite of
  source content before removal, for both single files and entire
  directory trees.
- 📦 **File-type-aware compression** — already-compressed formats (jpg,
  mp4, pdf, zip, etc.) are stored instead of wasting time re-compressing
  them.
- 📊 **Live progress** — real byte-accurate progress bar with elapsed
  time and ETA.
- 🔍 **Dry-run mode** (`--dry-run`) — preview the estimated output size
  and settings before actually creating the archive.
- ⏸️ **Resume support** (`--resume`) — safely detect and re-run an
  interrupted pack, verified by checksum and completion state, not just
  file presence.
- 🧩 **Modular by design** — every backend is a self-contained crate
  behind one shared `Backend` trait; adding a new backend never touches
  the CLI or core logic.
- 📱 **Built for constrained environments** — developed and tested on
  Termux/Kali NetHunter (proot/chroot) in addition to standard Linux.

### Security design

Three encryption modes are available beyond plain age, and it's
important to understand exactly what each one buys you — the differences
matter a lot for post-quantum guarantees specifically.

**`--argon2id`** replaces age's internal scrypt-based key derivation with
Argon2id (64 MiB memory, 3 iterations, parallelism 4 by default, all
configurable). This makes password-guessing attacks meaningfully more
expensive for an attacker, independent of ML-KEM.

**`--mlkem`** adds a *hybrid hardening* layer, not a recipient-key
system. A fresh ML-KEM-768 keypair is generated per archive,
self-encapsulated, and the resulting shared secret is combined
(SHA-256) with the Argon2id-derived key to form the final encryption
key. The ML-KEM decapsulation key itself is stored in the archive,
encrypted under the same Argon2id key. **This means `--mlkem` provides
no extra protection against someone guessing your password** — if the
password is compromised, the ML-KEM secret is trivially recoverable
right alongside it. It only hardens against a hypothetical structural
flaw in key derivation (key separation).

**`--recipient` (with `ramz keygen`)** is the real post-quantum
guarantee, and works completely differently. A permanent ML-KEM-768
identity is generated once (`ramz keygen`), producing a public
`identity.pub` (share freely) and a private `identity` file (keep
secret, `chmod 600`, optionally password-protected). When packing with
`--recipient <identity.pub>`, the shared secret is encapsulated
directly to that public key — **the decapsulation key never enters the
archive at all**. To decrypt, the recipient needs the physical
`identity` file, not a guessable password. This is what actually
defeats the "Harvest Now, Decrypt Later" threat: an attacker who
captures the archive today and gains a quantum computer in ten years
still cannot decrypt it without also having stolen the identity file.

| Threat | `--mlkem` (hybrid hardening) | `--recipient` (true post-quantum) |
|---|---|---|
| Attacker guesses the password | Archive fully opens — ML-KEM adds nothing | No password exists to guess |
| Attacker stores the archive, waits for a quantum computer | Still opens once the password is broken, since the decapsulation key travels with the archive | Still safe — decapsulation key was never in the archive, only in a separately-held identity file |

**`--secure-delete`** overwrites source content (3 passes: zeros, ones,
random, each repeated) before removal, recursively for directories.
This is best-effort: on SSDs/flash storage with wear-leveling, the
drive controller may not actually rewrite the same physical block, so
treat it as raising the bar against casual recovery, not a physical
guarantee.

`--argon2id`, `--mlkem`, and `--recipient` currently apply to the `age`
backend only. The `7z` backend does not support them.

#### Known limitations

- **`7z` backend: password briefly visible to other local users.** The
  `7z` backend shells out to the system `7z`/`7zz`/`7za` binary and
  passes the password as a command-line argument (`-p<password>`).
  While the process is running, other users on the same multi-user
  machine can see it via `ps aux` or `/proc/<pid>/cmdline`. This is a
  limitation of the external `7z` binary itself — it has no way to
  accept a password from stdin or an environment variable — so it
  cannot be fixed by ramz without dropping 7z compatibility entirely.
  If this matters for your threat model, use the `age` backend
  instead, where the password never appears as a process argument.
- **No streaming for very large files.** The current pipeline buffers
  the whole compressed payload in memory/a temp file rather than
  processing it as a true stream. See the roadmap.
- **The `RMZ1`/`RIM1` binary formats have not had an independent
  security review.** They are custom formats, not an established
  standard like plain `age`. See the roadmap.

### Installation

#### Build from source

Requires the [Rust toolchain](https://rustup.rs):

```bash
git clone https://github.com/msoleimani62/ramz.git
cd ramz
cargo install --path cli
```

Or build without installing:

```bash
cargo build --release --manifest-path cli/Cargo.toml
# binary at target/release/ramz
```

#### Prebuilt binaries

Download the archive for your platform from the
[Releases page](https://github.com/msoleimani62/ramz/releases):
Linux (glibc & musl), Android/Termux (aarch64), macOS (x86_64 & Apple
Silicon), and Windows.

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

### Quick start

```bash
# Pack a file or folder with the default age backend, prompts for a password
ramz pack /path/to/folder --password "your-password"

# Pack with Argon2id key derivation
ramz pack /path/to/file.pdf --password "your-password" --argon2id

# Pack with ML-KEM hybrid hardening (see Security design for what this does)
ramz pack /path/to/file.pdf --password "your-password" --mlkem

# Generate a permanent recipient identity (once)
ramz keygen --output ~/.config/ramz/identity

# Pack for that recipient — no password needed at all
ramz pack /path/to/folder --recipient ~/.config/ramz/identity.pub

# Extract a recipient archive using the identity's secret key
ramz extract /path/to/folder.age.tar.zst --identity ~/.config/ramz/identity --output /path/to/destination

# Securely wipe the source after a verified pack
ramz pack /path/to/folder --password "your-password" --delete-source --secure-delete

# Preview the archive without creating it
ramz pack /path/to/folder --password "your-password" --dry-run

# Use the 7z-compatible backend instead
ramz pack /path/to/folder --password "your-password" --backend seven-z

# Verify an existing archive
ramz verify /path/to/folder.age.tar.zst --password "your-password"
```

### Command reference

```
Usage: ramz <COMMAND>

Commands:
  pack     Pack files into an encrypted archive
  verify   Verify archive integrity
  extract  Extract archive contents
  keygen   Generate a recipient identity keypair
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
| `--secure-delete` | Overwrite source before deletion (used with `-d`) — see [Security design](#security-design) |
| `-f, --force` | Force overwrite of an existing archive |
| `-b, --backend <age\|seven-z>` | Backend to use [default: `age`] |
| `--argon2id` | Use Argon2id instead of age's default KDF |
| `--mlkem` | Enable ML-KEM hybrid hardening — see [Security design](#security-design) |
| `--recipient <PUB_KEY_PATH>` | Encrypt for a recipient identity — no password needed, see [Security design](#security-design) |
| `--argon2-memory-kib <N>` | Argon2 memory in KiB [default: 65536] |
| `--argon2-iterations <N>` | Argon2 iterations [default: 3] |
| `--argon2-parallelism <N>` | Argon2 parallelism [default: 4] |
| `--dry-run` | Preview output without creating the archive |
| `--resume` | Resume an interrupted archive (checksum + completion verified) |

**`ramz verify <ARCHIVE>`**

| Flag | Description |
|---|---|
| `-p, --password <PASSWORD>` | Password for decryption |
| `--identity <PATH>` | Identity secret-key file, for recipient archives |

**`ramz extract <ARCHIVE>`**

| Flag | Description |
|---|---|
| `-o, --output <DIR>` | Output directory |
| `-p, --password <PASSWORD>` | Password for decryption |
| `--identity <PATH>` | Identity secret-key file, for recipient archives |

**`ramz keygen`**

| Flag | Description |
|---|---|
| `-o, --output <PATH>` | Where to write the identity (produces `<PATH>` and `<PATH>.pub`) |
| `-p, --password <PASSWORD>` | Optionally protect the secret key with a password |

### Backends explained

| Backend | Flag | Extension | External binary | Best for |
|---|---|---|---|---|
| age (default) | `--backend age` | `.age.tar.zst` | No | You control both ends, or the recipient also has `ramz`/`age` |
| 7z compatibility | `--backend seven-z` | `.7z` | Yes (`7z`/`7zz`/`7za`) | Sending an archive to someone with only 7-Zip/WinRAR/etc. |

### Archive & identity formats

Full byte-level specifications, for anyone auditing the format or
building an interoperable implementation:

- [`docs/ARCHIVE_FORMAT.md`](docs/ARCHIVE_FORMAT.md) — the `RMZ1`
  container used by `--argon2id`, `--mlkem`, and `--recipient`.
- [`docs/IDENTITY_FORMAT.md`](docs/IDENTITY_FORMAT.md) — the `RIM1`
  identity keypair format used by `ramz keygen`.

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
├── core/               shared types, Backend trait, tar/dry-run/resume/secure-delete helpers
├── backends-age/        age backend — Argon2id, ML-KEM hybrid, recipient identities, zstd compression
├── backends-7z/         7z backend (compatibility mode)
├── cli/                 command-line interface (package: ramz-cli, binary: ramz)
├── integration-tests/   end-to-end tests exercising the public API of every backend together
```

Every backend implements the same `Backend` trait. Adding a new one means
writing a new crate — the CLI and core logic never change.

### Testing

```bash
cargo test --workspace --all-features
```

84 tests currently cover path detection, tar packing/unpacking, dry-run
estimation, resume-state checksums and false-completion prevention,
secure-delete overwrite behavior (files and recursive directories),
ML-KEM roundtrips, Argon2id key derivation with configurable
parameters, recipient identity generation/save/load (password-protected
and not), and full pack → verify → extract round-trips for every age
backend mode (default, `--argon2id`, `--mlkem`, `--recipient`) as well
as the 7z backend, including wrong-password/wrong-identity rejection
and backend/flag incompatibility checks.

### Roadmap

See [TODO.md](TODO.md) and [ROADMAP.md](ROADMAP.md) for the full,
up-to-date, detailed list. Highlights:

- Independent security review of the `RMZ1`/`RIM1` formats
- Multi-recipient support
- Streaming/chunked encryption for very large files
- Publishing to crates.io / AUR

### Contributing

This is currently a personal project under active development. Issues
and pull requests are welcome — see the
[issue](.github/ISSUE_TEMPLATE) and
[pull request](.github/pull_request_template.md) templates.

### License

Dual-licensed under either of:

- [MIT License](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option, following common Rust ecosystem practice.

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
- [فرمت‌های آرشیو و identity](#فرمتهای-آرشیو-و-identity)
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
رابط ساده با چهار دستور اصلی قرار می‌ده: `pack`, `verify`, `extract`,
`keygen`.

### ویژگی‌ها

- 🔒 **رمزگذاری مدرن به‌صورت پیش‌فرض** — رمزگذاری passphrase-based
  [age](https://age-encryption.org) (ChaCha20-Poly1305)، یک فرمت ساده و
  audited، بدون نیاز به باینری خارجی.
- 🧂 **KDF اختیاری Argon2id** (`--argon2id`) — اشتقاق کلید memory-hard
  به‌عنوان جایگزین سخت‌شده‌ی KDF داخلی scrypt-based خودِ age، با
  پارامترهای کاملاً قابل‌تنظیم.
- 🧬 **سخت‌سازی hybrid با ML-KEM** (`--mlkem`) — دفاع اضافه روی یه
  پسورد. برای این‌که دقیقاً بدونی چی رو محافظت می‌کنه و چی رو نه، بخش
  [طراحی امنیتی](#طراحی-امنیتی) رو ببین.
- 🔑 **رمزگذاری پسا-کوانتومی recipient-based** (`ramz keygen`،
  `--recipient`، `--identity`) — یه تضمین واقعی پسا-کوانتومی که اصلاً
  به قدرت پسورد وابسته نیست. به [طراحی امنیتی](#طراحی-امنیتی) نگاه کن.
- 🔁 **حالت سازگاری** — یک بک‌اند مبتنی بر `7z` برای وقتی که طرف مقابل
  `ramz` نداره و به فرمتی نیاز داره که ابزار خودش بازش کنه.
- ✅ **تایید قبل از حذف** — آرشیو به‌طور مستقل دوباره خونده و بررسی
  می‌شه قبل از این‌که مبدا اصلی حذف بشه. بدون تایید، حذفی هم در کار نیست.
- 🧹 **حذف امن** (`--secure-delete`) — بازنویسی چندمرحله‌ای محتوای مبدا
  قبل از حذف، هم برای فایل تکی هم به‌صورت بازگشتی برای کل پوشه.
- 📦 **فشرده‌سازی هوشمند بر اساس نوع فایل** — فرمت‌های از قبل فشرده
  (jpg، mp4، pdf، zip و مشابه) دوباره فشرده نمی‌شن، فقط ذخیره می‌شن.
- 📊 **پیشرفت زنده** — نوار پیشرفت دقیق بر اساس بایت واقعی، با زمان
  سپری‌شده و زمان تخمینی باقی‌مانده.
- 🔍 **حالت dry-run** (`--dry-run`) — پیش‌نمایش سایز تخمینی و تنظیمات
  خروجی قبل از ساخت واقعی آرشیو.
- ⏸️ **پشتیبانی از resume** (`--resume`) — تشخیص و ادامه‌ی امن یک pack
  قطع‌شده، با تأیید چک‌سام و وضعیت تکمیل، نه فقط وجود فایل.
- 🧩 **ماژولار از پایه** — هر بک‌اند یک crate مستقل پشت یک trait مشترک
  `Backend` هست؛ اضافه‌کردن بک‌اند جدید هیچ‌وقت به CLI یا منطق اصلی دست
  نمی‌زنه.
- 📱 **ساخته‌شده برای محیط‌های محدود** — علاوه بر لینوکس استاندارد، روی
  Termux/Kali NetHunter (proot/chroot) هم توسعه و تست شده.

### طراحی امنیتی

سه حالت رمزگذاری اضافه بر age ساده در دسترسه، و مهمه دقیقاً بدونی
هرکدوم چی می‌ده — این تفاوت‌ها مخصوصاً برای تضمین‌های پسا-کوانتومی خیلی
مهمن.

**`--argon2id`** به‌جای KDF داخلی scrypt-based خودِ age، از Argon2id
(۶۴ مگابایت حافظه، ۳ iteration، parallelism ۴ به‌صورت پیش‌فرض، همه
قابل‌تنظیم) استفاده می‌کنه. این کار حمله‌ی حدس‌زدن پسورد رو برای مهاجم
گرون‌تر می‌کنه، مستقل از ML-KEM.

**`--mlkem`** یه لایه‌ی *سخت‌سازی hybrid* اضافه می‌کنه، نه یه سیستم
recipient-key. به ازای هر آرشیو، یه جفت‌کلید تازه‌ی ML-KEM-768 تولید
می‌شه، به خودش self-encapsulate می‌شه، و secret مشترک حاصل با کلید
مشتق‌شده از Argon2id ترکیب می‌شه (SHA-256). خودِ decapsulation key هم
داخل آرشیو، رمزشده با همون کلید Argon2id، ذخیره می‌شه. **یعنی
`--mlkem` در برابر حدس‌زدن پسورد هیچ محافظت اضافه‌ای نمی‌ده** — اگه
پسورد لو بره، secret مربوط به ML-KEM هم دقیقاً کنارش به‌راحتی قابل
بازیابیه. این فقط در برابر یه ضعف ساختاری فرضی توی اشتقاق کلید
(جداسازی کلید) سخت‌سازی می‌کنه.

**`--recipient` (همراه با `ramz keygen`)** تضمین واقعی پسا-کوانتومیه،
و کاملاً متفاوت کار می‌کنه. یه identity دائمی ML-KEM-768 یه‌بار تولید
می‌شه (`ramz keygen`)، که یه `identity.pub` عمومی (آزادانه قابل
اشتراک) و یه فایل `identity` خصوصی (محرمانه، `chmod 600`، اختیاراً
محافظت‌شده با پسورد) می‌سازه. موقع pack با `--recipient
<identity.pub>`، secret مشترک مستقیم به همون کلید عمومی encapsulate
می‌شه — **decapsulation key اصلاً وارد آرشیو نمی‌شه.** برای رمزگشایی،
گیرنده به خودِ فایل `identity` فیزیکی نیاز داره، نه یه پسورد قابل‌حدس.
این دقیقاً همون چیزیه که سناریوی «الان جمع‌آوری کن، بعداً با کوانتوم
بشکن» رو خنثی می‌کنه: مهاجمی که امروز آرشیو رو می‌گیره و ده سال دیگه
کامپیوتر کوانتومی هم داشته باشه، بدون دزدیدن فایل identity هنوز نمی‌تونه
بازش کنه.

| تهدید | `--mlkem` (سخت‌سازی hybrid) | `--recipient` (پسا-کوانتومی واقعی) |
|---|---|---|
| مهاجم پسورد رو حدس می‌زنه | آرشیو کامل باز می‌شه — ML-KEM هیچی اضافه نمی‌کنه | اصلاً پسوردی برای حدس زدن وجود نداره |
| مهاجم آرشیو رو ذخیره می‌کنه، منتظر کامپیوتر کوانتومی می‌مونه | با شکستن پسورد بازم باز می‌شه، چون decapsulation key همراه آرشیوه | همچنان امنه — decapsulation key هیچ‌وقت توی آرشیو نبوده، فقط توی یه فایل identity جدا |

**`--secure-delete`** قبل از حذف، محتوای مبدا رو (۳ pass: صفر، یک،
تصادفی، هرکدوم تکرار) overwrite می‌کنه، به‌صورت بازگشتی برای پوشه‌ها
هم. این تلاش‌محوره: روی SSD/فلش با wear-leveling، کنترلر درایو ممکنه
واقعاً همون بلاک فیزیکی رو ننویسه، پس این رو به‌عنوان بالابردن سطح
دشواری بازیابی معمولی در نظر بگیر، نه یه تضمین فیزیکی.

`--argon2id`، `--mlkem`، و `--recipient` فعلاً فقط روی بک‌اند `age`
کار می‌کنن. بک‌اند `7z` ازشون پشتیبانی نمی‌کنه.

#### محدودیت‌های شناخته‌شده

- **بک‌اند `7z`: پسورد به‌طور موقت در معرض دید بقیه‌ی کاربران محلیه.**
  بک‌اند `7z` به باینری سیستمی `7z`/`7zz`/`7za` شل می‌کنه و پسورد رو
  به‌عنوان یه آرگومان خط‌فرمان (`-p<password>`) پاس می‌ده. تا وقتی
  پروسه در حال اجراست، بقیه‌ی کاربرها روی همون سیستم چندکاربره می‌تونن
  با `ps aux` یا `/proc/<pid>/cmdline` ببیننش. این محدودیت خودِ باینری
  `7z`‌ه — هیچ راهی برای گرفتن پسورد از stdin یا متغیر محیطی نداره —
  پس ramz نمی‌تونه بدون کنار گذاشتن کامل سازگاری با 7z این رو رفع کنه.
  اگه این برای مدل تهدید شما مهمه، به‌جاش از بک‌اند `age` استفاده کن؛
  اونجا پسورد هیچ‌وقت به‌صورت آرگومان پروسه ظاهر نمی‌شه.
- **بدون streaming واقعی برای فایل‌های خیلی بزرگ.** pipeline فعلی کل
  محتوای فشرده‌شده رو توی RAM/یه فایل موقت بافر می‌کنه، نه پردازش
  واقعی به‌صورت جریانی. به نقشه‌راه نگاه کن.
- **فرمت‌های باینری `RMZ1`/`RIM1` هنوز بررسی امنیتی مستقل نشدن.** این‌ها
  فرمت‌های خودساخته‌ان، نه یه استاندارد جاافتاده مثل `age` خالص. به
  نقشه‌راه نگاه کن.

### نصب

#### ساخت از سورس

نیاز به نصب [Rust](https://rustup.rs):

```bash
git clone https://github.com/msoleimani62/ramz.git
cd ramz
cargo install --path cli
```

یا بدون نصب، فقط build:

```bash
cargo build --release --manifest-path cli/Cargo.toml
# باینری در target/release/ramz
```

#### باینری از پیش کامپایل‌شده

آرشیو مناسب پلتفرمت رو از [صفحه‌ی Releases](https://github.com/msoleimani62/ramz/releases)
دانلود کن: لینوکس (glibc و musl)، اندروید/Termux (aarch64)، مک (x86_64
و Apple Silicon)، و ویندوز.

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

### شروع سریع

```bash
# رمزگذاری یک پوشه با بک‌اند پیش‌فرض age
ramz pack /path/to/folder --password "your-password"

# رمزگذاری با اشتقاق کلید Argon2id
ramz pack /path/to/file.pdf --password "your-password" --argon2id

# رمزگذاری با سخت‌سازی hybrid از طریق ML-KEM
ramz pack /path/to/file.pdf --password "your-password" --mlkem

# ساخت یه identity دائمی برای recipient (یک‌بار)
ramz keygen --output ~/.config/ramz/identity

# رمزگذاری برای اون گیرنده — اصلاً پسورد لازم نیست
ramz pack /path/to/folder --recipient ~/.config/ramz/identity.pub

# استخراج آرشیو recipient با کلید خصوصی identity
ramz extract /path/to/folder.age.tar.zst --identity ~/.config/ramz/identity --output /path/to/destination

# حذف امن مبدا بعد از یک pack تأییدشده
ramz pack /path/to/folder --password "your-password" --delete-source --secure-delete

# پیش‌نمایش آرشیو بدون ساخت واقعیش
ramz pack /path/to/folder --password "your-password" --dry-run

# استفاده از بک‌اند سازگار با 7z
ramz pack /path/to/folder --password "your-password" --backend seven-z

# تایید یک آرشیو موجود
ramz verify /path/to/folder.age.tar.zst --password "your-password"
```

### مرجع دستورات

```
Usage: ramz <COMMAND>

Commands:
  pack     بسته‌بندی فایل‌ها در یک آرشیو رمزشده
  verify   تایید یکپارچگی آرشیو
  extract  استخراج محتوای آرشیو
  keygen   تولید یک جفت‌کلید identity برای گیرنده
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
| `--secure-delete` | Overwrite مبدا قبل از حذف (همراه با `-d`) — به [طراحی امنیتی](#طراحی-امنیتی) نگاه کن |
| `-f, --force` | بازنویسی اجباری آرشیو موجود |
| `-b, --backend <age\|seven-z>` | بک‌اند مورد استفاده [پیش‌فرض: `age`] |
| `--argon2id` | استفاده از Argon2id به‌جای KDF پیش‌فرض age |
| `--mlkem` | فعال‌سازی سخت‌سازی hybrid با ML-KEM — به [طراحی امنیتی](#طراحی-امنیتی) نگاه کن |
| `--recipient <PUB_KEY_PATH>` | رمزگذاری برای یک identity گیرنده — بدون نیاز به پسورد، به [طراحی امنیتی](#طراحی-امنیتی) نگاه کن |
| `--argon2-memory-kib <N>` | حافظه‌ی Argon2 به کیلوبایت [پیش‌فرض: ۶۵۵۳۶] |
| `--argon2-iterations <N>` | تعداد iteration های Argon2 [پیش‌فرض: ۳] |
| `--argon2-parallelism <N>` | میزان parallelism آرگون۲ [پیش‌فرض: ۴] |
| `--dry-run` | پیش‌نمایش خروجی بدون ساخت واقعی آرشیو |
| `--resume` | ازسرگیری آرشیو قطع‌شده (با تأیید چک‌سام و وضعیت تکمیل) |

**`ramz verify <ARCHIVE>`**

| فلگ | توضیح |
|---|---|
| `-p, --password <PASSWORD>` | پسورد رمزگشایی |
| `--identity <PATH>` | فایل کلید خصوصی identity، برای آرشیوهای recipient |

**`ramz extract <ARCHIVE>`**

| فلگ | توضیح |
|---|---|
| `-o, --output <DIR>` | پوشه‌ی خروجی |
| `-p, --password <PASSWORD>` | پسورد رمزگشایی |
| `--identity <PATH>` | فایل کلید خصوصی identity، برای آرشیوهای recipient |

**`ramz keygen`**

| فلگ | توضیح |
|---|---|
| `-o, --output <PATH>` | مسیر ذخیره‌ی identity (فایل `<PATH>` و `<PATH>.pub` ساخته می‌شن) |
| `-p, --password <PASSWORD>` | محافظت اختیاری کلید خصوصی با پسورد |

### توضیح بک‌اندها

| بک‌اند | فلگ | پسوند | نیاز به باینری خارجی | مناسب برای |
|---|---|---|---|---|
| age (پیش‌فرض) | `--backend age` | `.age.tar.zst` | خیر | خودت هر دو طرف رو کنترل می‌کنی، یا طرف مقابل هم `ramz`/`age` داره |
| سازگاری با 7z | `--backend seven-z` | `.7z` | بله (`7z`/`7zz`/`7za`) | فرستادن آرشیو برای کسی که فقط 7-Zip/WinRAR و مشابه داره |

### فرمت‌های آرشیو و identity

مستندات کامل و بایت‌به‌بایت، برای هرکسی که می‌خواد فرمت رو audit کنه یا
یه پیاده‌سازی سازگار بسازه:

- [`docs/ARCHIVE_FORMAT.md`](docs/ARCHIVE_FORMAT.md) — کانتینر `RMZ1`
  که توسط `--argon2id`، `--mlkem`، و `--recipient` استفاده می‌شه.
- [`docs/IDENTITY_FORMAT.md`](docs/IDENTITY_FORMAT.md) — فرمت جفت‌کلید
  identity به اسم `RIM1` که `ramz keygen` می‌سازه.

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
├── core/                تایپ‌های مشترک، trait اصلی Backend، ابزارهای tar/dry-run/resume/secure-delete
├── backends-age/         بک‌اند age — Argon2id، سخت‌سازی hybrid با ML-KEM، identity گیرنده، فشرده‌سازی zstd
├── backends-7z/          بک‌اند 7z (حالت سازگاری)
├── cli/                  رابط خط فرمان (package: ramz-cli، باینری: ramz)
├── integration-tests/    تست‌های end-to-end که API عمومی همه‌ی بک‌اندها رو با هم اجرا می‌کنن
```

هر بک‌اند همون trait مشترک `Backend` رو پیاده می‌کنه. اضافه‌کردن یک
بک‌اند جدید یعنی نوشتن یک crate جدید — CLI و منطق اصلی هیچ‌وقت تغییر
نمی‌کنن.

### تست

```bash
cargo test --workspace --all-features
```

الان ۸۴ تست، تشخیص مسیر، بسته‌بندی/باز‌کردن tar، تخمین dry-run، چک‌سام
حالت resume و جلوگیری از اعلام کاذب تکمیل، رفتار overwrite حذف امن (هم
فایل تکی هم پوشه‌ی بازگشتی)، چرخه‌ی ML-KEM، اشتقاق کلید Argon2id با
پارامترهای قابل‌تنظیم، تولید/ذخیره/بارگذاری identity (با و بدون
پسورد)، و چرخه‌ی کامل pack → verify → extract برای هر چهار حالت بک‌اند
age (پیش‌فرض، `--argon2id`، `--mlkem`، `--recipient`) به‌علاوه‌ی بک‌اند
7z رو پوشش می‌ده — شامل
تست رد پسورد/identity غلط و چک ناسازگاری بک‌اند/فلگ.

### نقشه راه

فهرست کامل و به‌روز رو توی [TODO.md](TODO.md) و [ROADMAP.md](ROADMAP.md)
ببین. مهم‌ترین‌ها:

- بررسی امنیتی مستقل فرمت‌های `RMZ1`/`RIM1`
- پشتیبانی از چند گیرنده هم‌زمان
- رمزنگاری streaming/chunked برای فایل‌های خیلی بزرگ
- انتشار روی crates.io / AUR

### مشارکت

این فعلاً یک پروژه‌ی شخصی در حال توسعه‌ی فعاله. از issue و pull request
استقبال می‌شه — به قالب‌های
[issue](.github/ISSUE_TEMPLATE) و
[pull request](.github/pull_request_template.md) نگاه کن.

### مجوز

این پروژه دو-مجوزی هست، هرکدوم رو که ترجیح می‌دی:

- [مجوز MIT](LICENSE-MIT)
- [مجوز Apache، نسخه‌ی ۲.۰](LICENSE-APACHE)

طبق رسم رایج اکوسیستم Rust.
