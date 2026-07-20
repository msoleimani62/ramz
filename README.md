# ramz

**Status: early scaffold (MVP architecture) — not yet built/tested with network access.**

A cross-platform, secure archiving CLI written in Rust. Wraps well-audited
encryption engines (age by default, 7z for compatibility) behind one
consistent interface, with real-time progress reporting and mandatory
integrity verification before the source is ever deleted.

## Architecture

```
ramz/
├── core/            shared types, Backend trait, tar packing helpers
├── backends-age/     age engine (default) — modern, audited, no external binary
├── backends-7z/      7z engine (compatibility mode) — shells out to system 7z/7zz
├── cli/              command-line interface (binary name: ramz)
```

Adding a new engine means implementing the `Backend` trait in a new crate —
the CLI and core logic never need to change.

## Build

Requires the Rust toolchain (`rustup`) and network access to fetch crates
from crates.io on first build.

```bash
cargo build --release
```

The binary will be at `target/release/ramz`.

### Cross-compiling for Termux / Android

```bash
rustup target add aarch64-linux-android
cargo install cross
cross build --release --target aarch64-linux-android
```

## Usage

```bash
# Encrypt with the default engine (age), prompts for password
ramz /sdcard/Download/MvTest

# Compatibility mode using 7z (requires p7zip/7zip installed)
ramz --engine compat7z /sdcard/Download/MvTest

# Delete the source after successful verification
ramz --delete-source /sdcard/Download/MvTest

# Skip encryption (compression only) — must be explicit
ramz --no-password /sdcard/Download/somefile.pdf
```

## Design principles

- No hand-rolled cryptography — every engine wraps an existing, audited
  implementation (the `age` crate, or the system `7z` binary).
- The source is only deleted after the archive has been independently
  verified (re-read and checked), never right after writing.
- Password prompts require confirmation and reject empty input by default.

## Known gaps (not yet done)

- `cargo build` has not been verified in this environment (no network access
  in the sandbox that generated this scaffold).
- No automated tests yet.
- No release pipeline / prebuilt binaries yet.

---

# رمز (ramz)

**وضعیت: اسکلت اولیه پروژه (معماری MVP) — هنوز با دسترسی شبکه build و تست نشده.**

یک ابزار خط‌فرمان آرشیو‌سازی امن و کراس‌پلتفرم به زبان Rust. موتورهای
رمزنگاری audited و شناخته‌شده (پیش‌فرض: age، حالت سازگاری: 7z) رو پشت یک
رابط یکپارچه قرار می‌ده، با نمایش پیشرفت زنده و تایید اجباری یکپارچگی
آرشیو قبل از هرگونه حذف فایل مبدا.

## معماری

```
ramz/
├── core/             تایپ‌های مشترک، trait اصلی Backend، ابزار بسته‌بندی tar
├── backends-age/      موتور age (پیش‌فرض) — مدرن، audited، بدون نیاز به باینری خارجی
├── backends-7z/       موتور 7z (حالت سازگاری) — از باینری سیستمی 7z/7zz استفاده می‌کنه
├── cli/               رابط خط فرمان (نام باینری: ramz)
```

اضافه کردن یک موتور جدید یعنی فقط پیاده‌سازی trait به نام `Backend` در یک
crate جدید — نیازی به تغییر CLI یا منطق اصلی نیست.

## ساخت (Build)

نیاز به نصب Rust (از طریق `rustup`) و دسترسی به اینترنت برای دانلود
وابستگی‌ها از crates.io در اولین build.

```bash
cargo build --release
```

باینری نهایی در مسیر `target/release/ramz` قرار می‌گیره.

### کامپایل متقاطع برای Termux / اندروید

```bash
rustup target add aarch64-linux-android
cargo install cross
cross build --release --target aarch64-linux-android
```

## نحوه استفاده

```bash
# رمزگذاری با موتور پیش‌فرض (age)، درخواست رمز عبور
ramz /sdcard/Download/MvTest

# حالت سازگاری با 7z (نیاز به نصب p7zip/7zip)
ramz --engine compat7z /sdcard/Download/MvTest

# حذف مبدا پس از تایید موفقیت‌آمیز آرشیو
ramz --delete-source /sdcard/Download/MvTest

# غیرفعال کردن رمزگذاری (فقط فشرده‌سازی) — باید صراحتاً درخواست بشه
ramz --no-password /sdcard/Download/somefile.pdf
```

## اصول طراحی

- هیچ رمزنگاری دست‌نویسی وجود نداره — هر موتور دور یک پیاده‌سازی موجود و
  audited (crate رسمی `age`، یا باینری سیستمی `7z`) پوشیده شده.
- مبدا فقط پس از تایید مستقل آرشیو (بازخوانی و بررسی مجدد) حذف می‌شه، نه
  بلافاصله بعد از نوشتن.
- درخواست رمز عبور به‌صورت پیش‌فرض نیاز به تکرار و تایید داره و ورودی خالی
  رو رد می‌کنه.

## نواقص شناخته‌شده (هنوز انجام نشده)

- `cargo build` در این محیط به‌خاطر نبود دسترسی شبکه تایید نشده.
- هنوز تست خودکار نداره.
- هنوز pipeline انتشار / باینری از پیش‌کامپایل‌شده نداره.
