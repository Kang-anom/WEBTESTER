# 🌐 WEBTESTER v1.5 - All-in-One Pentesting Framework

![License](https://img.shields.io/badge/license-Open%20Source-blue.svg)
![Bash](https://img.shields.io/badge/language-Bash-orange.svg)

**WEBTESTER** adalah framework pengujian keamanan web berbasis Bash yang dirancang untuk mengotomatisasi berbagai tahap penetrasi dengan kecepatan tinggi menggunakan sistem **Turbo Multi-threading**.

---

## 📸 Tampilan & Hasil / Interface & Results

Berikut adalah dokumentasi visual dari antarmuka dan proses pemindaian WEBTESTER:

### 1. Main Menu Interface
Tampilan menu utama yang terorganisir berdasarkan kategori serangan (Server-Side, Client-Side, Recon, & Advanced).
![Main Menu](Screenshot_2025-12-29_22_13_42.png)

### 2. Scanning Process (Turbo Mode)
Proses pemindaian menggunakan multi-threading yang memungkinkan pengecekan ratusan direktori atau ID dalam hitungan detik.
![Scanning Process](Screenshot_2025-12-29_22_14_55.png)

### 3. Professional Audit Report
Contoh hasil laporan audit dalam format tabel yang rapi, mencakup Path, HTTP Code, dan status temuan.
![Audit Report](Screenshot_2025-12-29_22_15_59.png)

---

## 🇮🇩 Bahasa Indonesia

### 📝 Catatan Pengembang
Saya tahu script ini masih belum sempurna dan masih perlu banyak perbaikan. Oleh karena itu, saya memutuskan untuk menjadikan project ini **Open Source** agar kalian bisa mengembangkannya lebih jauh lagi. Keamanan siber terus berkembang, dan kolaborasi adalah kunci untuk tetap selangkah di depan.

Jika Anda ingin berkolaborasi, memberikan saran, atau melaporkan bug, silakan hubungi saya melalui Gmail. Terima kasih banyak atas dukungan dan donasi yang telah diberikan, itu sangat berarti bagi kelangsungan pengembangan alat ini.

**Salam hormat, KANG ANOM**

---

## 📬 Kontak & Donasi / Contact & Donation

Jika Anda merasa alat ini bermanfaat, dukung pengembangan lebih lanjut melalui link di bawah ini:

* **Gmail**: [kalicianting@gmail.com](mailto:kalicianting@gmail.com)
* **Donasi**: [👉 **Klik di sini untuk Donasi**](https://sfl.gl/RCU0)

---

## 🚀 Fitur Utama / Main Features

* **Turbo Engine**: Multi-threading pada modul Directory Bruter & IDOR.
* **Complete Modules**: Mencakup LFI, SQLi, XSS, RCE, SSRF, hingga JWT & Smuggling.
* **Professional Reporting**: Auto-generate laporan audit per domain (Modul 99).

## 🛠️ Instalasi / Installation

Pastikan Anda berada di direktori project setelah melakukan clone:

```bash
# Clone repository
git clone [https://github.com/Kang-anom/WEBTESTER.git](https://github.com/Kang-anom/WEBTESTER.git)

# Masuk ke direktori
cd WEBTESTER

# Berikan izin eksekusi
chmod +x webtester.sh

# Jalankan framework
./webtester.sh
