# Upload-Labs Writeup

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Upload--Labs-orange" alt="Platform">
  <img src="https://img.shields.io/badge/Challenges-20-blue" alt="Challenges">
  <img src="https://img.shields.io/badge/Language-Bilingual-green" alt="Language">
</p>

<p align="center">
  <a href="#english">🇬🇧 English</a> | <a href="#中文">🇨🇳 中文</a>
</p>

---

<a name="english"></a>
## 🇬🇧 English

### About

A comprehensive walkthrough of [Upload-Labs](https://github.com/c0ny1/upload-labs), a PHP-based file upload vulnerability training platform. Each challenge presents different upload restrictions that need to be bypassed.

### Challenge Index

| # | Challenge | Vulnerability Type | Difficulty | Status |
|---|-----------|-------------------|------------|--------|
| 01 | [Pass-01](Pass-01/) | Client-side JS Validation | ⭐ | ✅ |
| 02 | [Pass-02](Pass-02/) | MIME Type Validation | ⭐ | 🔲 |
| 03 | [Pass-03](Pass-03/) | Blacklist - Alternate Extensions | ⭐⭐ | 🔲 |
| 04 | [Pass-04](Pass-04/) | Blacklist - .htaccess | ⭐⭐ | 🔲 |
| 05 | [Pass-05](Pass-05/) | Blacklist - Case Sensitivity | ⭐⭐ | 🔲 |
| 06 | [Pass-06](Pass-06/) | Blacklist - Trailing Space | ⭐⭐ | 🔲 |
| 07 | [Pass-07](Pass-07/) | Blacklist - Trailing Dot | ⭐⭐ | 🔲 |
| 08 | [Pass-08](Pass-08/) | Blacklist - ::$DATA | ⭐⭐ | 🔲 |
| 09 | [Pass-09](Pass-09/) | Blacklist - Combined Bypass | ⭐⭐⭐ | 🔲 |
| 10 | [Pass-10](Pass-10/) | Blacklist - Double Extension | ⭐⭐ | 🔲 |
| 11 | [Pass-11](Pass-11/) | Whitelist - %00 Truncation (GET) | ⭐⭐⭐ | 🔲 |
| 12 | [Pass-12](Pass-12/) | Whitelist - %00 Truncation (POST) | ⭐⭐⭐ | 🔲 |
| 13 | [Pass-13](Pass-13/) | File Header - Image Shell | ⭐⭐⭐ | 🔲 |
| 14 | [Pass-14](Pass-14/) | File Header - getimagesize() | ⭐⭐⭐ | 🔲 |
| 15 | [Pass-15](Pass-15/) | File Header - exif_imagetype() | ⭐⭐⭐ | 🔲 |
| 16 | [Pass-16](Pass-16/) | Image Recompression | ⭐⭐⭐⭐ | 🔲 |
| 17 | [Pass-17](Pass-17/) | Race Condition | ⭐⭐⭐⭐ | 🔲 |
| 18 | [Pass-18](Pass-18/) | Race Condition + Rename | ⭐⭐⭐⭐ | 🔲 |
| 19 | [Pass-19](Pass-19/) | Path Traversal | ⭐⭐⭐ | 🔲 |
| 20 | [Pass-20](Pass-20/) | Combined Vulnerabilities | ⭐⭐⭐⭐⭐ | 🔲 |

### Environment Setup

```bash
# Using Docker (Recommended)
docker pull c0ny1/upload-labs
docker run -d -p 80:80 c0ny1/upload-labs

# Or use PHPStudy/XAMPP with source code
git clone https://github.com/c0ny1/upload-labs.git
```

### Tools Used

- **Burp Suite** - HTTP proxy and request manipulation
- **Browser DevTools** - JavaScript debugging and network analysis
- **010 Editor / HxD** - Hex editing for file header manipulation

### Disclaimer

This repository is for **educational purposes only**. Only test on systems you own or have explicit permission to test.

---

<a name="中文"></a>
## 🇨🇳 中文

### 关于

这是 [Upload-Labs](https://github.com/c0ny1/upload-labs) 的完整通关笔记，Upload-Labs 是一个基于 PHP 的文件上传漏洞训练平台。每个关卡都有不同的上传限制需要绕过。

### 关卡索引

| # | 关卡 | 漏洞类型 | 难度 | 状态 |
|---|------|---------|------|------|
| 01 | [Pass-01](Pass-01/) | 前端 JS 校验 | ⭐ | ✅ |
| 02 | [Pass-02](Pass-02/) | MIME 类型校验 | ⭐ | 🔲 |
| 03 | [Pass-03](Pass-03/) | 黑名单 - 替代扩展名 | ⭐⭐ | 🔲 |
| 04 | [Pass-04](Pass-04/) | 黑名单 - .htaccess | ⭐⭐ | 🔲 |
| 05 | [Pass-05](Pass-05/) | 黑名单 - 大小写绕过 | ⭐⭐ | 🔲 |
| 06 | [Pass-06](Pass-06/) | 黑名单 - 尾部空格 | ⭐⭐ | 🔲 |
| 07 | [Pass-07](Pass-07/) | 黑名单 - 尾部点号 | ⭐⭐ | 🔲 |
| 08 | [Pass-08](Pass-08/) | 黑名单 - ::$DATA | ⭐⭐ | 🔲 |
| 09 | [Pass-09](Pass-09/) | 黑名单 - 组合绕过 | ⭐⭐⭐ | 🔲 |
| 10 | [Pass-10](Pass-10/) | 黑名单 - 双写扩展名 | ⭐⭐ | 🔲 |
| 11 | [Pass-11](Pass-11/) | 白名单 - %00 截断 (GET) | ⭐⭐⭐ | 🔲 |
| 12 | [Pass-12](Pass-12/) | 白名单 - %00 截断 (POST) | ⭐⭐⭐ | 🔲 |
| 13 | [Pass-13](Pass-13/) | 文件头 - 图片马 | ⭐⭐⭐ | 🔲 |
| 14 | [Pass-14](Pass-14/) | 文件头 - getimagesize() | ⭐⭐⭐ | 🔲 |
| 15 | [Pass-15](Pass-15/) | 文件头 - exif_imagetype() | ⭐⭐⭐ | 🔲 |
| 16 | [Pass-16](Pass-16/) | 图片二次渲染 | ⭐⭐⭐⭐ | 🔲 |
| 17 | [Pass-17](Pass-17/) | 条件竞争 | ⭐⭐⭐⭐ | 🔲 |
| 18 | [Pass-18](Pass-18/) | 条件竞争 + 重命名 | ⭐⭐⭐⭐ | 🔲 |
| 19 | [Pass-19](Pass-19/) | 目录穿越 | ⭐⭐⭐ | 🔲 |
| 20 | [Pass-20](Pass-20/) | 综合漏洞 | ⭐⭐⭐⭐⭐ | 🔲 |

### 环境搭建

```bash
# 使用 Docker（推荐）
docker pull c0ny1/upload-labs
docker run -d -p 80:80 c0ny1/upload-labs

# 或使用 PHPStudy/XAMPP 配合源码
git clone https://github.com/c0ny1/upload-labs.git
```

### 使用工具

- **Burp Suite** - HTTP 代理和请求修改
- **浏览器开发者工具** - JavaScript 调试和网络分析
- **010 Editor / HxD** - 十六进制编辑器用于文件头操作

### 免责声明

本仓库仅供**学习研究**使用。请仅在您拥有或获得明确授权的系统上进行测试。

---

## Repository Structure / 仓库结构

```
upload-labs-writeup/
├── README.md              # This file / 本文件
├── Pass-01/
│   ├── README.md          # Writeup (Bilingual)
│   └── images/
│       ├── 01-js-block-alert.png
│       ├── 02-devtools-disable-js.png
│       ├── 03-upload-success-broken-image.png
│       ├── 04-phpinfo-executed.png
│       ├── 05-burp-intercept-js-block.png
│       └── 06-console-override-checkfile.png
├── Pass-02/
│   └── ...
└── ...
```

## License / 许可证

MIT License
