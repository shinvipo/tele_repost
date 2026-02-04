# CTI

> 🤖 Hệ thống tự động chuyển tiếp tin nhắn từ các kênh Telegram sang các kênh/nhóm khác.

## 📋 Mục lục

- [Tính năng](#-tính-năng)
- [Cấu trúc thư mục](#-cấu-trúc-thư-mục)
- [Cài đặt](#-cài-đặt)
- [Cấu hình](#-cấu-hình)
- [Sử dụng](#-sử-dụng)
- [Quản lý Keywords](#-quản-lý-keywords)
- [Lưu ý](#-lưu-ý)

## ✨ Tính năng

- ✅ **Chuyển tiếp tin nhắn** tự động giữa các kênh/nhóm Telegram
- 🔍 **Lọc nội dung** theo từ khóa (keywords)
- 🎯 **Định tuyến thông minh** với nhiều route cùng lúc
- 👥 **Kiểm soát người gửi** với whitelist allowed_senders
- 📸 **Hỗ trợ media** (ảnh, video, file, album)
- 💬 **Topics support** cho Telegram Forum groups
- 🔄 **Hot reload** khi thay đổi cấu hình
- 📊 **Lưu trạng thái** để tránh tin nhắn trùng lặp
- 🛠️ **Admin commands** để quản lý keywords động
- 🔙 **Backfill** tin nhắn cũ khi cần

## 📁 Cấu trúc thư mục

```
CTI/
├── 📦 cti/                    # Package chính
│   ├── __init__.py
│   ├── __main__.py           
│   ├── admin.py              # Admin commands handler
│   ├── apply.py              # Apply config và watch changes
│   ├── backfill.py           # Backfill tin nhắn cũ
│   ├── config.py             # Parse và validate config
│   ├── constants.py          # Các hằng số
│   ├── filters.py            # Logic lọc tin nhắn
│   ├── handler.py            # Handler chuyển tiếp tin nhắn
│   ├── main.py               # Main entry point
│   ├── models.py             # Data models (dataclasses)
│   ├── normalize.py          # Normalize dữ liệu input
│   ├── repost.py             # Logic repost tin nhắn
│   ├── routing.py            # Quản lý routes
│   ├── state.py              # State management
│   └── telegram.py           # Telegram client utils
├── 📊 data/                   # Dữ liệu runtime
│   ├── dump_session.session  # Telegram session
│   ├── state_last_ids.json   # Lưu ID tin nhắn cuối
│   └── .gitkeep
├── ⚙️ config/                 # Cấu hình
│   ├── config.json           # Config thực tế
│   └── config.json.example   # Config mẫu
├── main.py                   # Entry point chính
├── requirements.txt          # Python dependencies
└── README.md                 # Tài liệu này
```

## 🚀 Cài đặt

### Yêu cầu

- Python 3.8 trở lên
- Telegram API credentials (api_id và api_hash)

### Các bước cài đặt

1. **Clone hoặc tải project về**

2. **Cài đặt dependencies:**

```bash
pip install -r requirements.txt
```

3. **Tạo file cấu hình:**

```bash
# Windows (PowerShell)
Copy-Item config\config.json.example config\config.json

# Linux/macOS
cp config/config.json.example config/config.json
```

4. **Lấy Telegram API credentials:**

   - Truy cập https://my.telegram.org
   - Đăng nhập và vào "API development tools"
   - Tạo app mới và lấy `api_id` và `api_hash`

5. **Cấu hình file `config/config.json`** (xem phần [Cấu hình](#-cấu-hình))

## ⚙️ Cấu hình

Chỉnh sửa file `config/config.json` với nội dung sau:

```json
{
  "telegram": {
    "api_id": 12345678,
    "api_hash": "your_api_hash_here",
    "session": "data/dump_session"
  },
  "monitor": {
    "routes": [
      {
        "source": "https://t.me/source_channel",
        "dest": -1001234567890,
        "topic_id": 2,
        "keywords": ["keyword1", "keyword2"],
        "allowed_senders": [123456789]
      }
    ]
  },
  "options": {
    "download_media": true,
    "album_wait_seconds": 1.2,
    "progress_log": true,
    "keywords": ["global_keyword"],
    "max_send_retries": 3,
    "retry_base_seconds": 1.5,
    "state_file": "data/state_last_ids.json",
    "reload_interval_seconds": 2,
    "admin_chat_ids": [-1001234567890],
    "admin_senders": [987654321]
  }
}
```

### 📝 Chi tiết cấu hình

#### `telegram`

| Field | Kiểu | Mô tả |
|-------|------|-------|
| `api_id` | int | Telegram API ID |
| `api_hash` | string | Telegram API Hash |
| `session` | string | Đường dẫn file session |

#### `monitor.routes`

Mỗi route có:

| Field | Kiểu | Mô tả |
|-------|------|-------|
| `source` | string/int | Link hoặc ID kênh nguồn |
| `dest` | int | ID kênh/nhóm đích |
| `topic_id` | int | (Optional) Topic ID cho Forum groups |
| `keywords` | array | (Optional) Keywords riêng cho route này |
| `allowed_senders` | array | (Optional) Danh sách user ID được phép |

#### `options`

| Field | Kiểu | Mặc định | Mô tả |
|-------|------|----------|-------|
| `download_media` | bool | `true` | Tải media trước khi repost |
| `album_wait_seconds` | float | `1.2` | Thời gian chờ để gom album |
| `progress_log` | bool | `true` | Hiển thị progress khi tải media |
| `keywords` | array | `[]` | Keywords global cho tất cả routes |
| `max_send_retries` | int | `3` | Số lần retry khi gửi thất bại |
| `retry_base_seconds` | float | `1.5` | Thời gian base cho retry |
| `state_file` | string | `data/state_last_ids.json` | File lưu state |
| `reload_interval_seconds` | float | `2` | Thời gian check config thay đổi |
| `admin_chat_ids` | array | `[]` | Danh sách chat ID được dùng admin commands |
| `admin_senders` | array | `[]` | Danh sách user ID được dùng admin commands |

## 🎮 Sử dụng

### Chạy chương trình

**Cách 1: Chạy trực tiếp**

```bash
python main.py
```

**Cách 2: Chạy như module**

```bash
python -m cti
```

### Lần chạy đầu tiên

- Chương trình sẽ yêu cầu bạn đăng nhập Telegram
- Nhập số điện thoại và mã xác nhận
- Session sẽ được lưu vào file `data/dump_session.session`

### Hot Reload

Khi bạn thay đổi `config/config.json`, hệ thống tự động:
- Phát hiện thay đổi
- Reload cấu hình mới
- Áp dụng routes và keywords mới
- Không cần restart chương trình

## 🔑 Quản lý Keywords

### Admin Commands

Để sử dụng admin commands, cần cấu hình:

```json
{
  "options": {
    "admin_chat_ids": [-1001234567890],
    "admin_senders": [987654321]
  }
}
```

**⚠️ Lưu ý:** 
- Nếu cả hai đều được cấu hình, lệnh chỉ được chấp nhận khi **đúng chat VÀ đúng người gửi**
- Nếu chỉ cấu hình một trong hai, chỉ kiểm tra điều kiện đó

### Các lệnh hỗ trợ

```bash
# Xem keywords hiện tại
/keywords show

# Đặt lại toàn bộ keywords
/keywords set keyword1,keyword2,keyword3

# Thêm keywords mới
/keywords add keyword4 keyword5

# Xóa keywords
/keywords remove keyword2

# Xóa tất cả keywords
/keywords clear
```

### Ví dụ sử dụng

```
/keywords show
→ Hiển thị: ["vietnam", "server"]

/keywords add datacenter cloud
→ Thêm: ["vietnam", "server", "datacenter", "cloud"]

/keywords remove vietnam
→ Còn: ["server", "datacenter", "cloud"]

/keywords set hosting domain email
→ Đặt lại: ["hosting", "domain", "email"]

/keywords clear
→ Xóa hết: []
```

## ⚠️ Lưu ý

### Tips

- 💡 Keywords **không phân biệt** chữ hoa/thường
- 💡 Để trống `keywords` = chuyển tiếp **tất cả** tin nhắn
- 💡 `topic_id` chỉ hoạt động với **Forum groups**
- 💡 `allowed_senders` giúp lọc spam hiệu quả
- 💡 Session file có thể dùng lại, không cần đăng nhập lại

### Xử lý lỗi

**Lỗi đăng nhập:**
```bash
# Xóa session cũ và thử lại
rm data/dump_session.session
python main.py
```

**Lỗi không tìm thấy channel:**
- Kiểm tra bot đã join channel chưa
- Kiểm tra link/ID channel có đúng không

**Lỗi gửi tin nhắn:**
- Kiểm tra bot có quyền post trong channel/group không
- Kiểm tra `topic_id` có đúng không (nếu dùng Forum)

---

**Phát triển bởi:** shinvipo  
**Issues:** Báo lỗi tại GitHub Issues
