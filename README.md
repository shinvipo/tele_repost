# CTI - Channel To Issue Forwarder

## Cấu trúc thư mục

```
CTI/
├── cti/                    # Package chính
│   ├── __init__.py
│   ├── __main__.py
│   ├── apply.py
│   ├── backfill.py
│   ├── config.py
│   ├── constants.py
│   ├── filters.py
│   ├── handler.py
│   ├── main.py
│   ├── models.py
│   ├── normalize.py
│   ├── repost.py
│   ├── routing.py
│   ├── state.py
│   └── telegram.py
├── data/                   # Dữ liệu runtime (session, state, exports)
│   ├── dump_session.session
│   ├── state_last_ids.json
├── config/                 # Configuration files
│   ├── config.json
│   └── config.json.example
├── backups/
├── tests/
│   └── test.py
├── main.py
└── requirements.txt
```

## Cài đặt

```bash
pip install -r requirements.txt
```

## Sử dụng

```bash
python final.py
```

## Cấu hình

Copy `config/config.json.example` thành `config/config.json` và cập nhật thông tin:

```bash
cp config/config.json.example config/config.json
```

Chỉnh sửa các thông tin Telegram API và routes trong `config/config.json`.
