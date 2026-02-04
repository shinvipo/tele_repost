# CTI - Channel To Issue Forwarder

## Cau truc thu muc

```
CTI/
??? cti/                    # Package chinh
?   ??? __init__.py
?   ??? __main__.py
?   ??? admin.py
?   ??? apply.py
?   ??? backfill.py
?   ??? config.py
?   ??? constants.py
?   ??? filters.py
?   ??? handler.py
?   ??? main.py
?   ??? models.py
?   ??? normalize.py
?   ??? repost.py
?   ??? routing.py
?   ??? state.py
?   ??? telegram.py
??? data/                   # Du lieu runtime (session, state, exports)
?   ??? dump_session.session
?   ??? state_last_ids.json
??? config/                 # Configuration files
?   ??? config.json
?   ??? config.json.example
??? backups/
??? tests/
?   ??? test.py
??? main.py
??? requirements.txt
```

## Cai dat

```bash
pip install -r requirements.txt
```

## Su dung

```bash
python main.py
```

Hoac:

```bash
python -m cti
```

## Cau hinh

Copy `config/config.json.example` thanh `config/config.json` va cap nhat thong tin:

```bash
cp config/config.json.example config/config.json
```

Chinh sua thong tin Telegram API va routes trong `config/config.json`.

### Admin chat commands (keywords)

Trong `options` co the cau hinh:

- `admin_chat_ids`: danh sach ID chat quan tri (group/private) duoc phep gui lenh.
- `admin_senders`: danh sach user/bot ID duoc phep gui lenh.

**Neu ca hai cung co gia tri**, he thong chi chap nhan lenh khi **dung chat** va **dung sender**.

Lenh ho tro:

```
/keywords show
/keywords set k1,k2
/keywords add k3 k4
/keywords remove k2
/keywords clear
```

Lenh se cap nhat `config/config.json` va tu dong reload.
