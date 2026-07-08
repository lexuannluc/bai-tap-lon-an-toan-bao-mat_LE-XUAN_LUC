# 🔐 Secure Personal Data Vault — Đề tài 22 (Bản nâng cấp)

Bài tập lớn FIT4012 — Secure System Upgrade Challenge.
Nâng cấp từ dự án khoá trước [`ma-hoa-thong-tin-nhay-cam-main`](.) (Flask + Triple DES/AES-CBC,
lưu `users.json`, mật khẩu admin lưu dạng rõ trong `.env`) lên hệ thống đáp ứng đầy đủ yêu cầu kỹ
thuật bắt buộc của đề bài.

## 1. Kiến trúc tổng quan

```
Trình duyệt ── HTTPS/HTTP ──▶ Flask app (app.py)
                                 ├── auth.py       (RBAC decorators: login_required, roles_required)
                                 ├── crypto_utils.py (AES-256-GCM, HMAC, scrypt, HKDF key mgmt, 3DES-legacy)
                                 ├── db.py         (SQLite: users, vault_records, access_grants,
                                 │                  used_nonces, login_attempts, audit_logs)
                                 └── templates/    (giao diện "Vault Ledger")
```

Vai trò (3 role bắt buộc theo đề bài):

| Vai trò  | Quyền |
|---------|-------|
| **User**    | Xem/sửa/xoá **chỉ** dữ liệu của chính mình, phải nhập lại mật khẩu để giải mã |
| **Admin**   | Quản lý danh sách bản ghi, nhưng **không mặc định xem được dữ liệu thật**. Phải gửi yêu cầu truy cập (kèm lý do) và chờ Auditor phê duyệt. Quyền được cấp có **thời hạn** và **dùng một lần**. |
| **Auditor** | Phê duyệt/từ chối yêu cầu của Admin, xem toàn bộ nhật ký hệ thống, xác minh chuỗi hash của log — **không có route nào cho phép Auditor giải mã dữ liệu**. |

## 2. Những gì đã nâng cấp so với bài khoá trước

| Thành phần | Bài khoá trước có gì? | Nhóm nâng cấp gì? | Minh chứng |
|---|---|---|---|
| Mã hoá dữ liệu | AES-CBC + Triple DES-CBC, **không có xác thực** (không phát hiện được ciphertext bị sửa) | Chuyển hẳn sang **AES-256-GCM** (authenticated encryption) cho toàn bộ dữ liệu nhạy cảm; Triple DES chỉ giữ lại ở trang `/admin/benchmark` để **so sánh minh hoạ**, không dùng để bảo vệ dữ liệu thật | `crypto_utils.py`, `tests/test_security.py::test_aes_gcm_tamper_detected` |
| Toàn vẹn dữ liệu | Không có | Thêm lớp **HMAC-SHA256** ở cấp bản ghi, phủ cả các trường không mã hoá (bank_name, timestamp…) | `compute_record_hmac`/`verify_record_hmac`, test `test_hmac_record_tamper_detected` |
| Lưu trữ | File JSON phẳng (`users.json`), không transaction | **SQLite** thật với khoá chính/khoá ngoại, transaction | `db.py` |
| Mật khẩu | Mật khẩu admin lưu **dạng rõ** trong `.env`, so sánh trực tiếp `==` | **scrypt** (qua `werkzeug.security`) cho mọi tài khoản, salt ngẫu nhiên | `hash_password`/`verify_password` |
| Phân quyền | 2 vai trò ẩn (user/admin), admin xem được mọi dữ liệu ngay khi đăng nhập | 3 vai trò tách bạch, **Admin phải xin quyền từng bản ghi**, Auditor duyệt, quyền có hạn dùng + hết hạn theo thời gian | `access_grants` table, `/admin/grant/*`, `/auditor/grant/*` |
| Chống replay | Không có | Nonce một lần dùng (single-use, có TTL) bắt buộc cho **mọi hành động giải mã** (user tự xem, admin xem sau khi được duyệt) | `used_nonces` table, `db.consume_nonce`, test `test_replay_nonce_cannot_be_reused` |
| Khoá bí mật | 2 khoá hex hard-code kiểu, đọc thẳng từ `.env`, không có key separation | **HKDF** suy dẫn nhiều khoá con (mã hoá, HMAC, chữ ký log, legacy-3DES) từ **một** `ROOT_SECRET` duy nhất — không khoá nào hard-code trong mã nguồn | `crypto_utils.init_keys`, `_derive_key` |
| Ghi log | `logging` cơ bản, có lúc ghi cả dict dữ liệu cũ/mới (rủi ro rò rỉ) | Audit log có **hash-chain** chống giả mạo (mỗi dòng log ký lên dòng trước), không bao giờ ghi plaintext nhạy cảm, phân loại sự kiện rõ ràng | `db.append_audit_log`, `db.verify_log_chain`, `/auditor/verify_logs` |
| Đăng nhập sai | Giới hạn theo session (dễ bị vượt qua bằng cách xoá cookie) | Giới hạn theo **username trong CSDL**, khoá 15 phút sau 5 lần sai | `login_attempts` table |
| Giao diện | Bootstrap mặc định | Giao diện riêng "Vault Ledger" (xem mục 4) | `static/style.css`, `templates/` |

## 3. Cơ chế bảo mật chi tiết

### 3.1 Mã hoá dữ liệu (yêu cầu 4.1)
- **AES-256-GCM** là cơ chế chính: mỗi trường (CCCD, BHXH, số tài khoản) có nonce riêng (12 byte,
  sinh ngẫu nhiên mỗi lần mã hoá) và một **tag xác thực** — nếu bản mã hoặc tag bị sửa một bit,
  `decrypt_and_verify` sẽ ném lỗi thay vì trả về dữ liệu sai.
- **Triple DES-CBC** chỉ tồn tại trong `des3_cbc_encrypt_legacy/decrypt_legacy` và được gọi duy
  nhất từ trang benchmark, đúng theo yêu cầu "TripleDES chỉ nên dùng như chế độ minh hoạ/so sánh".

### 3.2 Toàn vẹn & xác thực (yêu cầu 4.2)
- GCM-tag bảo vệ **từng trường mã hoá**.
- HMAC-SHA256 cấp bản ghi bảo vệ **toàn bộ bản ghi**, kể cả `bank_name`, `created_at`,
  `updated_at` — phát hiện cả trường hợp kẻ tấn công sửa trực tiếp trong CSDL mà không đụng vào
  các trường đã mã hoá.
- Log hash-chain bảo vệ **tính toàn vẹn của chính nhật ký** — Auditor có nút "Xác minh chuỗi hash"
  để phát hiện log có bị chỉnh sửa hay không.

### 3.3 Quản lý khoá / phiên (yêu cầu 4.3)
- Một `ROOT_SECRET` duy nhất (32 byte ngẫu nhiên, nằm trong `.env`, **không** commit git) qua
  HKDF sinh ra các khoá con theo mục đích (`aaes-gcm-field-encryption`, `record-integrity-hmac`,
  `legacy-3des-demo-only`, `audit-log-hash-chain`) — không khoá nào bị hard-code trong `app.py`.
- `session_id` (uuid4) được sinh khi đăng nhập và gắn vào mọi dòng audit log để truy vết theo
  phiên làm việc.
- Không bao giờ log mật khẩu, token, hay dữ liệu nhạy cảm dạng rõ.

### 3.4 Chống replay (yêu cầu 4.4)
- Mọi hành động "xem dữ liệu thật" (user tự xem, admin xem sau khi được cấp quyền) yêu cầu một
  **nonce một lần dùng** với TTL (mặc định 60 giây), lưu trong bảng `used_nonces`. Nếu form bị
  chặn lại và gửi lại (replay), server sẽ từ chối và ghi log `REPLAY_DETECTED`.
- Quyền truy cập Admin (`access_grants`) cũng chỉ **dùng được một lần** và có hạn 10 phút.

### 3.5 Ghi log & xử lý lỗi (yêu cầu 4.5)
Các loại sự kiện được ghi: `LOGIN_SUCCESS`, `LOGIN_FAIL`, `LOGIN_BLOCKED_LOCKOUT`, `LOGOUT`,
`ACCOUNT_CREATED`, `ACCOUNT_DELETED`, `VIEW_OWN_DATA`, `DATA_MODIFIED`, `GRANT_REQUESTED`,
`GRANT_APPROVED`, `GRANT_DENIED`, `DECRYPT_SUCCESS`, `PERMISSION_DENIED`, `REAUTH_FAIL`,
`REPLAY_DETECTED`, `INTEGRITY_FAIL`, `DATA_EXPIRED`, `LOG_INTEGRITY_CHECK`, `BENCHMARK_RUN`.

## 4. Giao diện — "Vault Ledger"

Ý tưởng thiết kế: kết hợp cảm giác của **một cuốn sổ ghi chép trong két sắt ngân hàng** với một
terminal mật mã hiện đại. Bảng màu than chì/thép (`#14171c` / `#1c2028`) với điểm nhấn màu đồng
thau (`#c99a4b`, gợi con dấu sáp) cho các hành động và trạng thái "đã xác thực"; dữ liệu chưa giải
mã hiển thị dưới dạng vạch kẻ sọc như tài liệu bị bôi đen (redacted document). Font chữ: IBM Plex
Serif (tiêu đề, gợi văn bản chính thức), IBM Plex Sans (nội dung), IBM Plex Mono (dữ liệu/số liệu
mật mã). Chi tiết trong `static/style.css`.

## 5. Cài đặt & chạy

```bash
pip install -r requirements.txt

# Sinh khoá + tạo file .env mới (không commit .env lên git)
python init_db.py --gen-keys

# Khởi tạo CSDL + tạo tài khoản admin/auditor mẫu (đổi mật khẩu ngay!)
python init_db.py --seed

python app.py
# Trình duyệt tự mở http://127.0.0.1:5000
```

Chạy test:
```bash
pytest tests/ -v
```

## 6. Bảng kế thừa và nâng cấp (mục 6 báo cáo)

| Thành phần | Bài khoá trước có gì? | Nhóm kế thừa gì? | Nhóm nâng cấp gì? | Minh chứng |
|---|---|---|---|---|
| Giao diện | Bootstrap form đơn giản | Cấu trúc trang (nhập liệu, xem, sửa) | Thiết kế lại toàn bộ theo hướng "Vault Ledger" | Ảnh/video demo |
| Thuật toán | AES-CBC + 3DES-CBC | Ý tưởng mã hoá đối xứng | AES-256-GCM là chính, 3DES chỉ minh hoạ | `crypto_utils.py` |
| Giao thức | HTTP form POST | Luồng request/response cơ bản | Thêm nonce chống replay, session_id | `replay` logic trong `app.py`/`db.py` |
| Xác thực | So khớp CCCD làm mật khẩu | — (thiết kế cũ không an toàn, bỏ hẳn) | Đăng nhập username/password (scrypt), khoá tài khoản sau 5 lần sai | `login`, `login_attempts` |
| Kiểm tra toàn vẹn | Không có | — | GCM-tag + HMAC bản ghi + hash-chain log | `tests/test_security.py` |
| Chống replay | Không có | — | Nonce một lần dùng + TTL | `used_nonces` |
| Quản lý khoá | 2 khoá hex trong `.env` | Việc lưu khoá ngoài mã nguồn | HKDF suy dẫn nhiều khoá từ 1 root secret | `crypto_utils.init_keys` |
| Logging | `system.log` cơ bản | Việc ghi file log | Audit log có cấu trúc + hash-chain, phân quyền xem log cho Auditor | `audit_logs` table |
| Benchmark | Số liệu tĩnh trong README cũ | — | Trang `/admin/benchmark` đo trực tiếp trên máy chạy | `crypto_utils.benchmark` |
| GitHub | — | — | Lịch sử commit sau thời điểm nhận đề (nhóm tự thực hiện khi nộp bài) | Link repo |

## 7. Hạn chế & hướng phát triển
- Chưa tích hợp xác thực đa yếu tố (2FA/TOTP) cho bước re-auth khi giải mã.
- `SQLite` phù hợp cho demo học thuật; triển khai thật nên dùng PostgreSQL/MySQL với connection pool.
- Cơ chế cấp quyền hiện là single-use theo từng bản ghi; có thể mở rộng thành chính sách theo
  nhóm dữ liệu (data classification) hoặc tích hợp Vault/Secret Manager thực sự cho `ROOT_SECRET`.
- Nên bổ sung HTTPS/TLS termination và CSRF token toàn cục (hiện anti-replay nonce đã đóng vai trò
  tương tự cho các hành động nhạy cảm, nhưng một lớp CSRF token chuẩn của Flask-WTF sẽ chặt chẽ hơn
  cho toàn bộ form).
