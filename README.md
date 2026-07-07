# Secure Personal Data Vault — Đề tài 22

Đồ án An toàn Bảo mật: hệ thống lưu trữ thông tin nhạy cảm (số điện thoại,
email, số giấy tờ...) có **mã hóa AES-256-GCM**, **phân quyền RBAC**
(user / admin / auditor) và **audit log dạng hash-chain**.

## 1. Kiến trúc

```
secure_vault/
├── app.py             # Flask backend: auth, RBAC, API, audit log
├── crypto_utils.py     # Mã hóa AES-GCM + quản lý khóa (envelope encryption)
├── legacy_demo.py      # Demo TripleDES (chỉ để SO SÁNH, không dùng bảo vệ data thật)
├── database.py          # Schema SQLite + helper
├── static/index.html    # Giao diện web (HTML/JS thuần, gọi REST API thật)
├── tests/test_app.py    # Bộ test bắt buộc (pytest)
├── requirements.txt
├── vault.db              # Database SQLITE MẪU (đã seed sẵn dữ liệu demo)
├── audit_log_sample.csv  # Audit log mẫu xuất từ database trên
└── test_report.txt       # Kết quả chạy pytest
```

## 2. Cài đặt & chạy thử

```bash
cd secure_vault
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# (tuỳ chọn) đặt khóa chủ qua biến môi trường thay vì để hệ thống tự sinh:
# export VAULT_MASTER_KEY=$(python3 -c "import base64,os;print(base64.b64encode(os.urandom(32)).decode())")

python3 app.py
# mở trình duyệt: http://127.0.0.1:5000
```

Lần chạy đầu sẽ tự tạo `vault.db` (nếu chưa có) và `master.key` (nếu không
đặt biến môi trường `VAULT_MASTER_KEY`).

> File `vault.db` đính kèm đã có sẵn 4 tài khoản mẫu để bạn đăng nhập thử ngay
> (xem mục 5 bên dưới) — không cần đăng ký lại.

## 3. Chạy test

```bash
pytest tests/ -v
```

Kết quả mẫu: xem `test_report.txt` (8/8 test PASSED).

## 4. Các quyết định thiết kế chính (đáp ứng yêu cầu nâng cấp bắt buộc)

| Yêu cầu | Cách đáp ứng |
|---|---|
| AES-GCM là cơ chế mã hóa chính | `crypto_utils.py` dùng `AESGCM` (cryptography lib), nonce ngẫu nhiên 96-bit mỗi lần mã hóa, AAD gắn `owner_id:field_name` để chống đổi-chỗ ciphertext. |
| TripleDES chỉ dùng so sánh/legacy | `legacy_demo.py` độc lập, không được `app.py` import/sử dụng để bảo vệ dữ liệu thật. |
| Phân quyền tối thiểu user/admin/auditor | Bảng `users.role` + decorator `role_required()` trong `app.py`. |
| Admin không mặc định xem được dữ liệu | Bảng `decrypt_grants`: admin phải tự "Xin quyền" (endpoint `/grant`), quyền hết hạn sau 10 phút, mọi lần giải mã đều kiểm tra grant còn hiệu lực. |
| Mọi lần giải mã ghi audit log | `write_audit()` được gọi ở mọi nhánh: `DECRYPT_SUCCESS`, `DECRYPT_DENIED`, `INTEGRITY_FAILURE`, `LOGIN_SUCCESS/FAILED`, `GRANT_CREATED`, `ACCESS_DENIED`... |
| Cơ chế quản lý khóa | Envelope encryption: 1 Master Key (file `master.key`, mode 600, hoặc biến môi trường) → mỗi user có 1 Data Encryption Key dẫn xuất bằng HKDF-SHA256 (`derive_user_dek`). Xem chi tiết comment trong `crypto_utils.py`. |
| Test dữ liệu trong DB không ở dạng rõ | Cột `sensitive_data.ciphertext` chỉ chứa base64(nonce‖ciphertext+tag); không có cột plaintext nào (xem seed data ở `vault.db`). |

## 5. Tài khoản mẫu trong `vault.db` đính kèm

| username | password | role |
|---|---|---|
| alice | alicepw123 | user |
| bob | bobpassword | user |
| admin1 | adminpass1 | admin |
| auditor1 | auditorpass | auditor |

Kịch bản đã seed sẵn trong audit log mẫu: alice tạo 3 trường dữ liệu, bob tạo
1 trường; admin1 cố giải mã khi **chưa** có quyền (bị từ chối, có log
`DECRYPT_DENIED`), sau đó xin quyền (`GRANT_CREATED`) và giải mã thành công
(`DECRYPT_SUCCESS`); auditor1 cố xem dữ liệu nhạy cảm và bị từ chối
(`ACCESS_DENIED`).

## 6. Kiểm thử bảo mật bắt buộc — đối chiếu

1. **User tạo dữ liệu nhạy cảm** → `test_user_creates_and_views_own_data`.
2. **User xem dữ liệu của mình** → cùng test trên; cũng test
   `test_user_cannot_see_other_users_data` để đảm bảo cô lập theo owner.
3. **Admin không có quyền giải mã nếu chưa cấp quyền** →
   `test_admin_cannot_decrypt_without_grant` (và `..._after_grant` cho chiều ngược lại).
4. **Auditor xem log nhưng không xem dữ liệu nhạy cảm** →
   `test_auditor_sees_log_but_not_sensitive_data`.
5. **Sửa ciphertext trong database** → `test_tampered_ciphertext_detected`
   (dùng endpoint demo `/tamper` cố tình sửa 1 ký tự ciphertext, AES-GCM phát
   hiện qua `InvalidTag`, trả lỗi "toàn vẹn dữ liệu thất bại").
6. **Kiểm tra log giải mã** → `test_decrypt_actions_are_logged`,
   `test_login_failure_logged`.

Có thể demo trực quan ngay trên giao diện web: đăng nhập `admin1`, bấm nút
đỏ "Demo: Sửa ciphertext record đầu tiên" rồi thử "Xin quyền" + "Giải mã" để
thấy lỗi toàn vẹn hiện ra trên UI.

## 7. Hạn chế đã biết (nên nêu trong báo cáo để thể hiện tư duy phản biện)

- Cơ chế "Xin quyền" hiện do chính admin tự cấp cho mình (self-service) để
  đơn giản hoá demo trong phạm vi đồ án; hệ thống thật nên có người khác
  (vd: security officer) phê duyệt yêu cầu trước khi cấp quyền (four-eyes
  principle / break-glass có duyệt).
- Master key lưu trên cùng máy chủ ứng dụng (file `master.key`); môi trường
  production nên dùng KMS/HSM tách biệt.
- Phiên đăng nhập dùng Flask session cookie đơn giản, chưa có 2FA / rate
  limiting chống brute-force — có thể bổ sung nếu giảng viên yêu cầu mở rộng.
- Chưa có video demo trong gói nộp này — bạn cần tự quay màn hình thao tác
  trên giao diện web theo các bước ở mục 6 để hoàn thiện sản phẩm nộp bài.

## 8. Ngôn ngữ & thư viện đã dùng (đối chiếu mục 9 đề bài)

Python 3 + Flask, `cryptography` (AES-GCM, TripleDES demo, HKDF), `bcrypt`
(băm mật khẩu), `pytest` (kiểm thử) — đúng danh sách thư viện khuyến nghị.
