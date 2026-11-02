# Tiến độ: công cụ kiểm kê mật mã và đề xuất PQC

Cập nhật: 2026-11-02

## Mục tiêu

Sếp cần một công cụ để **demo**. Công cụ tìm xem phần mềm của khách hàng dùng những thuật toán mật mã nào, rồi đề xuất chuyển sang mật mã hậu lượng tử (PQC) ở những chỗ yếu. Yêu cầu **đa ngôn ngữ**; C/C++ không bắt buộc.

## Tóm tắt kết quả

- Không có tool mã nguồn mở nào đủ dùng một mình. Hướng đi là **ghép 3 tool** (CBOMkit, CryptoScan, qryx) và bổ sung các bộ quét tự viết, tất cả trong repo này (`pqc-assess`).
- **Bộ mẫu tự sinh** (26 điểm crypto biết trước, 6 ngôn ngữ + nginx): tìm được **25/26**. Từng tool riêng lẻ chỉ được 16, 13 và 10. Ngoài ra còn tìm được crypto bên trong `.jar` và binary Go đã xóa symbol, không cần source.
- **App thật:**
  - **OWASP WebGoat** (Java): 147 phát hiện, 111 trong code và 36 trong test/tài liệu. Gần như tất cả đều đúng.
  - **OWASP Juice Shop** (TypeScript): 51 phát hiện, 28 trong code và 23 trong test/tài liệu. Ở phần code, trong 24 phát hiện cần xử lý có khoảng 19 là đúng.
- Tìm ra và sửa **một lỗ hổng bảo mật trong CryptoScan**: đi theo symlink nên làm lộ file trên máy quét, ví dụ khóa SSH. Báo cáo gửi riêng cho nhóm phát triển đã soạn xong nhưng **chưa gửi**.

## Các việc đã làm

### 1. Đánh giá CryptoScan (csnp/cryptoscan)
- Clone, đọc code, build và chạy test trong Docker `golang:1.22`, vì máy chưa cài Go. Tất cả test đạt, kể cả `-race`.
- Thử nghiệm xác nhận lỗi symlink: một symlink `innocent.py -> ~/.ssh/id_rsa` khiến private key bị chép vào báo cáo JSON.
- Sửa lỗi, kèm test chứng minh test fail khi chưa sửa và đạt khi đã sửa. Commit `c01771d` trên nhánh `fix/skip-symlinks`.
- Thêm luật cho `DES3` (PyCryptodome), `DES-CBC3` (nginx/OpenSSL), `EVP_des_ede3*`, `EVP_aes_*`, `EVP_PKEY_EC` và các hằng số đường cong `NID_*`. Có test và mục CHANGELOG. Commit `0d9cdee`.
- Phát hiện CryptoScan ẩn AES và SHA-2 theo mặc định; phải bật `--include-quantum-safe`.

### 2. So sánh các tool khác
- Đã chạy thử CBOMkit (`cbomkit-action`, chạy offline) và qryx (build từ source, chạy offline) trên cùng bộ mẫu.
- Đã tra cứu: cbomkit-theia, cryptobom-forge (GPL), Wind River crypto-detector (bỏ dở từ 2020), CipherScope, cryptosweep, qscout, CodeQL (license thương mại cần GitHub Advanced Security), luật Semgrep (license cấm dùng cho SaaS/sản phẩm cạnh tranh), và các giải pháp thương mại (IBM QSE, SandboxAQ, Keyfactor).

### 3. Xây dựng `pqc-assess` (repo này)
- **Chạy cô lập:** mỗi tool chạy trong container không mạng, không quyền đặc biệt, thư mục quét được mount chỉ-đọc. Thư mục quét được sao chép và loại bỏ symlink trước.
- **Ghim phiên bản** trong `tools.lock.json`, không dùng submodule:
  - CBOMkit: theo digest của image.
  - qryx: theo phiên bản v1.1.1.
  - CryptoScan: theo commit `61fe200`, cộng 2 patch trong `patches/cryptoscan/`.
- **Gộp kết quả:** chuẩn hóa tên thuật toán, gộp theo file + dòng + họ thuật toán, và ghi tool nào đã thấy.
- **Phân loại rủi ro và đề xuất thay thế:** ML-KEM-768, ML-DSA-65, SLH-DSA, AES-256-GCM, TLS 1.3 + X25519MLKEM768.
- **Bộ quét tự viết:**
  - `detectors/jar.py`: đọc bytecode Java (constant pool, mã lệnh, LineNumberTable) để lấy thuật toán, độ dài khóa và số dòng gốc.
  - `detectors/gobinary.py`: đọc bảng tên hàm (pclntab) của binary Go, kể cả binary đã xóa symbol.
  - `detectors/jose.py`: tìm thuật toán ký JWT/JOSE (RS256, ES256, PS*, EdDSA). Đây là chỗ cả 3 tool đều sót trên Juice Shop.
- **Giảm nhiễu khi chạy trên app thật:**
  - Bỏ các luật "chứng chỉ" của CryptoScan khớp với chữ thường như `expires` (299/354 phát hiện của Juice Shop).
  - Tách phát hiện trong code khỏi phát hiện trong test, tài liệu, file dịch và dữ liệu.
  - Gom các dòng cùng file, cùng thuật toán thành một hàng trong báo cáo.
- **Không chép bí mật:** khóa hoặc chuỗi khớp của các phát hiện kiểu "key material" không bao giờ vào báo cáo. Báo cáo chỉ ghi tên thư mục quét, không ghi đường dẫn trên máy quét.
- 27 unit test, chỉ dùng thư viện chuẩn của Python 3.10.

### 4. Gói demo
- `demo-package.zip` gồm bộ mẫu, kết quả gốc của công cụ, symlink bẫy và `report.md` (tiếng Anh) có link tới từng file.

### 5. Thử trên app thật
- WebGoat (commit `be2c186`) và Juice Shop (commit `717f5ef`), mỗi app quét khoảng 30 giây.
- Kết quả nằm trong `real-apps-results/` (báo cáo, CBOM, findings).

## Vị trí các file

Thư mục gốc: `~/Tung/projects/security/`

| Đường dẫn | Nội dung |
|---|---|
| `pqc-assess/` | repo chính (repo này) |
| `cryptoscan/` | clone của csnp/cryptoscan; nhánh `fix/skip-symlinks` có 2 commit sửa lỗi |
| `disclosure/` | báo cáo lỗ hổng soạn cho CSNP và 2 file patch |
| `demo-package/`, `demo-package.zip` | gói demo kèm báo cáo |
| `real-apps-results/WebGoat/`, `real-apps-results/juice-shop/` | kết quả quét app thật |

## Cách chạy lại

```sh
cd ~/Tung/projects/security/pqc-assess
python3 -m pqc_assess build                       # build/tải image các tool (cần mạng, làm 1 lần)
python3 -m pqc_assess scan <thư-mục> -o <thư-mục-kết-quả>
python3 -m unittest discover -s tests -t .        # chạy test
```

## Giới hạn đã biết

- Luật tìm theo chữ của CryptoScan vẫn còn báo động giả trong code: chuỗi `'%md5%'`, phần mở rộng `.md5`, `code: RSA` (mã quốc gia Nam Phi).
- `createHmac('sha1')` bị xếp vào "broken". Thực tế HMAC-SHA1 vẫn được NIST chấp nhận, nên cần tách khỏi SHA-1 dùng để băm.
- Một khóa RSA hardcode hiện ra hai lần: "Key material in code" và "RSA". Hợp lý nhưng làm tăng số đếm.
- CBOMkit quét Java chính xác nhất khi dự án đã được build; hiện đang chạy chế độ chỉ source.
- Binary C/C++ và Rust đã xóa symbol chưa được phân tích. Ngoài phạm vi demo.
- Thuật toán được chọn lúc chạy (từ file cấu hình, database) thì không quét tĩnh được.

## Bước tiếp theo đề xuất

1. **Demo:** dùng kết quả WebGoat và Juice Shop. App thật, nổi tiếng, thuyết phục hơn bộ mẫu. Có thể đưa vào gói demo.
2. **Giảm báo động giả còn lại:** tách HMAC-SHA1; hạ mức các phát hiện chỉ do CryptoScan bắt được khi chuỗi khớp nằm trong tên file hoặc chuỗi SQL; gộp "Key material" và "RSA" cùng một dòng.
3. **Build Java trước khi quét** (Maven/Gradle trong container) để CBOMkit chính xác hơn.
4. **Bảng tổng quan HTML một trang** cho buổi trình bày.
5. **Gửi bản sửa lên CryptoScan:** ngày 2026-11-02 đã quyết định đưa bản sửa symlink lên fork công khai và đưa repo này công khai. Từ lúc đó lỗ hổng coi như đã công khai, nên cần **báo ngay cho CSNP** (`disclosure/cryptoscan-symlink-report.md`), rồi mở PR từ fork cho cả hai commit.
6. **Thử trên một codebase lớn** để đo thời gian và mức nhiễu.
