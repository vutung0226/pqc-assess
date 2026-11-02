# Tiến độ: công cụ kiểm kê mật mã và đề xuất PQC

Cập nhật: 2026-11-02

## Mục tiêu

Sếp cần một công cụ để **demo**. Công cụ tìm xem phần mềm của khách hàng dùng những thuật toán mật mã nào, rồi đề xuất chuyển sang mật mã hậu lượng tử (PQC) ở những chỗ yếu. Yêu cầu **đa ngôn ngữ**; C/C++ không bắt buộc.

## Tóm tắt kết quả

- Không có tool mã nguồn mở nào đủ dùng một mình. Hướng đi là **ghép 3 tool** (CBOMkit, CryptoScan, qryx) và bổ sung các bộ quét tự viết, tất cả trong repo này (`pqc-assess`).
- **Bộ mẫu tự sinh** (26 điểm crypto biết trước, 6 ngôn ngữ + nginx): tìm được **25/26**. Từng tool riêng lẻ chỉ được 16, 13 và 10. Ngoài ra còn tìm được crypto bên trong `.jar` và binary Go đã xóa symbol, không cần source.
- **App thật:**
  - **OWASP WebGoat** (Java): 147 phát hiện, 111 trong code và 36 trong test/tài liệu.
  - **OWASP Juice Shop** (TypeScript): 48 phát hiện, 21 trong code. Ở phần code có 15 hàng cần xử lý, chỉ 1 báo động giả (lần đầu chạy: 354 phát hiện, phần lớn là nhiễu).
  - WebGoat ở phần code có 22 hàng cần xử lý, 3 báo động giả.
- Repo công khai: https://github.com/vutung0226/pqc-assess và fork https://github.com/vutung0226/cryptoscan (nhánh `fix/skip-symlinks`).
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
- `demo-package.zip` gồm bộ mẫu, kết quả gốc của công cụ, symlink bẫy, kết quả WebGoat và Juice Shop (`real-apps/`), và `report.md` (tiếng Anh) có link tới từng file.

### 5. Thử trên app thật
- WebGoat (commit `be2c186`) và Juice Shop (commit `717f5ef`), mỗi app quét khoảng 30 giây.
- Kết quả nằm trong `real-apps-results/` (báo cáo, CBOM, findings).
- Sau đó đã cải tiến thêm:
  - HMAC-SHA1 tách khỏi SHA-1, xếp là chấp nhận được.
  - Dòng chứa khóa RSA chỉ còn một phát hiện "Key material", kèm ghi chú thuật toán.
  - Phát hiện chỉ do CryptoScan bắt được mà tên thuật toán chỉ nằm trong phần mở rộng file, URL hoặc chuỗi SQL thì xếp thành "mention".
  - Các bước này đọc dòng nguồn qua `source.py`: không đi theo symlink, không đọc ra ngoài thư mục quét.
- 33 unit test.

### 6. GitHub
- Fork `csnp/cryptoscan` sang `vutung0226/cryptoscan`, push nhánh `fix/skip-symlinks` (2 commit).
- Tạo repo công khai `vutung0226/pqc-assess` và push. Push qua HTTPS bằng thông tin đăng nhập của `gh` (tài khoản vutung0226); SSH key của máy thuộc tài khoản khác (Vuchauduytung).

### 7. Deploy lên Raspberry Pi (mikerpi5.lan)
- Pi 5: aarch64, Debian 12, Docker 29, Python 3.11. Ổ thẻ nhớ ban đầu chỉ còn 825 MB.
- Dọn dung lượng: `docker builder prune` không giải phóng được gì (cache dùng chung layer với image). Đã chạy `sudo apt-get clean` (1,3 GB file `.deb`) và `pip cache purge` (223 MB), lên được 2,2 GB trống. Không xóa image hay container nào; các container Home Assistant, Grafana, InfluxDB đã dừng vẫn giữ nguyên.
- `scripts/deploy.sh mikerpi5.lan`: biên dịch chéo CryptoScan và qryx sang arm64 trên máy dev, chép repo và binary lên `~/pqc-assess`, đóng image distroless trên Pi, kéo CBOMkit bản arm64 (cùng digest đã ghim), rồi chạy test và tự kiểm tra.
- Kiểm chứng: quét bộ mẫu trên Pi (`~/pqc-assess-demo/`) cho ra 41/41 phát hiện, giống hệt kết quả trên máy dev. Mất 9 giây. Sau khi deploy Pi còn 1,6 GB trống.
- Chạy trên Pi: `ssh mikerpi5.lan 'cd ~/pqc-assess && python3 -m pqc_assess scan <thư-mục> -o <kết-quả>'`.

### 8. Pull request lên csnp/cryptoscan
- Nội dung PR đã soạn: mô tả lỗi symlink, cách tái hiện, thay đổi và test. Hệ thống phân quyền của Claude Code chặn việc tự mở PR (tạo nội dung công khai), nên **anh cần tự chạy lệnh mở PR**.

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

- Luật tìm theo chữ của CryptoScan vẫn còn vài báo động giả trong code: `code: RSA` (mã quốc gia Nam Phi), tên file `MD5.java` trong file cấu hình, checksum `<sha1>`.
- CBOMkit quét Java chính xác nhất khi dự án đã được build; hiện đang chạy chế độ chỉ source.
- Binary C/C++ và Rust đã xóa symbol chưa được phân tích. Ngoài phạm vi demo.
- Thuật toán được chọn lúc chạy (từ file cấu hình, database) thì không quét tĩnh được.

## Bước tiếp theo đề xuất

1. ~~Đưa kết quả WebGoat và Juice Shop vào gói demo~~ (đã xong).
2. ~~Tách HMAC-SHA1; gộp "Key material" và "RSA" cùng dòng; hạ mức các chuỗi khớp trong tên file, URL, chuỗi SQL~~ (đã xong).
3. **Build Java trước khi quét** (Maven/Gradle trong container) để CBOMkit chính xác hơn.
4. **Bảng tổng quan HTML một trang** cho buổi trình bày.
5. **Gửi bản sửa lên CryptoScan** (đã chọn cách mở PR; chờ anh chạy lệnh `gh pr create`): ngày 2026-11-02 đã quyết định đưa bản sửa symlink lên fork công khai và đưa repo này công khai. Từ lúc đó lỗ hổng coi như đã công khai, nên cần **báo ngay cho CSNP** (`disclosure/cryptoscan-symlink-report.md`), rồi mở PR từ fork cho cả hai commit.
6. **Thử trên một codebase lớn** để đo thời gian và mức nhiễu.
