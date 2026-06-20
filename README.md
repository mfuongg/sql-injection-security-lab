<p align="center">
  <img src="images/GD0.3.jpeg" width="50%">
</p>

<h1 align="center">
SQL Injection Security Lab
</h1>

<p align="center">
Mô phỏng tấn công SQL Injection và các cơ chế phòng thủ bằng Spring Boot & MySQL
</p>


## 👥 THÀNH VIÊN

* Nguyễn Thị Thu Giang - 23010871
* Ngô Thị Minh Phương - 23012156
* Hoàng Vân Quỳnh - 23010836
* Nguyễn Bá Đức - 23010765

---

# 🛡️ Giới thiệu dự án

**SQL Injection Security Lab** là một hệ thống mô phỏng môi trường học tập về bảo mật ứng dụng Web, tập trung vào việc phân tích lỗ hổng **SQL Injection** và triển khai các cơ chế phòng thủ an toàn.

Dự án được xây dựng bằng **Spring Boot + MySQL**, cho phép người dùng:

* Thực hiện mô phỏng các cuộc tấn công SQL Injection.
* Quan sát sự khác biệt giữa truy vấn không an toàn và truy vấn bảo mật.
* Kiểm tra khả năng phát hiện payload nguy hiểm.
* Theo dõi nhật ký bảo mật.
* Đánh giá mức độ an toàn của hệ thống.

Mục tiêu chính của hệ thống là hỗ trợ học tập môn **An toàn thông tin / Bảo mật hệ thống thông tin**, giúp người học hiểu rõ cách một ứng dụng Web có thể bị khai thác và cách xây dựng hệ thống phòng thủ.

---

# 🎯 Mục tiêu dự án

* Minh họa nguyên lý hoạt động của SQL Injection.
* Mô phỏng các dạng tấn công phổ biến.
* So sánh Vulnerable Mode và Secure Mode.
* Áp dụng Secure Coding trong phát triển Web.
* Xây dựng hệ thống đánh giá và giám sát bảo mật.
* Hỗ trợ thực hành theo hướng OWASP.

---

# ✨ Chức năng hệ thống

## 🔐 Authentication System

Chức năng đăng nhập hệ thống:

* Đăng nhập User/Admin.
* Quản lý phiên đăng nhập.
* Mã hóa mật khẩu bằng BCrypt.
* Kiểm tra bảo mật thông tin tài khoản.
* Hỗ trợ xác thực hai bước (Two Factor Authentication).

---

# ⚔️ Attack Lab

Môi trường mô phỏng SQL Injection.

Bao gồm:

### Login Bypass

Mô phỏng tấn công vượt qua xác thực bằng payload SQL Injection.

Ví dụ:

```
' OR '1'='1
```

---

### Boolean Based Injection

Kiểm tra phản hồi ứng dụng dựa trên điều kiện SQL đúng/sai.

---

### UNION Injection

Mô phỏng truy vấn UNION nhằm khai thác dữ liệu.

---

### Vulnerable Mode

Sử dụng truy vấn SQL không an toàn nhằm minh họa lỗ hổng.

---

### Secure Mode

Áp dụng:

* Prepared Statement.
* Parameterized Query.
* Input Validation.

Nhằm ngăn chặn SQL Injection.

---

# 🛡️ Security Workbench

Khu vực kiểm thử bảo mật với các chức năng:

* Phân tích payload.
* Kiểm tra mức độ nguy hiểm.
* Mô phỏng hành vi tấn công.
* Kiểm tra file.
* Đánh giá cơ chế bảo vệ.

---

# 🔍 SQL Injection Detector

Hệ thống phát hiện các mẫu truy vấn nguy hiểm:

* SELECT
* UNION
* OR
* DROP
* DELETE
* UPDATE

Kết quả đánh giá:

| Mức độ    | Ý nghĩa                      |
| --------- | ---------------------------- |
| SAFE      | Không phát hiện nguy hiểm    |
| WARNING   | Có dấu hiệu bất thường       |
| DANGEROUS | Payload có khả năng tấn công |

---

# 📋 Audit Logging

Hệ thống lưu lại toàn bộ hoạt động bảo mật:

Thông tin ghi nhận:

* Người dùng.
* IP truy cập.
* Payload gửi lên.
* Loại kiểm thử.
* Thời gian.
* Kết quả.

Ứng dụng:

* Theo dõi sự cố.
* Điều tra tấn công.
* Phân tích hành vi.

---

# 📊 Dashboard

Dashboard hiển thị:

* Tổng số lượt kiểm thử.
* Số lượng cảnh báo bảo mật.
* Thống kê người dùng.
* Thống kê log.
* Tổng quan trạng thái hệ thống.

---

# 🧩 Defense Matrix

Ma trận phòng thủ giúp so sánh các kỹ thuật bảo mật:

Bao gồm:

* Parameterized Query.
* Password Hashing.
* Input Validation.
* Secure Authentication.
* Audit Logging.

---

# 🖥️ SOC Mini Dashboard

Hệ thống hỗ trợ mô phỏng giám sát bảo mật:

Chức năng:

* Theo dõi sự kiện.
* Hiển thị cảnh báo.
* Phân tích log.
* Quan sát hoạt động đáng ngờ.

---

# 📄 Báo cáo bảo mật PDF

Hệ thống hỗ trợ tạo báo cáo:

* Security Assessment Report.
* Audit Trail Report.

Báo cáo phục vụ việc:

* Đánh giá hệ thống.
* Lưu trữ kết quả kiểm thử.

---

# 🚀 Công nghệ sử dụng

## Backend

* Java 17
* Spring Boot 3.3.1
* Spring MVC
* Spring Data JPA
* Hibernate

## Database

* MySQL 8.4

## Frontend

* Thymeleaf
* HTML5
* CSS3
* Bootstrap

## Security

* BCrypt Password Hashing
* Prepared Statement
* Parameterized Query
* Input Validation
* Security Logging

## Tools

* Maven
* Docker
* Docker Compose
* JUnit Test

---

# 🏗️ Kiến trúc hệ thống

```
Browser
   |
Controller Layer
   |
Service Layer
   |
Repository Layer
   |
MySQL Database
```

Cấu trúc package:

```
src/main/java/com/example/sqlinjectiondemo

├── controller
├── service
├── repository
├── entity
├── model
├── config
└── security
```

---

# 🔒 Cơ chế bảo mật

## Vulnerable Mode

Mục đích:

* Minh họa SQL Injection.
* Cho phép thực hành khai thác trong môi trường an toàn.

---

## Secure Mode

Giải pháp:

* Prepared Statement.
* Parameter Binding.
* BCrypt.
* Validation.

Mục tiêu:

* Bảo vệ dữ liệu.
* Ngăn chặn truy vấn độc hại.

---

# 👤 Tài khoản mẫu

## Admin

```
username:
admin

password:
123456
```

## User

```
username:
user

password:
123456
```

---

# ⚙️ Cài đặt

## Clone repository

```bash
git clone https://github.com/mfuongg/sql-injection-security-lab.git

cd sql-injection-security-lab
```

---

# 🐳 Chạy bằng Docker

```bash
docker-compose up --build
```

Sau khi chạy:

```
http://localhost:8080
```

---

# 🗄️ Database

Database mặc định:

```
sql_injection_demo
```

Docker tự động import:

```
db/mysql_setup.sql
```

---

# 🧪 Kiểm thử

Chạy test:

```bash
mvn test
```

---

# 📌 Kết quả đạt được

* Xây dựng thành công môi trường mô phỏng SQL Injection.
* Minh họa Vulnerable và Secure Mode.
* Triển khai cơ chế bảo vệ SQL Injection.
* Xây dựng hệ thống phát hiện payload.
* Ghi nhận log bảo mật.
* Tạo báo cáo PDF.
* Hỗ trợ học tập và nghiên cứu bảo mật Web.

---

# 🔮 Hướng phát triển

Trong tương lai có thể mở rộng:

* Tích hợp Spring Security đầy đủ.
* Bổ sung XSS Lab.
* Bổ sung CSRF Lab.
* API Security Testing.
* Tích hợp OWASP ZAP.
* Xây dựng hệ thống SIEM mini.

---

# 📷 Giao diện hệ thống

## Login

<p align="center">
<img src="images/GD11.jpeg" width="80%">
</p>

## Dashboard

<p align="center">
<img src="images/GD1.jpeg" width="80%">
</p>

## Attack Lab

<p align="center">
<img src="images/GD2.jpeg" width="80%">
</p>

## Security Workbench

<p align="center">
<img src="images/GD4.jpeg" width="80%">
</p>

## Audit Logs

<p align="center">
<img src="images/GD8.jpeg" width="80%">
</p>

## Defense Matrix

<p align="center">
<img src="images/GD5.jpeg" width="80%">
</p>

## User Management

<p align="center">
<img src="images/GD7.jpeg" width="80%">
</p>
