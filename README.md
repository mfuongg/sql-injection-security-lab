<p align="center">
  <img src="images/GD0.3.jpeg" width="50%">
</p>

<h1 align="center">
SQL Injection Security Lab
</h1>

<p align="center">
Mô phỏng tấn công SQL Injection và các cơ chế phòng thủ bằng Spring Boot & MySQL
</p>

## 👥THÀNH VIÊN

* Nguyễn Thị Thu Giang - 23010871
* Ngô Thị Minh Phương - 23012156
* Hoàng Vân Quỳnh - 23010836
* Nguyễn Bá Đức - 23010765

---

## 🛡️Giới thiệu

SQL Injection Security Lab là hệ thống mô phỏng tấn công và phòng chống SQL Injection được xây dựng bằng Spring Boot và MySQL.

Dự án được phát triển nhằm mục đích học tập, nghiên cứu và minh họa các lỗ hổng bảo mật phổ biến trong ứng dụng web, đồng thời cung cấp các cơ chế phòng thủ hiện đại giúp ngăn chặn các cuộc tấn công SQL Injection.

Người dùng có thể trực tiếp thực hành, quan sát và so sánh sự khác biệt giữa ứng dụng có lỗ hổng bảo mật (Vulnerable Mode) và ứng dụng đã được bảo vệ (Secure Mode).

---

## 🎯Mục tiêu của dự án

* Minh họa nguyên lý hoạt động của SQL Injection.
* Mô phỏng các hình thức tấn công phổ biến.
* So sánh giữa truy vấn không an toàn và truy vấn tham số hóa.
* Áp dụng các kỹ thuật bảo mật trong phát triển phần mềm.
* Hỗ trợ học tập môn An toàn và Bảo mật Hệ thống Thông tin.

---

## ✨Chức năng chính

### 🔐Đăng nhập hệ thống

* Xác thực người dùng.
* Phân quyền Admin và User.
* Mã hóa mật khẩu bằng BCrypt.
* Hỗ trợ chế độ Vulnerable và Secure.

---

### ⚔️Attack Lab

Môi trường thực hành SQL Injection cho phép:

* Bypass đăng nhập.
* Comment Injection.
* Boolean-Based Injection.
* UNION Injection.
* Kiểm tra kết quả tấn công.

Người dùng có thể so sánh trực tiếp:

* Vulnerable Mode.
* Secure Mode.

---

### 🛡️Security Workbench

Khu vực kiểm thử bảo mật với các chức năng:

* Phân tích payload SQL Injection.
* Đánh giá mức độ nguy hiểm.
* Mô phỏng các cuộc tấn công.
* So sánh cơ chế phòng thủ.

---

### 🔑SQL Injection Detector

Hệ thống phát hiện các chuỗi đầu vào nguy hiểm như:

* OR
* UNION
* SELECT
* DROP
* DELETE
* UPDATE

Mức độ đánh giá:

* SAFE
* WARNING
* DANGEROUS

---

### 📑Audit Logging

Ghi nhận toàn bộ hoạt động kiểm thử:

* Tài khoản sử dụng
* Địa chỉ IP
* Payload đầu vào
* Chế độ thực thi
* Thời gian thực hiện
* Kết quả kiểm thử

Hỗ trợ:

* Điều tra sự cố
* Theo dõi bảo mật
* Phân tích tấn công

---

### 📊Dashboard

Hiển thị tổng quan hệ thống:

* Số lượng lượt kiểm thử
* Số lần phát hiện tấn công
* Thống kê người dùng
* Thống kê sự kiện bảo mật

---

### 🧩Defense Matrix

Ma trận phòng thủ giúp người học hiểu các cơ chế bảo mật:

* Parameterized Query
* Password Hashing
* Input Validation
* Audit Logging
* Secure Authentication

---

### 📄Báo cáo PDF

Cho phép xuất:

* Security Test Report
* Audit Trail Report

---

## 🚀Công nghệ sử dụng

### Backend

* Java 17
* Spring Boot 3
* Spring Data JPA
* Hibernate

### Database

* MySQL 8

### Frontend

* Thymeleaf
* Bootstrap 5
* HTML5
* CSS3

### Bảo mật

* BCrypt Password Hashing
* Prepared Statement
* Parameterized Query
* Content Security Policy
* Security Headers

### Công cụ triển khai

* Maven
* Docker
* Docker Compose

---

## 🖥️Kiến trúc hệ thống

```text
Controller Layer
       ↓
Service Layer
       ↓
Repository Layer
       ↓
MySQL Database
```

Các package chính:

```text
src/main/java/com/example/sqlinjectiondemo

├── controller
├── service
├── repository
├── entity
├── model
├── security
└── config
```

---

## 🔒Thiết kế bảo mật

### Vulnerable Mode

Sử dụng truy vấn SQL ghép chuỗi trực tiếp.

Mục đích:

* Minh họa lỗ hổng SQL Injection.
* Thực hành tấn công trong môi trường an toàn.

---

### Secure Mode

Sử dụng:

* Prepared Statement
* Parameterized Query
* BCrypt Password Hashing
* Input Validation

Mục đích:

* Ngăn chặn SQL Injection.
* Áp dụng Secure Coding.

---

## 👤Tài khoản mẫu

### Quản trị viên

Tên đăng nhập:

admin

Mật khẩu:

123456

---

### Người dùng

Tên đăng nhập:

user

Mật khẩu:

123456

---

## ⚙️Hướng dẫn cài đặt

### Clone dự án

```bash
git clone https://github.com/mfuongg/sql-injection-security-lab.git
cd sql-injection-security-lab
```

---

### Tạo cơ sở dữ liệu

```sql
CREATE DATABASE sql_injection_demo;
```

---

### Import dữ liệu mẫu

```bash
mysql -u root -p sql_injection_demo < db/mysql_setup.sql
```

---

### Cấu hình kết nối MySQL

Mở file:

```properties
src/main/resources/application.properties
```

Ví dụ:

```properties
spring.datasource.url=jdbc:mysql://localhost:3306/sql_injection_demo
spring.datasource.username=root
spring.datasource.password=your_password
```

---

### Chạy ứng dụng

```bash
mvn clean spring-boot:run
```

Truy cập:

```text
http://localhost:8080
```

---

## 🐳Docker

Khởi chạy bằng Docker:

```bash
docker-compose up --build
```

---

## 📌Kết quả đạt được

* Xây dựng thành công hệ thống mô phỏng SQL Injection.
* Minh họa trực quan sự khác biệt giữa Vulnerable Mode và Secure Mode.
* Áp dụng BCrypt Password Hashing.
* Áp dụng Parameterized Query.
* Xây dựng hệ thống Audit Logging.
* Tích hợp Dashboard và báo cáo PDF.
* Hỗ trợ học tập và thực hành an toàn thông tin.

---

## 📌Hướng phát triển

* Tích hợp Spring Security.
* Bổ sung mô phỏng XSS.
* Bổ sung mô phỏng CSRF.
* Xây dựng REST API Security Lab.
* Mở rộng theo chuẩn OWASP Top 10.

---


## 📷Giao diện hệ thống

### Trang đăng nhập

<p align="center">
  <img src="images/GD11.jpeg" width="80%">
</p>

### Dashboard

<p align="center">
  <img src="images/GD1.jpeg" width="80%">
</p>

### Attack Lab

<p align="center">
  <img src="images/GD2.jpeg" width="80%">
</p>

### Security Workbench

<p align="center">
  <img src="images/GD4.jpeg" width="80%">
</p>

### Audit Logs

<p align="center">
  <img src="images/GD8.jpeg" width="80%">
</p>

### Defense Matrix

<p align="center">
  <img src="images/GD5.jpeg" width="80%">
</p>

### Quản lý người dùng

<p align="center">
  <img src="images/GD7.jpeg" width="80%">
</p>
