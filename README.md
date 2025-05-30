===================ĐỌC KĨ HƯỚNG DẪN SỬ DỤNG TRƯỚC KHI DÙNG===================
1. Edit line 441: ExecStart=/usr/local/bin/microsocks -i 0.0.0.0 -p 1080 -u wg-tele -P 123456789
   User: wg-tele
   Pass: 123456789
   port: 1080
   Thay thành các thông số tùy thích.
2. Socks5 định dạng: IP:PORT với user và pass đã edit
3. Chỉ fw luồng của tele, các luồng khác giữ nguyên qua IP VPS
4. Mới test trên ubuntu 24.04
   
