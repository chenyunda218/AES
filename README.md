# AES
This is a home work for my college.
來源為 http://www.codedata.com.tw/social-coding/aes/，授權為 GNU GPL 授權。
本程式將來源程式擴充成5種加密模式
gcc AES.c -o aes.exe 編譯
參數說明
-f 輸入檔案 -o 輸出檔案 -k 密碼 -e 加密 -d 解密 -m 模式

                  範例
使用 key test 以ECB模式加密 test.7z 輸出為 out.en 
./aes.exe -f test.7z -o out.en -k test -e -m ECB
使用 key test 以ECB模式解密 out.en 輸出為 out.7z 
./aes.exe -f out.en -o out.7z -k test -d -m ECB
