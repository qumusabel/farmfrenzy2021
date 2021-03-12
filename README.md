#  Инженерная задача по Информационной безопасности НТИ 2021 | Весёлая Ферма

## Задача
 На финальном мероприятии нам дали задание, суть которого была в том, что нам нужно было защитить подвергшийся атаке телецентр, выявить наибольшее количество уязвимых мест, разработать способы устранения атак, а также найти и обезвредить вредонос. 
 
## Вход во внутреннюю сеть

### ?

Сначала было произведено сканирование портов, найдены следующие:
```
| Порт | Прот. | Описание | |——-|——-|——————————————–| | 81 | HTTP | Хостит обфусцированный файл run.py | | 5000 | HTTP | Веб-приложение, сайт провайдера (?) NetGen | | 8037 |      UDP? | Открыт, но не отвечает | | 51515 | TCP | Какой-то сервис, просит пароль |
```
На сервисе NetGen есть страницы /register, /login, /logout Регистрируем пользователя, доступна функция создания тикетов. В параметре POST title обнаружена SSTI (предположительно, Jinja2) Некоторые ключевые слова фильтруются, причем необязательно в составе пейлоада (например, config)

Далее нами было получено SSTI RCE в сервисе на :5000
![kts](https://user-images.githubusercontent.com/67109334/110940347-cf5fa280-8347-11eb-917d-432bcbc26336.png)


### server.py:224 status_route() Possible RCE, weak filter

#### Решение:
>Использовать whitelist вместо blacklist, разрешать только опции к команде uptime
```
└─$ diff ../app/server.py server.py                                                           
224c224,226
&lt;     bad_words = ['whoami', 'id', 'python', 'php', 'bash'] #hacker shouldn't pass
---
&gt;     # Разрешить только опции к команде uptime: 
&gt;     good_words = ['-p', '--pretty', '-h', '--help', '-s', '--since', '-V', '--version']
&gt; 
227,228c229,230
&lt;         for i in bad_words:
&lt;             if i in req:
---
&gt;         for token in req.split():
&gt;             if token not in good_words:
229a232
```

* Создать пользователя " || "admin : passwd
* Войти как || "admin : admin <— слабая парольная политика!
* Перейти на /dialog?u=? -> слив диалога
* Если поменять " || "admin‘s passwd, то поменяется пароль самого админа
* Патч: использовать правильные методы к базе данных с экранированием, использовать экранирование

Улучшить парольные политики

### Взлом run.py на хосте :81

#### Сначала деобфусцируем скрипт:
>
- Упростим имена, переименуем все в более понятный вид
- Упростим hex-строки, получается encode, unhexlify и прочее
- Избавимся от непонятных вызовов locals(), getattr():
  - getattr(binascii, 'unhexlify')(...) 
  - binascii.unhexlify(...)
  - locals['somefunc'](..., ...) 
  - somefunc(..., ...)
- Последний шаг – избавимся от списков чисел. Можно заметить, что они используюстя только как аругмент к somefunc, при этом функция похожа на шифр Виженера. Для того, чтобы получить оригинальные строки, просто вызовем функцию с нужными аргументами. Выясняется, что большой список в начале файла – это зашифрованный приватный ключ RSA.

#### Алгоритм:

* Загрузить ключ RSA
* Получить hex-строку от пользователя
* Расшифровать строку
* Проверить соответствие с заданной строкой, если совпадают – вывести ~~флаг~~ важную информацию

#### Исследование:

>Приватный ключ дан почти в открытом виде, зашифруем с помощью него требуемую строку, затем подключимся к серверу на порту :51515, нас попросят ввести hex, отправим шифротекст, в ответ прилетит зашифрованная информация. С помощью скрипта и коюча ее расшифруем, получим сообщение с данными для входа во внутреннюю сеть

![kts](https://user-images.githubusercontent.com/67109334/110939654-cc17e700-8346-11eb-896b-367f495ac99b.png)

### SQLi №1

В ходе тестирования на проникновение, «Веселая ферма» смоделировала возможные действия злоумышленника на сайте телецентра “Sirius Game” и выявила возможность проведения атаки типа SQLi. Данная уязвимость даёт злоумышленнику возможность получения конфиденциальной информации пользователей, а именно переписок в личных диалогах.

Далее представлена некоторая техническая информация.

Для эксплуатации описанной выше уязвимости, необходимо послать GET запрос на страницу ```/dialog.``` В качестве уязвимого параметра используется ```‘u’```, в функционале сервиса он необходим для указания собеседника, переписку с которым необходимо загрузить.

Полезной нагрузкой в данном векторе атаки может быть ```" or "1" = "1" --```, однако не отрицаются другие варианты эксплуатирования данной уязвимости. Уязвимость расположена в функции ```get_dialog()``` и устраняется безопасной передачей аргументов в SQL-запрос:
```
└─$ diff server.py patched_sqli.py                                    
257c257
&lt;     c.execute('SELECT * FROM messages where to_user="' + username + '" and from_user="' + companion + '" or to_user="' + companion + '" and from_user="' + username + '"')                                                                    
---
&gt;     c.execute('SELECT * FROM messages where to_user=(?) and from_user=(?) or to_user=(?) and from_user=(?)', (username, companion, companion, username))
```

### :80 server

Это бинарь на  Golang. Let’s try to connect using clientScript.py. The server doesn’t seem to respond to our messages, which means we have to reverse the binary.

Используем IDA Free 7.0. Основной код  начинается с main_:

func	description
main.main	init function. Starts the server
main.server	server func
main.listAllKeys	lists all keys in the redis db
main.RedisTestConnection	puts test:connection into db, then gets it
main.RedisCreateUsers	creates admin user entry in the db
main.checkForExistence	checks if the user already exists
main.createMd5Password	returns random md5 password string
main.asyncHandleConnections	handles connections
main.readAndEncode	utility function
![kts](https://user-images.githubusercontent.com/67109334/110940047-5a8c6880-8347-11eb-9145-a3bff40562fa.png)
in main.main os.Setenv is called with the arguments ("ADMIN_PASS", "de4ea1a59bb6df9d2f6ddc61cc28ce29"). This is clearly the admin’s password. The envvar is then referenced in main.RedisCreateUsers, which puts admin:ADMIN_PASS into redis db.

Теперь мы можем.

![kts](https://user-images.githubusercontent.com/67109334/110940183-8dcef780-8347-11eb-80f0-e22d9b207303.png)
main.asyncHandleConnections is a big function, but it is quite easy to understand if you find all the strings used in it, which are:

^/register [0-9A-Za-z]{3,8}
/showall
/login
/logout
/get_screen
The logic for detecting the last two is not straightforward, so we just had to deduce.

Let’s try

/login admin de4ea1a59bb6df9d2f6ddc61cc28ce29
/get_screen
A very long base64 string is printed. Copying it from terminal doesn’t quite work, so let’s automate the interaction:

from pwn import remote

r = remote("195.19.98.103", 8037)
r.sendline("/login admin de4ea1a59bb6df9d2f6ddc61cc28ce29")
r.recv()
r.sendline("/get_screen")

data = r.recvuntil("==") # sadly no \n
from base64 import b64decode

with open("screeen.jpeg", "wb") as f:
    f.write(b64decode(data))
![kts](https://user-images.githubusercontent.com/67109334/110940251-a50de500-8347-11eb-8f00-64d13faa5db7.png)
After running the script we get an image with the instrunction on how to connect to the internal network.




### SQLi №2
В ходе тестирования на проникновение «Веселая ферма» смоделировала возможные действия злоумышленника на сайте телецентра “Sirius Game” и выявила возможность проведения атаки типа SQLi. Данная уязвимость даёт злоумышленнику возможность смены пароля любого пользователя, в том числе администратора.

Далее представлена некоторая техническая информация.

Для эксплуатации описанной выше уязвимости, необходимо зарегистрировать аккаунт с логином ```[username]"--```, где username это логин атакуемого пользователя, например ```admin"--```. Следующим шагом, необходимо сменить пароль созданного пользователя воспользовавшись функционалом ```/change_passwd```. После выполнения этих шагов, злоумышленник получает доступ к аккаунту атакуемого пользователя и может войти в систему с данными ```[username]:[new password]```

Уязвимость расположена в функции ```change_user_passwd()``` и устраняется безопасной передачей аргументов в SQL-запрос:
```
└─$ diff server.py patched_sqli.py 
257c257
&lt;         c.execute('UPDATE staff set password=(?) where username="' + session[0] + '"', (password, ))                                                          
---
&gt;         c.execute('UPDATE staff set password=(?) where username=(?)', (password, session[0])) 
```

## Патчи

### XML XXE

Используя такую нагрузку как ```<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>```, мы можем читать любой файл на сервере. Но это нельзя сделать через пользовательский интерфейс, поэтому нам придется делать прямой POST-запрос или добавить кнопку на страницу в нашем браузере.

Также мы можем создать скрипт, который автоматически скачивает файлы с сервера и выводит его в консоль.

Патч: изменить параметр в XMLParser.parse() в server.py, который закроет уязвимость
