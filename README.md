# SECURE_LAB_4
## Анализ в SonarCloud
![image](https://user-images.githubusercontent.com/87932748/200593896-511a71ff-1d04-4b25-97f5-6a52779b0f1b.png)
##  Анализ ошибок в коде
Значение GET параметра `id` никаким образом не проверяется перед добавление его в SQL запрос:
```php
  $id = $_GET[ 'id' ];
```
Оно записывается в переменную `$id`, далее с помощью этой переменной формируется запрос и успешно выполняется на стороне сервера:
```php
$getid  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
$result = mysqli_query($GLOBALS["___mysqli_ston"],  $getid );
```
Данный код уязвим к SQL-инъекциям

## Исправление ошибок в коде

1. Добавлено использование технология PDO (PHP Data Objects — расширение для PHP, предоставляющее разработчику универсальный интерфейс для доступа к различным базам данных)
2. Добавлено использование функции `is_numeric()` для проверки вводимого значения `id`
3. Добавлен код для защиты от CSRF атак. Теперь пользватель отправляет запрос с токеном, который не позволит выполнить поддельные запросы

Исправленный вариант: `fixed.php`

```php
if( isset( $_GET[ 'Submit' ] ) ) {
	checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ]);

	$id = $_GET[ 'id' ];
	if(is_numeric( $id )) {
		$data = $db->prepare( 'SELECT first_name, last_name FROM users WHERE user_id = (:id) LIMIT 1;' );
		$data->bindParam( ':id', $id, PDO::PARAM_INT );
		$data->execute();
		if( $data->rowCount() == 1 ) {
			$html .= '<pre>User ID exists in the database.</pre>';
		}
		else {
			header( $_SERVER[ 'SERVER_PROTOCOL' ] . ' 404 Not Found' );
			$html .= '<pre>User ID is MISSING from the database.</pre>';
		}
	}
}
generateNewSessionToken();
```

![image](https://user-images.githubusercontent.com/87932748/200596607-56f366d7-68c9-4fbc-9ddc-1806d28f65b8.png)
## Sql Map
Добавим в Burp новый адрес и порт прослушивания HTTP-пакетов.

![VirtualBox_Dojo-3 4 1_13_12_2022_02_37_25](https://user-images.githubusercontent.com/87932748/207287520-7cc3a151-977e-43ed-9225-e4ddf7271ca1.png)

В браузере укажем в качестве proxy-сервера выбранный ранее адрес и порт.

![VirtualBox_Dojo-3 4 1_13_12_2022_02_26_58](https://user-images.githubusercontent.com/87932748/207287579-6742d315-f96a-45d3-aa72-c477bc46baa1.png)

Отправим запрос в форму задания blind-injection, после чего в Burp сможем наблюдать перехваченный HTTP-пакет с заголовками.

![VirtualBox_Dojo-3 4 1_13_12_2022_02_37_25](https://user-images.githubusercontent.com/87932748/207287604-b5da090f-f2a3-4063-8bbc-9381bf44f6d5.png)

Воспользуемся утилитой SQLmap для поиска уязвимых параметров запроса. В результате поиска утилита выявила уязвимости типа boolean-based blind и time-based blind у параметра id.

![VirtualBox_Dojo-3 4 1_13_12_2022_02_59_28](https://user-images.githubusercontent.com/87932748/207287657-f21990e4-b4f7-4e60-b8b6-34f69ef7fdd0.png)

При помощи утилиты sqlmap получим список имеющихся баз данных.

![VirtualBox_Dojo-3 4 1_13_12_2022_03_00_09](https://user-images.githubusercontent.com/87932748/207287695-67686cfb-1678-4edf-8eb1-be1c86e69911.png)

При помощи утилиты sqlmap получим список имеющихся таблиц базы данных dvwa.

![VirtualBox_Dojo-3 4 1_13_12_2022_03_00_50](https://user-images.githubusercontent.com/87932748/207287734-1e8a2f74-8c00-40d2-a405-ff4c73746b0b.png)


При помощи утилиты sqlmap получим строки из таблицы users.

![VirtualBox_Dojo-3 4 1_13_12_2022_03_02_00](https://user-images.githubusercontent.com/87932748/207287767-761f610b-9650-4707-93e2-56d5645fb94b.png)

В ходе получения строк таблицы утилита sqlmap осуществила перебор паролей по имеющимся в таблице хэшам, в результате чего смогла определить пароли пользователей.

![image](https://user-images.githubusercontent.com/87932748/207287878-0e89f898-f1e8-40ea-b55f-f57956f55ea3.png)

## Burp
Включим перехват пакетов в Burp и осуществим отправку запроса в форме dvwa. В результате в Burp сможем наблюдать перехваченный HTTP-пакет.

![VirtualBox_Dojo-3 4 1_13_12_2022_03_06_13](https://user-images.githubusercontent.com/87932748/207287969-71d0ce18-53e2-4982-8560-fcaa56ec5182.png)

Изменим тело запроса, указав для параметра id значение 1 OR 1=1#.

![VirtualBox_Dojo-3 4 1_13_12_2022_03_07_23](https://user-images.githubusercontent.com/87932748/207288060-d86337c6-20a7-4a66-b09b-40e4f076449a.png)

В результате для каждого из имеющихся в базе данных значений id было возвращено true, и информация о всех пользователях, находящихся в таблице, помещена на странице сайта.

![VirtualBox_Dojo-3 4 1_13_12_2022_03_27_49](https://user-images.githubusercontent.com/87932748/207288103-a33f6329-8da7-45b8-87e9-039c62fc59b3.png)

Попробуем получить информацию об имеющихся в базе данных таблицах. Для этого в качестве значения для параметра id впишем 1 OR 1=1 UNION SELECT NULL,TABLE_NAME FROM INFORMATION_SCHEMA.TABLES#

![VirtualBox_Dojo-3 4 1_13_12_2022_03_29_34](https://user-images.githubusercontent.com/87932748/207288435-0cd361e1-30d3-40d0-862c-5d4dd13d100e.png)

В ответ на данный запрос, как и ожидалось, на странице отобразились все имеющиеся в базе данных таблицы.

![VirtualBox_Dojo-3 4 1_13_12_2022_03_29_47](https://user-images.githubusercontent.com/87932748/207288461-9b06be1c-8453-4832-ad67-f39c881ab679.png)

Наконец, попробуем получить логины и пароли пользователей, отправив запрос к таблице users: 1 OR 1=1 UNION SELECT USER,PASSWORD FROM users#.

![VirtualBox_Dojo-3 4 1_13_12_2022_03_30_42](https://user-images.githubusercontent.com/87932748/207288493-5217ee2d-ebed-4f96-9391-5159d30032f8.png)

В результате можем наблюдать полученные логины пользователей, а также захэшированные пароли.

![VirtualBox_Dojo-3 4 1_13_12_2022_03_30_47](https://user-images.githubusercontent.com/87932748/207288543-3be06953-0eae-4d02-a97e-af36a2f9dfac.png)



