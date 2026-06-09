# FileShareExpert

Простейший файлообменник на C# (ASP.NET Core + SQLite) с:

- регистрацией пользователя;
- cookie-сессией и CSRF-защитой;
- загрузкой, скачиванием, списком, удалением и переименованием файлов;
- шарингом файла по ссылке;
- белым списком пользователей для ограничения доступа к ссылке.

## Что реализовано

### Авторизация и пользователи

- `POST /api/auth/register` - регистрация
- `POST /api/auth/login` - логин, устанавливает cookie-сессию
- `POST /api/auth/logout` - выход
- `GET /api/auth/me` - текущий пользователь и CSRF-токен

Для защищённых методов используется cookie `fs_token`.
Для изменяющих запросов (`POST/PUT/DELETE`) нужен заголовок `X-CSRF-Token`.

### Файлы

- `POST /api/files/upload` - загрузка файла (multipart/form-data, поле `file`)
- `GET /api/files` - список ваших файлов
- `GET /api/files/{id}/download` - скачать свой файл
- `DELETE /api/files/{id}` - удалить файл
- `PUT /api/files/{id}/rename` - переименовать файл

### Шаринг и белый список

- `POST /api/files/{id}/share` - создать/получить ссылку на файл
- `DELETE /api/files/{id}/share` - отключить ссылку
- `GET /api/share/{token}` - скачать файл по ссылке
- `POST /api/files/{id}/whitelist` - добавить пользователя в белый список
- `DELETE /api/files/{id}/whitelist/{username}` - удалить пользователя из белого списка
- `GET /api/files/{id}/whitelist` - посмотреть белый список

Если белый список пустой, доступ по ссылке открыт всем.
Если в белом списке есть пользователи, скачать смогут только владелец или пользователь из белого списка (с авторизацией).

## Запуск в VS Code

## 1) Открыть проект

Откройте в VS Code папку:

`Users/123/FileShareExpert`

## 2) Установить .NET SDK

Нужен .NET 8 SDK:  
[https://dotnet.microsoft.com/download/dotnet/8.0](https://dotnet.microsoft.com/download/dotnet/8.0)

Проверка:

```bash
dotnet --version
```

## 3) Запуск через F5 (рекомендуется)

1. В VS Code откройте вкладку Run and Debug.
2. Выберите конфигурацию `.NET Launch FileShareExpert`.
3. Нажмите `F5`.

Приложение стартует на:

[http://localhost:5071](http://localhost:5071)

Веб-интерфейс доступен на главной странице:

[http://localhost:5071/](http://localhost:5071/)

Проверка здоровья API:

[http://localhost:5071/api/health](http://localhost:5071/api/health)

## 4) Запуск через терминал VS Code

```bash
dotnet restore
dotnet run --project FileShareExpert.csproj
```

После запуска откройте в браузере `http://localhost:5071/`.

## 5) Запуск тестов

```bash
dotnet test FileShareExpert.Tests/FileShareExpert.Tests.csproj
```

Покрыты основные сценарии: регистрация/логин, `me`, upload/list/download/rename/delete, share, whitelist и проверка CSRF.

## Где хранятся данные

- База SQLite: `storage/fileshare.db`
- Загруженные файлы: `storage/uploads/`

## Мини-пример использования (через Postman/Insomnia)

1. Зарегистрировать двух пользователей.
2. Войти одним из них и получить cookie-сессию + CSRF-токен.
3. Загрузить файл (`/api/files/upload`).
4. Создать ссылку (`/api/files/{id}/share`).
5. Добавить второго пользователя в белый список (`/api/files/{id}/whitelist`).
6. Открыть ссылку `/api/share/{token}`:
   - без токена - будет отказ, если белый список не пустой;
   - с токеном добавленного пользователя - файл скачается.
