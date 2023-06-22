# simple-auth

A dead simple true-false authentication gate, using JWT.

Why bother reinventing the wheel when you only want to know if a user is logged in?

## Introduction

This is a super lightweight authentication server, which only contains three APIs and uses a JSON file as its database. All it does is register new users, check the login password (BCrypt), and verify the JWT.

## Run

```shell
go mod download
go build .
./simple-auth
```

## APIs

### Register/Login

#### Request

```typescript
{
  username: string;
  password: string;
}
```

#### Response

```typescript
{
  ok: boolean;
  msg: string;
  token: string;
}
```

### Token

#### Request

```typescript
{
  token: string;
}
```

#### Response

```typescript
{
  ok: boolean;
  msg: string;
}
```
