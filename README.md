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

The token returned from register/login API is a short-life token, it is used for further token generation.

### Token-gen

Token-gen API takes a valid token and generate a new token, with specified age and data.

#### Request

```typescript
{
    appId: string;
    token: string;
    age: number;
    data: string;
}
```

### Response

```typescript
{
    ok: boolean;
    msg: string;
    token: string;
}
```

### Token-check

Token-check API only check if a token is valid, it does not return any data in the token.

#### Request

```typescript
{
    appId: string;
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

### Token-parse

Token-parse API verify the token and return the information contained in the token.

#### Request

```typescript
{
    appId: string;
    token: string;
}
```

### Response

```typescript
{
    ok: boolean;
    msg: string;
    data: string;
}
```
