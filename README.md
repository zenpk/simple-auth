# simple-auth

A dead simple true-false authentication gate, using JWT.

Why bother reinventing the wheel when you only want to know if a user is logged in?

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
