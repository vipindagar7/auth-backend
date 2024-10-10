
# APP_NAME

## API Endpoints for Authentication

---

### 1. Sign Up

**POST**: `/api/auth/signup`

- **URL**: `http://localhost:4000/api/auth/signup`
- **Body** (raw JSON):

```json
{
  "name": "vipin dagar",
  "email": "vdagar@gitam.in",
  "password": "21"
}
```

---

### 2. Verify Email

**POST**: `/api/auth/verify/:token`

- **URL**: `http://localhost:4000/api/auth/verify/a95ce96a-2d99-4877-845e-24c61e877202`

---

### 3. Login

**POST**: `/api/auth/login`

- **URL**: `http://localhost:4000/api/auth/login`
- **Body** (raw JSON):

```json
{
  "email": "dagarv23@gmail.com",
  "password": "dagar"
}
```

---

### 4. Get User Details

**POST**: `/api/auth/getUser`

- **URL**: `http://localhost:4000/api/auth/getUser`
- **Authorization**: Bearer Token

```
Token: <token>
```

---

### 5. Change Password Request

**POST**: `/api/auth/changePassword`

- **URL**: `http://localhost:4000/api/auth/changePassword`
- **Authorization**: Bearer Token

```
Token: <token>
```

- **Body** (raw JSON):

```json
{
  "password": "21",
  "newPassword": "s31",
  "email": "dagarv23@gsmail.com"
}
```

---

### 6. Register Reset Password Request

**POST**: `/api/auth/forgotPassword`

- **URL**: `http://localhost:4000/api/auth/forgotPassword`
- **Body** (raw JSON):

```json
{
  "email": "dagarv23@gmail.com"
}
```

---

### 7. Forgot Password

**POST**: `/api/auth/forgotPassword/:token`

- **URL**: `http://localhost:4000/api/auth/forgotPassword/jhuhknjh`

---

### 8. Refresh Access Token

**POST**: `/api/auth/refreshToken`

- **URL**: `http://localhost:4000/api/auth/refreshToken`
- **Body** (raw JSON):

```json
{
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY2ZmQxNTEwYzJhNjc5ODhkNGJjYWRhYyIsImVtYWlsIjoiZGFnYXJ2MjNAZ21haWwuY29tIiwiaWF0IjoxNzI4MjE3NTgxLCJleHAiOjE3MjgyMTc2NDF9.RCZRnc-2mlW4CWQJ0ztUpx0k_4WWJrryxEdMWn3fOWY"
}
```

---

### 9. Logout

**POST**: `/api/auth/logout`

- **URL**: `http://localhost:4000/api/auth/logout`
- **Authorization**: Bearer Token

```
Token: <token>
```

---

