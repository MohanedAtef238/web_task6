This is a basic Express.js API implementing JWT-based authentication and authorization, role management, and profile handling — all in-memory, without a database.

## Setup

1. Clone or download this repository.
2. Install dependencies:

```bash
npm install
```

3. include the `.env` i provided in the submission or create one of ur own with port and jwt_secret fields


4. Run the server:

```bash
node server.js
```

## Endpoints

### Public

- `GET /api/public` – Open to all roles of users

### Auth

- `POST /api/register` – Register a new user.
  - Body: `{ "username": "...", "email": "...", "password": "...", "role": "user|admin|moderator" }`
- `POST /api/login` – Login and receive JWT token.
  - Body: `{ "username": "...", "password": "..." }`

### Protected (requires JWT)

- `GET /api/profile` – Get logged-in user's info (username, email, role).
- `PUT /api/profile` – Update user's own email or password.
  - Body: `{ "email": "...", "password": "..." }`

### Non user role endpoints

- `GET /api/admin` – Admin-only route.
- `GET /api/moderator` – Admin and moderator access.

### Admin-only Actions

- `PUT /api/users/:id/role` – Update another user's role.
  - Body: `{ "role": "admin|moderator|user" }`

## How to Test

Use  Postmanor to test the endpoints

### Example Flow:

1. **Register a user** via `POST /api/register`
2. **Login** with the same credentials using `POST /api/login`
3. Copy the JWT token from the login response.
4. Use the token in `Authorization` header for protected routes:

```
Authorization: Bearer <your_token_here>
```

5. Try accessing `/api/profile`, `/api/admin`, etc.



this was made with love and dramatic commenting and just a sprinkle of 😱