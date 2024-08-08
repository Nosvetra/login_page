# LogIn Page

This is a basic login/register page for my project. It uses many npm packages such as -:

- "bcrypt": "^5.1.1",
- "body-parser": "^1.20.2",
- "dotenv": "^16.4.5",
- "ejs": "^3.1.10",
- "express": "^4.19.2",
- "express-session": "^1.18.0",
- "passport": "^0.7.0",
- "passport-local": "^1.0.0",
- "pg": "^8.12.0"

## Environment Variables

To run this project, you will need to add the following environment variables to your .env file

`EXPRESS_PORT`

`PG_USER`

`PG_HOST`

`PG_DATABASE`

`PG_PASSWORD `

`PG_PORT`

`SESSION_SECRET`

## Run Locally

Clone the project

```bash
  git clone https://github.com/Nosvetra/login_page.git
```

Go to the project directory

```bash
  cd my-project
```

Install dependencies

```bash
  npm install
```

Start the server

```bash
  node index.js
```
