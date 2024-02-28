const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookie = require('cookie');
const app = express();
const port = 3001;
const cors = require('cors');
app.use(cors({
    origin: 'http://localhost:3002',
    credentials: true
}));

// SQLite database initialization
const db = new sqlite3.Database('./simpleAuth.db', (err) => {
    if (err) {
        console.error(err.message);
    }
    console.log('Connected to the simpleAuth database.');
});

//after runing the server for the first time, comment out the following line to avoid creating the table again
// db.serialize(() => {
//     db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, password TEXT)");
// });

app.use(bodyParser.json());

// Register endpoint
app.post('/register', (req, res) => {
    const { name, password } = req.body;
    // console.log(req)

    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to hash password' });
        }

        db.run('INSERT INTO users (name, password) VALUES (?, ?)', [name, hashedPassword], (err) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to register user' });
            }
            res.status(201).json({ message: 'User registered successfully' });
        });
    });
});

// Login endpoint
app.post('/login', (req, res) => {
    const { name, password } = req.body;
    // console.log(req.body)
    db.get('SELECT * FROM users WHERE name = ?', [name], (err, row) => {
        if (err || !row) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        bcrypt.compare(password, row.password, (err, result) => {
            if (err || !result) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            const token = jwt.sign({ userId: row.id, name: row.name }, 'secret_key', { expiresIn: '1h' });

            // res.cookie('token', token);
            res.setHeader(
                "Set-Cookie",
                cookie.serialize("session", token || "", {
                    httpOnly: true,
                    // secure: false,
                    maxAge: 60 * 60,
                    // sameSite: "strict",
                    path: "/",
                })
            )
            res.status(200).json({ token });
        });
    });
});

// Middleware for JWT validation
function authenticateToken(req, res, next) {
    // const authHeader = req.headers['authorization'];
    const authHeader = req.headers?.cookie;
    console.log('authHeader', req.headers)
    // console.log('authHeader', req.cookies?.session)
    const token = authHeader && authHeader.split('=')[1];
    console.log('token', JSON.stringify(token))
    if (token == null) {
        return res.sendStatus(401);
    }

    jwt.verify(token, 'secret_key', (err, user) => {
        if (err) {
            return res.sendStatus(403);
        }
        req.user = user;
        next();
    });
}

// Sample protected route
app.get('/protected', authenticateToken, (req, res) => {
    res.status(200).json({ message: 'You are authorized' });
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
