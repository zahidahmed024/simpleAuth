const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookie = require('cookie');
const cors = require('cors');

const app = express();
const port = 3001;

app.use(cors({
    origin: 'http://localhost:3000',
    credentials: true
}));

app.use(bodyParser.json());

// SQLite database initialization
const db = new sqlite3.Database('./simpleAuth.db', (err) => {
    if (err) {
        console.error(err.message);
    }
    console.log('Connected to the simpleAuth database.');
});

// Uncomment this if running for the first time
// db.serialize(() => {
//     db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, password TEXT, refreshToken TEXT)");
// });

// 🔹 **Utility functions**
const generateAccessToken = (user) => {
    return jwt.sign({ userId: user.id, name: user.name }, 'access_secret_key', { expiresIn: '15m' });
};

const generateRefreshToken = (user) => {
    return jwt.sign({ userId: user.id, name: user.name }, 'refresh_secret_key', { expiresIn: '7d' });
};

// 🔹 **Register Route**
app.post('/register', (req, res) => {
    const { name, password } = req.body;

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

// 🔹 **Login Route**
app.post('/login', (req, res) => {
    console.log(req.body)
    const { name, password } = req.body;
    db.get('SELECT * FROM users WHERE name = ?', [name], (err, user) => {
        if (err || !user) {
            return res.status(422).json({ error: 'Invalid credentials' });
        }

        bcrypt.compare(password, user.password, (err, result) => {
            if (err || !result) {
                return res.status(422).json({ error: 'Invalid credentials' });
            }

            const accessToken = generateAccessToken(user);
            const refreshToken = generateRefreshToken(user);

            // Store refresh token in DB
            db.run('UPDATE users SET refreshToken = ? WHERE id = ?', [refreshToken, user.id]);

            // Set refresh token as HTTP-only cookie
            // res.setHeader('Set-Cookie', cookie.serialize('refreshToken', refreshToken, {
            //     httpOnly: true,
            //     secure: false, // Change to true in production (HTTPS)
            //     sameSite: 'strict',
            //     path: '/'
            // }));

            res.status(200).json({ accessToken, refreshToken });
        });
    });
});

// 🔹 **Middleware for JWT Validation**
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.sendStatus(401);
    }

    jwt.verify(token, 'access_secret_key', (err, user) => {
        if (err) {
            return res.sendStatus(403);
        }
        req.user = user;
        next();
    });
}

// 🔹 **Refresh Token Route**
app.post('/refresh', (req, res) => {
    const cookies = req.headers?.cookie;
    const refreshToken = cookies && cookies.split('refreshToken=')[1];

    if (!refreshToken) {
        return res.sendStatus(401);
    }

    db.get('SELECT * FROM users WHERE refreshToken = ?', [refreshToken], (err, user) => {
        if (err || !user) {
            return res.sendStatus(403);
        }

        jwt.verify(refreshToken, 'refresh_secret_key', (err, decoded) => {
            if (err) {
                return res.sendStatus(403);
            }

            const accessToken = generateAccessToken(user);
            res.status(200).json({ accessToken });
        });
    });
});

// 🔹 **Logout Route**
app.post('/logout', (req, res) => {
    const cookies = req.headers?.cookie;
    const refreshToken = cookies && cookies.split('refreshToken=')[1];

    if (!refreshToken) {
        return res.sendStatus(204);
    }

    // Remove refresh token from DB
    db.run('UPDATE users SET refreshToken = NULL WHERE refreshToken = ?', [refreshToken], () => {
        // res.setHeader('Set-Cookie', cookie.serialize('refreshToken', '', {
        //     httpOnly: true,
        //     secure: false, // Change to true in production
        //     sameSite: 'strict',
        //     path: '/',
        //     expires: new Date(0) // Expire immediately
        // }));
        res.sendStatus(204);
    });
});

// 🔹 **Protected Route Example**
app.get('/protected', authenticateToken, (req, res) => {
    res.status(200).json({ message: 'You are authorized' });
});

// 🔹 **Start Server**
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
