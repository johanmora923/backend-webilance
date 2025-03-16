import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import mysql from 'mysql2/promise';
import cookieParser from 'cookie-parser';
import bcryptjs from "bcryptjs";
import Jsonwebtoken from 'jsonwebtoken';

dotenv.config();

export const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
});

const app = express();
app.set("port", 3000);
app.listen(app.get("port"));
console.log("servidor corriendo", app.get("port"));

// Configuración de CORS
const corsOptions = {
    origin: "https://webfrilance.vercel.app",// Permitir solicitudes desde estos orígenes
    methods: "GET, POST", // Métodos permitidos
    credentials: true, // Permitir el uso de cookies
};

app.use(cors(corsOptions));

app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "https://webfrilance.vercel.app");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.setHeader("Access-Control-Allow-Credentials", "true");
    if (req.method === "OPTIONS") {
        return res.sendStatus(204); // Respuesta rápida para solicitudes preflight
    }
    next();
});

app.use(express.json());
app.use(cookieParser());

app.get("/comments", async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM comments');
        res.json(rows);
    } catch (error) {
        console.error(error);
        res.status(500).send('Error al obtener los comentarios');
    }
});

app.post("/comments", async (req, res) => {
    const { user, comment, rating } = req.body;

    if (!user || !comment || !rating) {
        return res.status(400).send('Por favor, proporciona usuario, comentario y calificación');
    }

    try {
        const result = await pool.query(
            'INSERT INTO comments (user, comment, rating, created_at) VALUES (?, ?, ?, ?)',
            [user, comment, rating, new Date()]
        );
        res.status(201).json({ message: 'Comentario agregado exitosamente', id: result.insertId });
    } catch (error) {
        console.error(error);
        res.status(500).send('Error al guardar el comentario');
    }
});

app.post("/register", async (req, res) => {
    const { name, email, password } = req.body;
    console.log(req.body);

    if (!name || !email || !password) {
        return res.status(400).json({ message: "Name, email, and password are required" });
    }

    try {
        const [users] = await pool.query("SELECT * FROM users WHERE name = ? OR email = ?", [name, email]);

        if (users.length > 0) {
            return res.status(400).json({ message: "User or email already exists" });
        }

        // Hash password
        const salt = await bcryptjs.genSalt(10);
        const hashPassword = await bcryptjs.hash(password, salt);

        // Insert user into database
        await pool.query("INSERT INTO users (name, password, email) VALUES (?, ?, ?)", [name, hashPassword, email]);

        return res.status(201).json({ message: "User registered successfully" });
    } catch (error) {
        console.error("Error during registration:", error);
        return res.status(500).json({ message: "Internal server error" });
    }
});

app.post("/login", async (req, res) => {

    const { name, password } = req.body;

    console.log(req.body)

    if (!name || !password) {
        return res.status(400).json({ message: "user and password are required" });
    }
    try {
        const [users] = await pool.query("SELECT * FROM users WHERE name = ?", [name]);
        const userDB = users[0];
        if (users.length === 0) {
            return res.status(401).json({ message: "Incorrect credentials 1" });
        }
        const loginSuccessful = await bcryptjs.compare(password, userDB.password);

        if (!loginSuccessful) {
            return res.status(401).json({ message: "Incorrect credentials 2" });
        }

        // Generate token
        const token = Jsonwebtoken.sign(
            { user: userDB.name },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRATION }
        );

        // Set token as cookie
        res.cookie("jwt", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production", // Use secure cookies in production
            sameSite: "Lax",
            maxAge: 7 * 24 * 60 * 60 * 1000 // 1 week
        });

        return res.status(200).json({
            message: "Login successful",
            id: userDB.id_user,
            user: userDB.name
        });
    } catch (error) {
        console.error("Error during login:", error);
        return res.status(500).json({ message: "Internal server error", error });
    }
});

// Verificar sesión
app.get("/session", (req, res) => {
    const token = req.cookies.jwt;

    if (!token) {
        return res.status(401).json({ message: "No autenticado" });
    }

    try {
        const decoded = Jsonwebtoken.verify(token, process.env.JWT_SECRET);
        res.status(200).json({ message: "Sesión activa", user: decoded });
    } catch (error) {
        console.error("Error al verificar sesión:", error);
        return res.status(403).json({ message: "Token no válido" });
    }
});

// Logout
app.post("/logout", (req, res) => {
    res.clearCookie("jwt");
    return res.status(200).json({ message: "Sesión cerrada exitosamente" });
});
