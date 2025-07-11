const express = require("express");
const path = require("path");

const cors = require("cors");

const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const { open } = require("sqlite");
const sqlite3 = require("sqlite3");

const app = express();
app.use(cors());
app.use(express.json());

let db;

const dbPath = path.join(__dirname, "myDB.db");

const intializeDBAndServer = async () => {
  try {
    db = await open({ filename: dbPath, driver: sqlite3.Database });
    await db.exec(
      `CREATE TABLE IF NOT EXISTS myUsers (id INTEGER PRIMARY KEY AUTOINCREMENT, fullname VARCHAR, email TEXT, password TEXT)`
    );
    await db.exec(
      `CREATE TABLE IF NOT EXISTS myTasks  (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, task TEXT, description TEXT, status TEXT, FOREIGN KEY (user_id) REFERENCES myUsers(id) ON DELETE CASCADE)`
    );
    app.listen(3000, async () => {
      console.log("Server is started at http://localhost:3000/");
    });
  } catch (e) {
    console.log(`ERROR MESSAGE: ${e.message}`);
    process.exit(1);
  }
};

intializeDBAndServer();

app.post("/signup", async (request, response) => {
  try {
    const { fullname, email, password } = request.body;
    const user = await db.get(`SELECT * FROM myUsers WHERE email = ?`, [email]);
    if (user) {
      return response.status(409).send({ message: "User Already Exists" });
    } else {
      const hashedPassword = await bcrypt.hash(password, 10);
      await db.run(
        `INSERT INTO myUsers (fullname, email, password) VALUES (?,?,?)`,
        [fullname, email, hashedPassword]
      );
      return response
        .status(201)
        .send({ message: "User Created Successfully!" });
    }
  } catch (error) {
    return response.status(500).send({ message: "Internal Server Error" });
  }
});

app.post("/login", async (request, response) => {
  try {
    const { email, password } = request.body;
    const user = await db.get(`SELECT * FROM myUsers WHERE email = ?`, [email]);
    if (!user) {
      return response.status(401).send({ message: "Invalid Email!" });
    }
    const passwordCheck = await bcrypt.compare(password, user.password);
    if (!passwordCheck) {
      return response.status(401).send({ message: "Invalid Password!" });
    }
    const token = jwt.sign({ userId: user.id }, "JWT_SECRET_CODE", {
      expiresIn: "1h",
    });
    return response.status(200).send({ token });
  } catch (error) {
    return response.status(500).send({ message: "Internal Server Error" });
  }
});
