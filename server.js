const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const db = require("./db");

const app = express();
app.use(cors());
app.use(express.json());
app.use("/uploads", express.static("uploads"));

const SECRET = "mysecretkey";

/* Image Upload */
const storage = multer.diskStorage({
  destination: "uploads/",
  filename: (req, file, cb) => {
    cb(null, Date.now() + "-" + file.originalname);
  },
});
const upload = multer({ storage });

/* Signup */
app.post("/signup", (req, res) => {
  const { email, password } = req.body;
  const hash = bcrypt.hashSync(password, 10);

  db.run(
    "INSERT INTO users(email,password) VALUES(?,?)",
    [email, hash],
    (err) => {
      if (err) return res.status(400).json({ message: "User exists" });
      res.json({ message: "Signup success" });
    }
  );
});

/* Login */
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  db.get("SELECT * FROM users WHERE email=?", [email], (err, user) => {
    if (!user) return res.status(401).json({ message: "Invalid" });

    const valid = bcrypt.compareSync(password, user.password);
    if (!valid) return res.status(401).json({ message: "Invalid" });

    const token = jwt.sign({ id: user.id }, SECRET);
    res.json({ token });
  });
});

/* Middleware */
function auth(req, res, next) {
  const token = req.headers.authorization;
  if (!token) return res.sendStatus(403);
  jwt.verify(token, SECRET, (err, data) => {
    if (err) return res.sendStatus(403);
    req.user = data;
    next();
  });
}

/* Categories */
app.get("/categories", auth, (req, res) => {
  db.all("SELECT * FROM categories", [], (err, rows) => {
    res.json(rows);
  });
});

app.post("/categories", auth, upload.single("image"), (req, res) => {
  const { name, itemCount } = req.body;
  const image = req.file.path;

  db.run(
    "INSERT INTO categories(name,itemCount,image) VALUES(?,?,?)",
    [name, itemCount, image],
    () => res.json({ message: "Category added" })
  );
});

app.listen(5000, () => console.log("Backend running on 5000"));
