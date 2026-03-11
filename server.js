const express = require("express");
const bodyParser = require("body-parser");
const fs = require("fs");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = 3000;
const SECRET = "vidhyas_secret_key"; // In production, use environment variable

app.use(bodyParser.json());
app.use(express.static(__dirname)); // Serve index.html and other files

// Helper functions to read/write JSON files
function readFile(file) {
  if (!fs.existsSync(file)) return [];
  return JSON.parse(fs.readFileSync(file, "utf8"));
}
function writeFile(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

// Register new user
app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;
  let users = readFile("users.json");

  if (users.find(u => u.username === username)) {
    return res.status(400).json({ message: "User already exists" });
  }

  const hashed = await bcrypt.hash(password, 10);
  users.push({ username, password: hashed });
  writeFile("users.json", users);

  res.json({ message: "Registration successful" });
});

// Login existing user
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  let users = readFile("users.json");

  const user = users.find(u => u.username === username);
  if (!user) return res.status(400).json({ message: "User not found" });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ message: "Invalid password" });

  const token = jwt.sign({ username }, SECRET, { expiresIn: "1h" });
  res.json({ message: "Login successful", token });
});

// Middleware to protect routes
function auth(req, res, next) {
  const header = req.headers["authorization"];
  if (!header) return res.status(401).json({ message: "No token provided" });

  const token = header.split(" ")[1];
  try {
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ message: "Invalid token" });
  }
}

// Save order (protected route)
app.post("/api/order", auth, (req, res) => {
  const order = { ...req.body, user: req.user.username, time: new Date() };
  let orders = readFile("orders.json");
  orders.push(order);
  writeFile("orders.json", orders);

  res.json({ message: "Order saved successfully!" });
});

// Get user orders (protected route)
app.get("/api/orders", auth, (req, res) => {
  let orders = readFile("orders.json");
  const userOrders = orders.filter(o => o.user === req.user.username);
  res.json(userOrders);
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
