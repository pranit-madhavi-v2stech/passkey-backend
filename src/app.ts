require("dotenv").config();
import express, { Application, Request, Response } from "express";
import session from "express-session";
import memoryStore from "memorystore";
import authRouter from "./routes/authRoutes";
import cors from "cors";
import mongoose from "mongoose";

const MemoryStore = memoryStore(session);

const app: Application = express();

app.use(
  cors({
    origin: [
      "localhost:3000",
      "http://localhost:3000",
    ],
    credentials: true,
  })
);

app.use(express.json());

app.use(
  session({
    secret: process.env.SESSION_SECRET || "passkey-auth",
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 86400000,
      httpOnly: true, // Ensure to not expose session cookies to clientside scripts
    },
    store: new MemoryStore({
      checkPeriod: 86_400_000, // prune expired entries every 24h
    }),
  })
);

const PORT = process.env.PORT || 5000;

const mongodbUri = process.env.MONGODB_URI || ""; // Ensure that process.env.MONGODB_URI is defined
mongoose
  .connect(mongodbUri)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.log(err));

app.get("/", (req: Request, res: Response) => {
  res.send("Hello World!");
});

app.use("/auth", authRouter);

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
