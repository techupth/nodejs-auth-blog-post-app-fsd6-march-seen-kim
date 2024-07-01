import { Router } from "express";
import { db } from "../utils/db.js";
import bcrypt from "bcrypt";

const authRouter = Router();
const collection = db.collection("usersData");

// 🐨 Todo: Exercise #1
// ให้สร้าง API เพื่อเอาไว้ Register ตัว User แล้วเก็บข้อมูลไว้ใน Database ตามตารางที่ออกแบบไว้
authRouter.post("/register", async (req, res) => {
  try {
    const userInput = req.body;
    const userData = {
      ...userInput,
      created_at: new Date(),
      updated_at: new Date(),
    };
    const salt = await bcrypt.genSalt(10);
    userData.password = await bcrypt.hash(userData.password, salt);
    await collection.insertOne(userData);
    return res
      .status(200)
      .json({ message: "User has been created successfully" });
  } catch {
    return res
      .status(500)
      .json({ message: "Cannot create user due to sever connection" });
  }
});

// 🐨 Todo: Exercise #3
// ให้สร้าง API เพื่อเอาไว้ Login ตัว User ตามตารางที่ออกแบบไว้
authRouter.post("/register", async (req, res) => {
  try {
    const userInput = req.body;
    const userData = {
      ...userInput,
      created_at: new Date(),
      updated_at: new Date(),
    };
    const salt = await bcrypt.genSalt(10);
    userData.password = await bcrypt.hash(userData.password, salt);
    await collection.insertOne(userData);
    return res
      .status(200)
      .json({ message: "User has been created successfully" });
  } catch {
    return res
      .status(500)
      .json({ message: "Cannot create user due to sever connection" });
  }
});

export default authRouter;
