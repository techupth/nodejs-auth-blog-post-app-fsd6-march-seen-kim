import { Router } from "express";
import { db } from "../utils/db.js";
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"
import 'dotenv/config'

const authRouter = Router();

authRouter.post("/register", async (req, res) => {

    const user = {
        username: req.body.username,
        password: req.body.password,
        firstName: req.body.firstName,
        lastName: req.body.lastName,
    }

    try {
        const salt = await bcrypt.genSalt(10);
    
        user.password = await bcrypt.hash(user.password, salt);
    
        const collection = db.collection("users")
        await collection.insertOne(user);
    
        return res.json({
            message: "User has been created successfully" 
        })

    } catch (error){
        res.status(400).json({
            message: "Server Error"
        })
    }

})

authRouter.post("/login", async (req, res) => {
    const user = await db.collection("users").findOne({
        username: req.body.username,
    })

    if(!user){
        return res.status(404).json({
            message: "Invalid username or password"
        })
    }

    const validatePassword = await bcrypt.compare(
        req.body.password,
        user.password
    )

    if(!validatePassword){
        return res.status(400).json({
            message: "Invalid username or password"
        })
    }

    const token = jwt.sign(
        { id: user._id, firstName: user.firstName, lastName: user.lastName },
        process.env.SECRET_KEY,
        { expiresIn: "900000"}
    )

    return res.json({
        message: "login successfully",
        token,
    });
});
// 🐨 Todo: Exercise #1
// ให้สร้าง API เพื่อเอาไว้ Register ตัว User แล้วเก็บข้อมูลไว้ใน Database ตามตารางที่ออกแบบไว้

// 🐨 Todo: Exercise #3
// ให้สร้าง API เพื่อเอาไว้ Login ตัว User ตามตารางที่ออกแบบไว้

export default authRouter;
