import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'

import User from '../models/user.js'

export const signin = async (req, res) => {
    const { email, password } = req.body
    try {
        const existingUser = await User.findOne({ email })
        // check if user exists
        if(!existingUser) return res.status(404).json({ message: "User doesn't exist"})
        // check if password is correct
        const isPasswordCorrect = await bcrypt.compare(password, existingUser.password)
        if(!isPasswordCorrect) return res.status(400).json({ message: 'Invalid credentials'})
        // if all is good, create token
        const token = jwt.sign({ email: existingUser.email, id: existingUser._id}, 'test', { expiresIn: '1h'})
        res.status(200).json({ result: existingUser, token })
    } catch (error) {
        res.status(500).json({ message: 'Something went wrong.'})
    }
}

export const signup = async (req, res) => {
    const { email, password, firstName, lastName, confirmPassword } = req.body
    try {
        const existingUser = await User.findOne({ email })
        // check if user exists
        if(existingUser) return res.status(400).json({ message: 'User already exists.'})
        // check if password and confirm match
        if(password !== confirmPassword) return res.status(400).json({ message: 'Passwords do not match.'})
        // if all is good, hash password and create new user
        const hashedPassword = await bcrypt.hash(password, 12)
        const result = await User.create({ email, password: hashedPassword, name: `${firstName} ${lastName}` })
        // then create token
        const token = jwt.sign({ email: result.email, id: result._id}, 'test', { expiresIn: '1h'})
        res.status(200).json({ result, token })
    } catch (error) {
        res.status(500).json({ message: 'Something went wrong.'})
    }
}