const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const { authenticateUser, authorizeUser } = require('./middleware')

const app = express()

const PORT = process.env.PORT || 5000

app.listen(PORT, () => {
    console.log(`App running on port ${PORT}...`);
});

app.use(express.json())


mongoose.connect('mongodb+srv://jh:UdJSuvfxvgQzIFIN@cluster0.txcchdp.mongodb.net/userDB',{useNewUrlParser: true})
    .then(()=> console.log("MongoDB connection successful"))
    .catch((err) => console.log(err))

const userSchema = new mongoose.Schema({
    email:{
        type: String,
        required: true,
        unique: true
    },
    password:{
        type: String,
        required: true
    },
    role: {
        type: String,
        enum: ['user', 'admin'],
        default: 'admin'
    },
    
})

userSchema.pre('save', async function(next){
    const user = this

    if (!user.isModified('password')){
        return next()
    }

    const salt = await bcrypt.genSalt(10)
    const hash = await bcrypt.hash(user.password, salt)

    user.password = hash
    
    next()
})

const User = mongoose.model('User', userSchema)

app.post('/register', async (req, res) => {
    try{
        const { email, password } = req.body

        const user = new User({ email, password })
        await user.save()

        res.json({
            success: true,
            message: 'User reg successfully'
        })
    } catch (error) {
        console.error(error)
        res.status(500).json({
            success: false,
            message: 'An error occured'
        })
    }
})

app.post('/login', async (req, res)=> {
    try{
        const { email, password } = req.body
        const user = await User.findOne({ email })

        if (!user){
            return res.status(400).json({
                success: false,
                message: 'Invalid email or password'
            })
        }
        const isMatch = await bcrypt.compare(password, user.password)

        if(!isMatch){
            return res.status(400).json({
                success: false,
                message: 'Invalid email or password'
            })
        }
        const token = jwt.sign({ userID: user._id, role: user.role }, 'secret',{
            expiresIn: '10d'
        })
        const cookieOptions = {
            expires: new Date(
                Date.now() + 10*24 * 60 * 60 * 1000
            ),
            httpOnly: true
        }
        res.cookie('jwt', token, cookieOptions)
        res.json({
            success: true,
            token,
        })

    } catch (error){
        console.error(error)
        res.json(500).json({
            success: false,
            message: 'An error occurred'
        })    
    }
})

app.get('/protected', authenticateUser, authorizeUser(['admin']), (req, res)=> 
    res.json({
        success: true,
        message: 'You have accessed a protected resource'
    })
)