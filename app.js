require('dotenv').config()
require('./config/database').connect()
const express = require('express')
const User = require('./model/user')
const auth = require('./middleware/auth')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

const app = express()

app.use(express.urlencoded({ extended: true }))
app.use(express.json())

app.post('/register', async (req, res) => {
  // Our register logic starts here
  try {
    console.log(req.body)
    // Get user input
    const { first_name, last_name, email, password } = req.body
    console.log({ first_name, last_name, email, password })
    // Validate user input
    if (!(email && password && first_name && last_name)) {
      return res.status(400).send('All input is required')
    }

    // check if user already exist
    // Validate if user exist in our database
    const oldUser = await User.findOne({ email })

    if (oldUser) {
      return res.status(409).send('User Already Exist. Please Login')
    }

    let encryptedPassword = ''
    //Encrypt user password
    try {
      const salt = bcrypt.genSaltSync(10)
      encryptedPassword = bcrypt.hashSync(password, salt)
    } catch (error) {
      console.error('Error hashing password:', error)
    }

    // Create user in our database
    const user = await User.create({
      first_name,
      last_name,
      email: email.toLowerCase(), // sanitize: convert email to lowercase
      password: encryptedPassword
    })

    // Create token
    const token = jwt.sign(
      { user_id: user._id, email },
      process.env.TOKEN_KEY,
      {
        expiresIn: '2h'
      }
    )
    // save user token
    user.token = token

    // return new user
    res.status(201).json(user)
  } catch (err) {
    console.log(err)
  }
  // Our register logic ends here
})

// Login
app.post('/login', async (req, res) => {
  // Our login logic starts here
  try {
    // Get user input
    const { email, password } = req.body

    // Validate user input
    if (!(email && password)) {
      res.status(400).send('All input is required')
    }
    // Validate if user exist in our database
    const user = await User.findOne({ email })

    if (user && (await bcrypt.compare(password, user.password))) {
      // Create token
      const token = jwt.sign(
        { user_id: user._id, email },
        process.env.TOKEN_KEY,
        {
          expiresIn: '2h'
        }
      )

      // save user token
      user.token = token

      // user
      res.status(200).json(user)
    }
    res.status(400).send('Invalid Credentials')
  } catch (err) {
    console.log(err)
  }
  // Our register logic ends here
})

app.post('/welcome', auth, (req, res) => {
  res.status(200).send('Welcome 🙌 ')
})

module.exports = app
