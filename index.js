import express from 'express'
import cookieParser from 'cookie-parser'
import bodyParser from 'body-parser'
import cors from 'cors'
import passport from './src/passport'

const app = express()

app.use(cookieParser())
app.use(bodyParser.json())
app.use(cors({
  origin: ['http://localhost:8080', 'http://localhost:8000'],
  credentials: true
}))

passport(app)

app.listen(3031, () => console.log('Listening on 3031'))
