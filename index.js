import express from 'express'
import cookieParser from 'cookie-parser'
import bodyParser from 'body-parser'
import cors from 'cors'
import passport from './src/passport'
import { MongoClient } from 'mongodb'

const url = 'mongodb://localhost:27017/popcornmoe_backend'
const app = express()

app.use(cookieParser())
app.use(bodyParser.json())
app.use(cors({
  origin: ['http://localhost:8080', 'http://localhost:8000'],
  credentials: true
}))

MongoClient.connect(url).then(db =>{
  console.log('Connected on mongodb')
  passport(app, db.collection('users'))
})


app.listen(3031, () => console.log('Listening on 3031'))
