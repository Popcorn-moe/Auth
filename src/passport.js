import passport from 'passport'
import jwt from 'jsonwebtoken'
import uuid from 'uuid/v4'
import { hash } from 'bcrypt'
import { SSOExchangeAuth, LocalAuth, KitsuAuth, DiscordAuth } from './auth'

const SPECIAL_PROVIDERS = ['local', 'ssoExchange', 'signup']
const ssoExchange = new SSOExchangeAuth()

export default function(app, db) {
    app.use(passport.initialize())

    passport.use(ssoExchange)
    passport.use(new LocalAuth(db))
    passport.use(new DiscordAuth(db, process.env.DISCORD_CLIENT_ID, process.env.DISCORD_CLIENT_SECRET, getCallback('discord')))
    passport.use(new KitsuAuth(db, 'dd031b32d2f56c990b1425efe6c42ad847e7fe3ab46bf1299f05ecd856bdb7dd',
            '54d7307928f63414defd96399fc31ba847961ceaecef3a5fd93144e960c0e151'))
   
    const PROVIDERS = Object.keys(passport._strategies).filter(p => !SPECIAL_PROVIDERS.includes(p) && p !== 'session')

    console.log('Registered sso providers:', PROVIDERS.join(', '))

    passport.serializeUser((user, cb) => cb(null, user))

    app.post('/login', passport.authenticate('local'), redirect)

    app.post('/signup', (req, res) => {
        hash(req.body.password, 10)
            .then(password => db.insertOne({
                email: req.body.email,
                login: req.body.login,
                group: 0,
                newsletter: req.body.newsletter || false,
                password
            }))
            .then(({ ops: [user] }) => {
                req.user = user
                req.user.provider = 'signup'
                redirect(req, res)
            })
            .catch(e => {
                console.error(e)
                res.status(500).end()
            })
    })

    app.post('/ssoExchange', passport.authenticate('ssoExchange'), redirect)

    app.get('/login/:provider', (req, res, next) => {
        const provider = req.params.provider
        if (PROVIDERS.includes(provider)) {
            res.cookie('callback', req.query.callback, { httpOnly: true })
            passport.authenticate(provider)(req, res, next)
        } else {
            res.status(400).send('Provider not found')
        }
    })

    app.get('/login/:provider/callback', (req, res, next) => {
        const provider = req.params.provider
        if (PROVIDERS.includes(provider)) {
            passport.authenticate(provider)(req, res, next)
        } else {
            res.status(400).send('Provider not found')
        }
    }, redirect)
}

function redirect(req, res) {
  if(SPECIAL_PROVIDERS.includes(req.user.provider)) {
    const id = uuid()
    res.cookie('session', jwt.sign({
        '_id': req.user._id
      }, 'secret', {
        expiresIn: '31 days',
        audience: 'session',
        jwtid: id
      }),
      {
        maxAge: 24 * 60 * 60 * 1000,
        httpOnly: true
      }
    )

    if(req.cookies.ssoExchange)
        res.clearCookie('ssoExchange')

    res.json({ csrf: jwt.sign({
        id
      }, 'secret', {
        expiresIn: '31 days',
        audience: 'csrf'
      })
    })
  } else {
    res.clearCookie('callback')
    ssoExchange.createToken(req.user).then(token => {
        res.cookie('ssoExchange', token)
        res.redirect(req.cookies.callback)
    })
  }
}

function getCallback(name) {
    return `${process.env.AUTH_URL || 'http://localhost:3031'}/login/${name}/callback`
}
