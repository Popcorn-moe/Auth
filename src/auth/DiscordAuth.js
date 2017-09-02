import { Strategy } from 'passport-discord'
import { callbackify } from './utils'

export default class DiscordAuth extends Strategy {
    constructor(db, clientID, clientSecret, callbackURL) {
        super({
            clientID,
            clientSecret,
            callbackURL,
            scope: ['identify', 'email']
        }, callbackify((accessToken, refreshToken, profile) => {
            return Promise.resolve(profile)
        }))
    }
}