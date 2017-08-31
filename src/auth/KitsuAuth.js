import { Strategy } from 'passport-oauth2'
import { callbackify } from './utils'

export default class KitsuAuth extends Strategy {
    constructor(clientID, clientSecret, callbackURL) {
        super({
            authorizationURL: 'https://kitsu.io/api/oauth/authorize',
            tokenURL: 'https://kitsu.io/api/oauth/token',
            clientID,
            clientSecret,
            callbackURL
        }, callbackify((accessToken, refreshToken, profile) => {
            return Promise.resolve(profile)
        }))
        this.name = 'kitsu';

        this._oauth2.setAuthMethod('Bearer');
        this._oauth2.useAuthorizationHeaderforGET(true);
    }

    userProfile(accessToken, done) {
        this._oauth2.get('https://kitsu.io/api/edge/users?filter[self]=true', accessToken, (err, body, res) => {
            if (err) return done(new Error('failed to fetch user profile', err));
            else try {
                const { id, username, email } = JSON.parse(body)
                done(null, { id, username, email, provider: 'discord' })
            } catch (e) { 
                done(e) 
            }
        })
    }
}