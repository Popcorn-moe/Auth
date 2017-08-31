import { Strategy } from 'passport-local'
import { callbackify } from './utils'

export default class LocalAuth extends Strategy {
    constructor(clientID, clientSecret, callbackURL) {
        super({
            session: false
        }, callbackify((username, password) => {
            return Promise.resolve({ username, provider: 'local' })
        }))
    }
}