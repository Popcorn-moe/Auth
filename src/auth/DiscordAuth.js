import { Strategy } from "passport-discord";
import { callbackify } from "./utils";

export default class DiscordAuth extends Strategy {
	constructor(db, clientID, clientSecret, callbackURL) {
		super(
			{
				clientID,
				clientSecret,
				callbackURL,
				scope: ["identify", "email"]
			},
			callbackify(
				(accessToken, refreshToken, { id, email, username, discriminator }) => {
					const insert = {
						email,
						login: username,
						group: "VIEWER",
						newsletter: false,
						password: null
					};
					return db
						.findOneAndUpdate(
							{ email },
							{
								$setOnInsert: insert,
								$set: {
									discord: {
										id,
										username,
										discriminator
									}
								}
							},
							{ upsert: true }
						)
						.then(({ value, lastErrorObject: { upserted } }) => {
							insert._id = upserted;
							return {
								...(upserted ? insert : value),
								provider: "discord"
							};
						});
				}
			)
		);
	}
}
