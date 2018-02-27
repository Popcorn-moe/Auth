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
			callbackify((accessToken, refreshToken, { id, email, username }) => {
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
							$set: { discordId: id }
						},
						{ upsert: true }
					)
					.then(({ value, lastErrorObject: { upserted } }) => {
						insert._id = upserted;
						return upserted ? insert : value;
					});
			})
		);
	}
}
