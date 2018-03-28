import { Strategy } from "passport-twitter";
import { callbackify } from "./utils";

export default class TwitterAuth extends Strategy {
	constructor(db, consumerKey, consumerSecret, callbackURL) {
		super(
			{
				consumerKey,
				consumerSecret,
				callbackURL,
				includeEmail: true,
				includeStatus: false
			},
			callbackify(
				(
					accessToken,
					refreshToken,
					{ id, username, emails: [{ value: email }] }
				) => {
					if (!email) return null;
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
								$set: { twitterId: id }
							},
							{ upsert: true }
						)
						.then(({ value, lastErrorObject: { upserted } }) => {
							insert._id = upserted;
							return {
								...(upserted ? insert : value),
								provider: "twitter"
							};
						});
				}
			)
		);
	}
}
