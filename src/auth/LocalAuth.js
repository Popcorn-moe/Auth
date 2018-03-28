import { Strategy } from "passport-local";
import { callbackify } from "./utils";
import { compare } from "bcrypt";

export default class LocalAuth extends Strategy {
	constructor(db) {
		super(
			{
				session: false
			},
			callbackify((username, password) => {
				return db
					.find({
						$or: [
							{
								email: username
							},
							{
								login: username
							}
						]
					})
					.limit(1)
					.toArray()
					.then(([user]) => {
						if (user && user.password) {
							user.provider = "local";
							return compare(password, user.password).then(res => {
								if (res) return user;
								else
									return [
										false,
										{
											error: true,
											text: "Invalid user or password"
										}
									];
							});
						} else
							return [
								false,
								{
									error: true,
									text: "Invalid user or password"
								}
							];
					});
			})
		);
	}
}
