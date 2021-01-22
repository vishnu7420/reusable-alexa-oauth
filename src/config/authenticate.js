import passport from "passport";
import { User } from "../models/user";
import { UserRefreshToken } from "../models/user_refresh_tokens";



export function SkeinAuthentication(req, res, next) {

    passport.authenticate('skein', async function (err, user, info) {

        if (user) {
            req.user = user

            console.log("INSTANCE", req.user)
            try {
                await User.create({
                    email: req.user.email,
                    first_name :req.user.name
                })
            }
            catch (err) {
                console.log(err)
                console.log("User already exists")
            }

            if (req.user.provider == req.params.type) {
                res.cookie('jwt', req.user.token)
            } else if (req.user.provider == 'firebase') {
                res.cookie('firebase', req.user.token)
            }

            delete req.user.token
            const refreshTokens = await UserRefreshToken.findAll({ user: user.id });
            req.user.ownsToken = token => !!refreshTokens.find(x => x.token === token);
            next()
        } else {
            res.send({
                status: false,
                message: err
            })
        }
    })(req, res, next);

}