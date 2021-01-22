import passport from "passport";
import { User } from "../models/user";
import { UserRefreshToken } from "../models/user_refresh_tokens";
const TokenGenerator = require('uuid-token-generator');


export function SkeinAuthentication(req, res, next) {

    passport.authenticate('skein', async function (err, user, info) {
        const tokgen2 = new TokenGenerator(256, TokenGenerator.BASE62);
        tokgen2.generate();
        let token = tokgen2;

        console.log(token)
        if (user) {
            req.user = user

            console.log("INSTANCE", req.user)
            try {
                await User.create({
                    email: req.user.email,
                    first_name :req.user.name,
                    token:token.baseEncoding
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