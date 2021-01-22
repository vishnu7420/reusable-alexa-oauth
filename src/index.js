import express, { json, urlencoded } from 'express';
import cookieParser from 'cookie-parser';
import logger from 'morgan';
import Paytm from 'paytmchecksum';

import { join } from 'path';

/** Passport for authentication */
import passport from 'passport';

/** Passport custom strategy */
import { Strategy } from 'passport-custom';

/** Firebase admin */
import firebaseAdmin from 'firebase-admin';


/** Firebase */
import firebase from 'firebase';


/** Sequelize datatypes */
import { DataTypes } from 'sequelize';

/** Skein authenticator */
import { SkeinAuthentication } from './config/authenticate';

/** JSON web token */
import { verify, decode, sign } from 'jsonwebtoken';


/** Operator alaises */
import user, { User } from './models/user';
import { operatorsAliases, sequelize } from './config/database';
import { exec } from 'child_process';


import * as LinkedInStrategy from 'passport-linkedin-oauth2';


import https from 'https'
import Mailer from './config/mailer';


import session from 'express-session';
import user_refresh_tokens, { UserRefreshToken } from './models/user_refresh_tokens';

import crypto from 'crypto'
import moment from 'moment';
import { throws } from 'assert';
import { Transaction } from './models/transactions';
import { checkSchema } from 'express-validator';
import { Master } from './models/master';

var app = express();
// require('dotenv').config()



/** Skein Signin Method Configuration */
export class SkeinUserManagement {

    // Initialization
    constructor(app) {
        this.app = app

        // view engine setup
        this.app.set('views', join(__dirname, '../public/views'));



        // view engine set to jade markup language
        this.app.set('view engine', 'ejs');


        // Access log
        this.app.use(logger('dev'));

        // Json support
        this.app.use(json());

        // URL encoded support
        this.app.use(urlencoded({ extended: false }));

        // Cookie parser to get data from cookies
        this.app.use(cookieParser());

        //  Public directory
        this.app.use(express.static(join(__dirname, '../public')));

        this.app.use(express.static(join(__dirname, '../node_modules')))

        // catch 404 and forward to error handler

        // error handler
        this.app.use(function (err, req, res, next) {
            // set locals, only providing error in development
            res.locals.message = err.message;
            res.locals.error = req.app.get('env') === 'development' ? err : {};
            // render the error page
            res.status(err.status || 500);
            res.render('error');
        });

    }

    /** Set firebase service account configuration */
    setFirebaseServiceAccount(firebaseServiceAccount) {
        this.firebaseServiceAccount = firebaseServiceAccount
    }

    /** Get firebase service account configration */
    getFirebaseServiceAccount() {
        return this.firebaseServiceAccount
    }

    /** Set firebase config */
    setFirebaseConfig({ apiKey, authDomain, databaseURL, projectId, storageBucket, messagingSenderId }) {
        this.firebaseConfig = { apiKey, authDomain, databaseURL, projectId, storageBucket, messagingSenderId }
    }

    /** Get firebase config */
    getFirebaseConfig() {
        return this.firebaseConfig
    }



    async migrate() {


        this.dbConfig = {
            username: process.env.DB_USER,
            password: process.env.DB_PASSWORD,
            port: process.env.DB_PORT,
            database: process.env.DB_NAME,
            dialect: process.env.DB_DIALECT,
            host: process.env.DB_HOST
        }

        if (!this.dbConfig) {
            console.error("Please configure database with skein user management module")
            process.exit(1)
        }

        if (!this.dbConfig.username) {
            console.error("Please set database username in database config")
            process.exit(1)
        }

        if (!this.dbConfig.password) {
            console.error("Please set database password in database config")
            process.exit(1)
        }

        if (!this.dbConfig.host) {
            console.error("Please set database host in database config")
            process.exit(1)
        }

        if (!this.dbConfig.port) {
            console.error("Please set database port in database config")
            process.exit(1)
        }

        if (!this.dbConfig.dialect) {
            console.error("Please set database dialect in database config")
            process.exit(1)
        }

        if (!this.dbConfig.database) {
            console.error("Please set database name in database config")
            process.exit(1)
        }


        let url = null,
            script = null

        if (this.dbConfig.dialect == DIALECT.POSTGRESQL) {
            url = `postgres://`;
            script = ``
        } else if (this.dbConfig.dialect == DIALECT.MYSQL) {
            url = `mysql://`
            script = `mysql -h ${this.dbConfig.host} -u ${this.dbConfig.username} -p${this.dbConfig.password} -e "CREATE DATABASE IF NOT EXISTS ${this.dbConfig.database}"`;
        }


        if (!url) {
            console.error("Something went wrong while exeuting database migration")
            process.exit(1)
        }


        await new Promise((resolve, reject) => {
            const migration_path = join(__dirname, 'db/migrations')

            var sam = `"${script}
            sequelize --migrations-path "${migration_path}" db:migrate --url "${url}${this.dbConfig.username}:${this.dbConfig.password}@${this.dbConfig.host}:${this.dbConfig.port}/${this.dbConfig.database}";
          , { env: process.env }"`
            console.log(sam)
            const migrate = exec(
                `
                ${script}
                  sequelize --migrations-path "${migration_path}" db:migrate --url "${url}${this.dbConfig.username}:${this.dbConfig.password}@${this.dbConfig.host}:${this.dbConfig.port}/${this.dbConfig.database}";
                `, { env: process.env },
                err => (err ? reject(err) : resolve())
            );

            // Forward stdout+stderr to this process
            migrate.stdout.pipe(process.stdout);
            migrate.stderr.pipe(process.stderr);
        });


    }


    /** Set database configuration */
    setDatabaseConfig({ username, password, database, host, port, dialect }) {
        this.dbConfig = {
            ... { username, password, database, host, port, dialect },
            ... {
                operatorsAliases: operatorsAliases
            }
        }
    }

    /** Get databasse configuration */
    getDatabaseConfig() {
        return this.dbConfig
    }


    init() {

        /** Checking login method is exists or not */
        if (!this.method.firebase && !this.method.jwt) {
            console.log("Signin method(s) not found")
            process.exit(1)
        }

        /** If we enabled firebase method */
        if (this.method.firebase) {
            /** If we didn't set firebase service account  */
            if (!this.firebaseServiceAccount) {
                console.log("Firebase service account configuration not found")
                process.exit(1)
            }

            firebaseAdmin.initializeApp({
                credential: firebaseAdmin.credential.cert(this.firebaseServiceAccount),
            });


            if (!this.firebaseConfig) {
                console.log("Firebase config is not set !")
                process.exit(1)
            }


            firebase.initializeApp(this.firebaseConfig);
        }

        if (!this.secret) {
            console.log("Secret not set !")
            process.exit(1)
        }

        /** Express session */

        this.app.use(session({
            resave: false,
            saveUninitialized: true,
            secret: this.secret
        }));

        /** PASSPORT SETUP */

        /** Passport initialize */
        this.app.use(passport.initialize());

        /** Passport session */
        this.app.use(passport.session());





        /** Passport serialize */
        passport.serializeUser(function (user, cb) {
            cb(null, user);
        });

        /** Passport deserialize */
        passport.deserializeUser(function (obj, cb) {
            cb(null, obj);
        });



        /** Firebase admin credentails */


        /** Passport custom strategy */
        const SkeinStrategy = Strategy;


        /** User authentication */
        /**
         * @param req // req from url
         * @function callback // user data
         */
        passport.use('skein', new SkeinStrategy(async (req, callback) => {

            /** token and type of token */
            let token = null,
                type = 'jwt',
                user = null;



            /** Checking token type */
            if (this.method.firebase && (req.headers.firebase != undefined || req.cookies.firebase != undefined || req.query.firebase != undefined || req.body.firebase != undefined)) {
                type = 'firebase'
                if (req.headers.firebase)
                    token = req.headers.firebase
                else if (req.headers.firebase)
                    token = req.query.firebase
                else if (req.cookies.firebase)
                    token = req.cookies.firebase
                else if (req.body.firebase)
                    token = req.body.firebase


                console.log(token)
                try {
                    user = await firebaseAdmin.auth().verifyIdToken(token)
                } catch (err) {
                    throw new Error(err)
                }
            }




            /** Checking token type */
            if (this.method.jwt && (req.headers.jwt != undefined || req.cookies.jwt != undefined || req.query.jwt != undefined || req.body.jwt != undefined)) {
                type = 'jwt'
                if (req.headers.jwt)
                    token = req.headers.jwt
                else if (req.headers.jwt)
                    token = req.query.jwt
                else if (req.cookies.jwt)
                    token = req.cookies.jwt
                else if (req.body.jwt)
                    token = req.body.jwt


                let options = this.jwtOptions;

                let secret = this.secret;

                if (!options) {
                    console.log("JWT options not set")
                    process.exit(1)
                }

                if (!secret) {
                    console.log("JWT secret not set")
                    process.exit(1)
                }

                try {
                    user = verify(token, secret, options);
                    user = decode(token)
                } catch (err) {
                    throw new Error(err)
                }
            }


            if (this.method.linkedIn && req.isAuthenticated()) {
                user = req.user
            }


            if (user) {

                user['provider'] = type
                user['token'] = token

                /** If user exists */

                callback(null, user)



            } else {
                callback("User not found !", false)
            }


        }))


        if (this.method.linkedIn) {
            if (!this.linkedInConfig) {
                console.error("Linked In configuration error")
                process.exit(1)
            }

            passport.use(new LinkedInStrategy.Strategy(this.linkedInConfig, function (token, tokenSecret, profile, done) {
                return done(null, profile);
            }));
        }



        /** User profile */
        this.app.get('/reusable-api/auth', (req, res) => {
            res.render('index')
        });


        /** Linked in authetication */
        this.app.get('/reusable-api/auth/linkedin', passport.authenticate('linkedin', {
            scope: ['r_emailaddress', 'r_liteprofile'],
        }));

        /** Linked in callback */
        this.app.get('/reusable-api/auth/:type/callback', passport.authenticate('linkedin', {
            successRedirect: '/reusable-api/user/profile',
            failureRedirect: '/reusable-api/auth'
        }));


        /** User forget password */
        this.app.get('/reusable-api/user/forget-password', (req, res) => {
            firebase.auth().signInWithEmailAndPassword()
        });

        /** User profile */
        this.app.get('/reusable-api/user/profile', SkeinAuthentication, (req, res) => {
            res.send(req.user)
        });

        /** Create User */
        // SkeinValidator(['first_name', 'last_name', 'email', 'password']),
        this.app.post('/reusable-api/user', async (req, res) => {
            try {
                let usr = await User.create(req.body)

                res.send({
                    status: true,
                    message: "User created successfully !!",
                    data: usr
                })

            } catch (err) {

                res.send({
                    status: false,
                    message: "Failed to create user !!",
                    error: err
                })

            }
        })

        /** User login */
        // SkeinValidator(['email_or_phone_no', 'password']), 
        this.app.post('/reusable-api/user/login', async (req, res) => {
            try {

                /** jwt options */
                let options = this.jwtOptions;

                /** jwt secret */
                let secret = this.secret;

                /** if options not set */
                if (!options) {
                    throw new Error("JWT options not set")
                }

                /** if secret not set */
                if (!secret) {
                    throw new Error("JWT secret not set")
                }

                /** getting user with email or phone no */
                let usr = await User.findOne({
                    where: {
                        $or: [{
                            email: req.body.email_or_phone_no
                        },
                        {
                            phone_no: req.body.email_or_phone_no
                        }
                        ],
                        password: req.body.password
                    }
                })


                /** generating jwt token */
                let token = this.generateJwtToken(usr.get())


                let refreshToken = await this.generateRefreshToken(usr.get(), req.ip)


                /** Set cookie  */

                setTokenCookie(res, { token, refreshToken })

                /** success response */
                res.send({
                    status: true,
                    message: "User login success !!",
                    data: usr,
                    token: token,
                    refreshToken
                })

            } catch (err) {

                /** if something went wrong */
                console.log(err)

                /** failure response */
                res.send({
                    status: false,
                    message: "Failed to login !!",
                    error: err
                })

            }
        })

        this.app.post('/reusable-api/user/revoke-token', SkeinAuthentication, (req, res) => {



            // accept token from request body or cookie

            const token = req.cookies.refreshToken || req.body.refreshToken

            const ipAddress = req.ip;

            if (!token) return res.status(400).json({ message: 'Token is required' });

            // users can revoke their own tokens and admins can revoke any tokens
            if (!req.user.ownsToken(token)) {
                return res.status(401).json({ message: 'Unauthorized' });
            }

            this.revokeToken({ token, ipAddress })
                .then(() => res.send({ status: true, message: 'Token revoked' }))
                .catch((err) => {
                    console.log(err)
                    res.send({ status: false, message: 'Failed to revoke token' })
                });
        });


        this.app.post('/reusable-api/user/refresh-token', SkeinAuthentication, async (req, res) => {
            try {
                if (this.method.jwt && (req.headers.jwt != undefined || req.cookies.jwt != undefined || req.query.jwt != undefined || req.body.jwt != undefined)) {

                    let token = req.headers.jwt || req.cookies.jwt || req.body.jwt || null
                    let data = await this.refreshToken({ token, ipAddress: req.ip, user: req.user })

                    if (data) {
                        res.send({
                            ...{
                                status: true,

                            },
                            ...data
                        })
                    }

                }
                else {
                    res.send({
                        status: false,
                        message: "JWT isn't configured with this application"
                    })
                }
            }
            catch (err) {
                console.log(err)
                res.send({
                    status: false,
                    message: "Something went wrong !"
                })
            }


        });

        this.app.post('/reusable-api/paytm/callback', async (req, res) => {

            let body = {
                mid: process.env.PAYTM_MERCHANT_ID,
                orderId: req.body.ORDERID
            }

            try {
                if (req.body.STATUS == "TRX_SUCCESS" && Paytm.verifySignature(body, process.env.PAYTM_MERCHANT_KEY, req.body.CHECKSUMHASH)) {
                    let trx = await Transaction.update({
                        status: "SUCCESS",
                        payment_gateway_callback_response: req.body
                    }, {
                        where: {
                            id: req.body.ORDERID
                        }
                    })

                    if (trx) {
                        res.send({
                            status: true,
                            message: "Transaction success !"
                        })
                    }
                    else {
                        res.send({
                            status: false,
                            message: "Transaction failed !"
                        })
                    }
                }
            }
            catch (err) {
                res.send({
                    status: false,
                    message: "Transaction failed !"
                })
            }



        })

        this.app.get('/reusable-api/paytm', (req, res) => {
            res.render('paytm')
        })



        this.app.get('/reusable-api/master',async (req, res) => {
            let master = await Master.findOne({
                where: {
                    $and: [{
                        client_id: req.query.clientID
                    },
                    {
                        secret_key: req.query.clientSecret
                    }
                    ],

                }
            })
            if (master) {
                res.redirect('/reusable-api/auth')
            }
        })

        this.app.post('/reusable-api/paytm/initiate', SkeinAuthentication, async (req, res) => {



            console.log("REQUEST ------>", req.body)
            if (req.body.amount < 1) {
                res.send({
                    status: false,
                    message: "Invalid amount"
                })
                return
            }

            let transaction = await Transaction.create({
                user_id: req.user.id,
                amount: req.body.amount,
                gateway: "PAYTM",
                status: "PENDING"
            })
            var paytmParams = {};


            paytmParams.body = {
                "requestType": "Payment",
                "mid": process.env.PAYTM_MERCHANT_ID,
                "websiteName": "WEBSTAGING",
                "orderId": transaction.id,
                "callbackUrl": "https://demo.emeetify.com:81/reusable-api/paytm/callback",
                "txnAmount": {
                    "value": req.body.amount,
                    "currency": "INR",
                },
                "userInfo": {
                    "custId": req.user.id,
                    "firstName": req.user.first_name,
                    "lastName": req.user.last_name,
                    "email": req.user.email,
                    "mobile": req.user.phone_no
                }
            };


            /*
            * Generate checksum by parameters we have in body
            * Find your Merchant Key in your Paytm Dashboard at https://dashboard.paytm.com/next/apikeys 
            */

            Paytm.generateSignature(JSON.stringify(paytmParams.body), process.env.PAYTM_MERCHANT_KEY).then(function (checksum) {


                paytmParams.head = {
                    "signature": checksum
                };
                var post_data = JSON.stringify(paytmParams);

                console.log(paytmParams)

                var options = {

                    /* for Staging */
                    hostname: process.env.PAYTM_URL_END,

                    /* for Production */
                    // hostname: 'securegw.paytm.in',

                    port: 443,
                    path: `/theia/api/v1/initiateTransaction?mid=${process.env.PAYTM_MERCHANT_ID}&orderId=${transaction.id}`,

                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Content-Length': post_data.length
                    }
                };


                var response;

                var post_req = https.request(options, function (post_res) {
                    post_res.on('data', function (chunk) {
                        response = chunk;
                    });

                    post_res.on('end', async function () {

                        let data = JSON.parse(response)

                        console.log(data)

                        if (data.body.resultInfo.resultStatus == "S") {
                            await Transaction.update({
                                payment_gateway_response: data,
                                payment_gateway_trx_id: data.body.txnToken,
                            }, {
                                where: {
                                    id: transaction.id
                                }
                            })
                            res.send({
                                status: true,
                                message: "Payment initiated !",
                                data: {
                                    timestamp: data.head.responseTimestamp,
                                    trx_token: data.body.txnToken,
                                    order_id: transaction.id,
                                    amount: req.body.amount
                                }
                            })
                        }
                        else {
                            res.send({
                                status: true,
                                message: "Failed to initiate payment ! Something went wrong !",
                            })
                        }

                    });

                    post_req.on('error', (e) => {
                        console.error(e);
                    });
                });

                post_req.write(post_data);
                post_req.end();

            });
        })



        // catch 404 and forward to error handler
        // this.app.use(function(req, res, next) {
        //     next(createError(404));
        // });
        this.app.get('*', (req, res) => {
            res.send({ error: "No routes matched" });
            res.end();
        })

        // helper functions

        function setTokenCookie(res, { token, refreshToken }) {
            // create http only cookie with refresh token that expires in 7 days
            const cookieOptions = {
                httpOnly: true,
                expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
            };
            res.cookie('refreshToken', refreshToken, cookieOptions);
            res.cookie('jwt', token, cookieOptions);

        }

    }



    //  jwt token generation
    generateJwtToken(user) {
        // create a jwt token containing the user id that expires in 15 minutes
        return sign(user, this.secret, this.jwtOptions);
    }

    async generateRefreshToken(user, ipAddress) {
        // create a refresh token that expires in 7 days

        let refreshToken = this.randomTokenString()

        let refresh = {
            user_id: user.id,
            token: refreshToken,
            expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
            createdByIp: ipAddress
        }

        await UserRefreshToken.create(refresh)

        return refreshToken
    }

    async refreshToken({ user, token, ipAddress }) {
        const refreshToken = await this.getRefreshToken(token);

        // replace old refresh token with a new one and save
        delete user.iat;
        delete user.exp
        delete user.iss

        const newRefreshToken = await this.generateRefreshToken(user, ipAddress);
        refreshToken.revoked = Date.now();
        refreshToken.revokedByIp = ipAddress;
        refreshToken.replacedByToken = newRefreshToken.token;
        delete refreshToken.id
        delete refreshToken.token
        delete refreshToken.user_id
        delete refreshToken.createdAt
        delete refreshToken.expires
        await UserRefreshToken.update(refreshToken, { where: { token } });

        // generate new jwt
        token = this.generateJwtToken(user);


        // return basic details and tokens
        return {
            ...{
                data: user
            },
            token,
            refreshToken: newRefreshToken
        };
    }


    async revokeToken({ token, ipAddress }) {
        const refreshToken = await this.getRefreshToken(token);

        // revoke token and save
        refreshToken.revoked = Date.now();
        refreshToken.revokedByIp = ipAddress;
        delete refreshToken.id
        delete refreshToken.token
        delete refreshToken.user_id
        delete refreshToken.createdAt
        delete refreshToken.expires
        await UserRefreshToken.update(refreshToken, { where: { token } });
    }

    async getRefreshToken(token) {
        let refreshToken = await UserRefreshToken.findOne({ token });

        refreshToken = refreshToken.dataValues

        if (!refreshToken || refreshToken.revoked || moment(refreshToken.expires).isBefore(new Date())) throw 'Invalid token';
        return refreshToken;
    }

    randomTokenString() {
        return crypto.randomBytes(40).toString('hex');
    }



    /** Set login methods */
    setMethod(method) {
        this.method = method
    }

    /** Get login methods */
    getMethod() {
        return this.method
    }

    /** LinkedIn config */
    setLinkedInConfig({
        clientID,
        clientSecret,
        callbackURL,
        scope
    }) {
        this.linkedInConfig = {
            clientID,
            clientSecret,
            callbackURL,
            scope
        }

        console.log(this.linkedInConfig)
    }

    /**  Secret */
    setSecret(secret) {
        this.secret = secret
    }

    /** JWT Options */
    setJwtOptions(options) {
        this.jwtOptions = options
    }

    /** Used sequelize for user data handling  */

    /** get database instance */
    getDatabaseInstance() {
        return this.sequelize
    }

    /** get users */
    async getUsers() {
        return await User.findAll()
    }

    /** get user by id */
    async findUserById(user_id) {
        return await User.findOne({
            where: {
                id: user_id
            }
        })
    }

    /** create user */
    async getUserCount() {
        return await User.count()
    }

    /** create user */
    async createUser(user) {
        return await User.create(user)
    }

    /** Mail configuration */
    async setMailConfiguration() {
        this.mailer = new Mailer()
    }

}


export const DIALECT = {
    MYSQL: 'mysql',
    POSTGRESQL: 'postgresql'
}



let skeinUserManagement = new SkeinUserManagement(app)

skeinUserManagement.setMethod({
    jwt: true,
    firebase: true,
    linkedIn: true
})

skeinUserManagement.setSecret("Skein@2020")

skeinUserManagement.setFirebaseServiceAccount(require('../loginauth-d504b-firebase-adminsdk-wegdv-30b0363b03.json'))

skeinUserManagement.setFirebaseConfig({
    apiKey: "AIzaSyDC3uGR3ZvkKmGU0KaIXTtVB2mObNcN4Yg",
    authDomain: "loginauth-d504b.firebaseapp.com",
    databaseURL: "https://loginauth-d504b.firebaseio.com",
    projectId: "loginauth-d504b",
    storageBucket: "loginauth-d504b.appspot.com",
    messagingSenderId: "1089627182362"
})

skeinUserManagement.setLinkedInConfig({
    clientID: '868vsx4thp0p3e',
    clientSecret: 'Rdvs3sxXCXQhGNld',
    callbackURL: `${process.env.HOST_NAME}/reusable-api/auth/linkedin/callback`,
    scope: ['r_emailaddress', 'r_liteprofile']
})
skeinUserManagement.init()


/* skeinUserManagement.setDatabaseConfig({
    username: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
    database: process.env.DB_NAME,
    dialect: process.env.DB_DIALECT,
    host: process.env.DB_HOST

}) */


skeinUserManagement.setJwtOptions({ expiresIn: "10d", issuer: "https://www.skeintech.com" })

skeinUserManagement.migrate()



export default app;