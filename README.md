# User management - reusable rest service (Skein Technologies)

# Features!
  - Google authentication
  - OTP authentication
  - Facebook Signin
  - Signin with email
  - GitHub
  - Custom user

# Installation
  Skein user management requires [Node.js](https://nodejs.org/) v8+ to run.
  SKEIN USER MANAGEMENT NPM : [skein-user-management@latest](https://www.npmjs.com/package/skein-user-management)
 
```sh
$ npm install skein-user-management@latest
```


# Development steps

in your entry.js you have to 

```sh
...
import SkeinUserManagenent from 'skein-user-management';
...
...
#  Here we creating an object to User Management Service
let skeinUserManagement = new SkeinUserManagement(app)

# Method configuration firebase and jwt

# if we pass firebase as true it enables all social authentication methods like facebook,google,otp authentication

skeinUserManagement.setMethod({
    jwt: true,
    firebase: true
})

# if we enabled firebase we have to set firebase service account configuration file
skeinUserManagement.setFirebaseServiceAccount(require('/path/to/service_config.json'))

# Initializing all services
skeinUserManagement.init()

#  Database configuration to skein user management
skeinUserManagement.setDatabaseConfig({
    username: '<username>',
    password: '<password>',
    port: <port>,
    database: '<database>',
    dialect: '<dialect:mysql,postgresqk>',
    host: '<host>'
})

# If you use jwt custom token you have to set secret and jwt options
skeinUserManagement.setJwtSecret("Skein@2020")
skeinUserManagement.setJwtOptions({ expiresIn: "10d", issuer: "https://www.skeintech.com" })

# after all steps completed to need to migrate some features to your database it will create some tables for authentication
skeinUserManagement.migrate()

```

# sipper-app

# 1.1 Sequelize - For migrations
***********

# To create migrations
sequelize migration:create --name create_or_alter_<migrate_name>


# To create migrations
sequelize seed:create --name <seeder_name>


# To run migrations
sequelize db:migrate

sequelize-cli db:migrate --env development && sequelize db:seed:all --env development
# To run seeders
sequelize db:seed:all



# use vs code extensions to get clarity in comments
exodiusstudios.comment-anchors

"# reusable-alexa-oauth" 
