export default class Mailer {


    /** Mailer constructor we need to pass
     * @param google_email_id (e.g. example@gmail.com)
     * @param google_email_password (e.g. password)
     */
    constructor({ google_email_id, google_email_password }) {

        /** Google email id */
        this.google_email_id = google_email_id

        /** Google email password */
        this.google_email_password = google_email_password

        /** Initializing transporter via nodemailer */
        this.transporter = nodemailer.createTransport({

            /** Have to pass service as gmail to create transport */
            service: 'gmail',
            /** Authentication */
            auth: {
                /** Email */
                user: this.google_email_id,
                /** Password */
                pass: this.google_email_password
            }
        });
    }

    /**
     * 
     * @param {email_id} to 
     * @param {subject of email} subject 
     * @param {text email} text 
     * @param {HTML content} html 
     * @return Promise
     */
    sendMail(to, subject, text, html = null) {
        /** Inititating promise */
        return new Promise((resolve, reject) => {

            /** Mail options */
            let mailOptions = {
                /** Set from */
                from: this.google_email_id,
                /** Set to it will be an array or a string */
                to: to,
                /** Mail subject */
                subject: subject,
                /** Mail text */
                text: text,

            };

            /** If we passed html content */
            if (html) {

                /** Assigning html content field in mail options */
                mailOptions = {
                    ...mailOptions,

                    ... {
                        html: html
                    }
                }
            }

            /** Call send mail function through send mail */
            this.transporter.sendMail(mailOptions,
                /**
                 * Call back function gives an success or failure callback
                 * @param {error in send mail} error 
                 * @param {mail information} info 
                 */
                function(error, info) {
                    if (error) {
                        console.log(error);
                        /** Reject if error */
                        reject(error)
                    } else {
                        console.log('Email sent: ' + info.response);
                        /** Resolve if success response */
                        resolve(info.response)
                    }
                });
        })
    }
}