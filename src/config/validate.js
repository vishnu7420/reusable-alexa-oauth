export const SkeinValidator = (params = []) => {
    return async(req, res, next) => {

        let validation = params.map(item => {
            if (item["email"]) {
                return check
            }
        })

        await Promise.all(validations.map(validation => validation.run(req)));
        const errors = validationResult(req);
        if (errors.isEmpty()) {
            return next();
        } else {
            res.send(Response.paramsMissingResponse(errors.errors[0].msg, errors.array(), false, 422));
        }
    };
}