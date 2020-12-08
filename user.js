const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const saltRounds = 10 //tamaño de encriptacion

// User Schema
const userSchema = new mongoose.Schema({
    username: {type: String,    
                require: true,
                unique: true},
    password: {type: String, require: true}
})

userSchema.pre('save', function(next) {
    if(this.isNew || this.isModified('password')) {
        const document = this;
        bcrypt.hash(document.password, saltRounds, (err, hashedPassword) => {
            if(err) {
                next(err)
            } else {
                document.password = hashedPassword
                next();
            }
        });
    } else {
        next();
    }
})

userSchema.methods.isPSWcorrect = function(password, callback) {
    bcrypt.compare(password, this.password, function(err, same) {
        if(err) {
            callback(err)
        } else {
            callback(err, same);
        }
    });
}

module.exports = mongoose.model('user', userSchema)
