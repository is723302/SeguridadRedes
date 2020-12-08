const express = require('express')
const path = require('path')
const bodyParser = require('body-parser')
const mongoose = require('mongoose')
const speakeasy = require('speakeasy')
const qrcode = require('qrcode')
const fs = require('fs')
const multer = require('multer')
const crypto = require('crypto')

const mongo_uri = "mongodb+srv://dbAdmin:dbadmin@auth.663cv.mongodb.net/auth?retryWrites=true&w=majority";
const User = require('./user')

const app = express()

const secret = speakeasy.generateSecret({
    name: 'Authentication Secret'
})

//************************************************************************************************
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({
    extended: false
}))

app.use(express.static(path.join(__dirname, 'public')))

// Mongo DB Conection
mongoose.connect(mongo_uri, { useNewUrlParser: true, useUnifiedTopology: true }, function (err, db) {
    if (err) {
        console.log(err);
    }
    else {
        console.log('Connected to ' + mongo_uri);
        db.close();
    }
})

// Home
app.get('/', (req, res) => {

})

// User Sing up 
app.post('/register', (req, res) => {
    const {
        username,
        password
    } = req.body;
    const user = new User({
        username,
        password
    })
    user.save(err => {
        if (err) {
            res.status(500).send('Failed to register')
        } else {
            res.status(200).send('Success registering')
        }
    })
})

// User Login
app.post('/login', (req, res) => {
    console.log(secret);

    qrcode.toDataURL(secret.otpauth_url, function (err, data) {
        console.log(data);
    })
    const {
        username,
        password
    } = req.body;
    User.findOne({
        username
    }, (err, user) => {
        if (err) {
            res.status(200).send('Failed authentication')
        } else if (!user) {
            res.status(500).send('User has not been found, try again')
        } else {
            user.isPSWcorrect(password, (err, result) => {
                if (err) {
                    res.status(500).send('Failed authentication')
                } else if (result) {
                    res.status(200).redirect('/qrcode')
                } else {
                    res.status(500).send('Incorrect username or password')
                }
            })
        }
    })
})


// Verify speakeasy
app.get('/verify', (req, res) => {
    let verified = speakeasy.totp.verify({
        secret: secret.ascii,
        encoding: 'ascii',
        token: req.query.token
    })

    console.log(verified);
    if (verified == true) {
        console.log('Success');
        res.status(200).send('Correct Token')
    } else {
        console.log('Incorrect');
        res.status(500).send('Try again')
    }
})


// QR code 
app.get('/qrcode', (req, res) => {
    qrcode.toDataURL(secret.otpauth_url, function (err, data_url) {
        res.end('<!DOCTYPE html>\
    <html lang="en">\
    <head>\
        <link href="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css" rel="stylesheet" id="bootstrap-css">\
        <script src="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/js/bootstrap.min.js"></script>\
        <script src="//cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>\
        <meta charset="UTF-8">\
        <link rel="stylesheet" href="style.css">\
        <meta name="viewport" content="width=device-width, initial-scale=1.0">\
        <title>Login</title>\
    </head>\
    <body>\
        <div id="login">\
            <div class="container">\
                <div id="login-row" class="row justify-content-center align-items-center">\
                    <div id="login-column" class="col-md-6">\
                        <div id="login-box" class="col-md-12">\
                            <form id="login-form" class="form" method="get" action="/verify">\
                                <h3 class="text-center text-info">Codigo QR</h3>\
                                <img src="' + data_url + '" alt="qr">\
                                <p>Generated key: "' + secret.ascii + '"  </p>\
                                <div class="form-group">\
                                    <label for="token" class="text-info">token:</label><br>\
                                    <input type="text" name="token" id="token" class="form-control">\
                                </div>\
                                <div class="form-group">\
                                <button onclick="verify()">Verify Token</button>\
                                </div>\
                            </form>\
                        </div>\
                    </div>\
                </div>\
            </div>\
        </div>\
    </body>\
    </html>');
    });
})

// File Storage
var storage = multer.diskStorage({
    destination: function (req, file, callback) {
        callback(null, './uploads');
    },
    filename: function (req, file, callback) {
        callback(null, 'file.txt');
    }
});
var upload = multer({ storage: storage }).single('txt');


// File upload
app.get('/upload', (req,res)=>{
    res.status(200).sendFile(__dirname + '/public/upload.html')
})

app.post('/upload',function(req,res){
    upload(req,res,function(err) {
        if(err) {
            return res.end("Failed to upload file");
        }
        console.log("File has been successfully uploaded");
        fs.readFile('uploads/file.txt', 'utf8', function(err, data) {
            if (err) throw err;
            const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
                modulusLength: 2048, 
            })
            
            console.log(
                publicKey.export({
                    type: "pkcs1",
                    format: "pem",
                }),
            
                privateKey.export({
                    type: "pkcs1",
                    format: "pem",
                })
            )
            
            const encryptedData = crypto.publicEncrypt(
                {
                    key: publicKey,
                    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                    oaepHash: "sha256",
                },
                Buffer.from(data)
            )
            
            console.log("encypted data: ", encryptedData.toString("base64"))
            
            const decryptedData = crypto.privateDecrypt(
                {
                    key: privateKey,
                    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                    oaepHash: "sha256",
                },
                encryptedData
            )
            
            console.log("decrypted data: ", decryptedData.toString())
            
            const verifiableData = data
            
            const signature = crypto.sign("sha256", Buffer.from(verifiableData), {
                key: privateKey,
                padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            })
            
            console.log(signature.toString("base64"))
            
            const isVerified = crypto.verify(
                "sha256",
                Buffer.from(verifiableData),
                {
                    key: publicKey,
                    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                },
                signature
            )
            
            console.log(isVerified)
        
        });
        
    });
});

app.listen(3000, () => {
    console.log('Running');
})

module.exports = app;