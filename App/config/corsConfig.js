const cors = require('cors');

const configureCors = () => {
    const whitelist = ['http://localhost:3000','www.example.com','www.somthing.com'];
    const corsOptions = {
        origin: (origin, callback) => {
            if (whitelist.indexOf(origin) !== -1 || !origin) {
                callback(null, true);//given access to the client
            } else {
                callback(new Error('Not allowed by CORS'));
            }
        },
        methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
        allowedHeaders: ['Content-Type', 'Authorization','Accept-Version','Origin','x-access-token'],
        exposedHeaders:['X-Total-Count','Content-Range','Link'],
        preflightContinue: false,
        maxAge: 600, //catch preeflight requests 10 minutes
        optionsSuccessStatus: 204,
    };
    return cors(corsOptions);
};


module.exports = configureCors;