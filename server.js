'use strict';

const express = require('express');
const session = require('express-session');
const app = express();
// const router = express.Router();

const flash = require('connect-flash');

const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

// const passportConfig = require('./passport');
// passportConfig(passport);

const bodyParser = require("body-parser");
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const requestIp = require('request-ip');
const useragent = require('express-useragent');
const { Client } = require('pg');

app.use(flash()); //connect-flash: 일회성 메시지들을 웹 브라우저에 나타낼 때 사용한다. cookie-parser와 express-session 뒤에 위치해야한다.

app.use(useragent.express());

app.use(session({secret:`비밀코드`, resave:true, saveUninitialized:false})); //세션 활성화

app.use(passport.initialize()); // passport 사용 하도록 세팅
app.use(passport.session()); // passport 사용 시 session을 활용

app.use(bodyParser.json()); //요청의 본문을 해석해주는 미들웨어 1
app.use(bodyParser.urlencoded({ extended: true })); //요청의 본문을 해석해주는 미들웨어 2


app.set('view engine', 'pug'); //템플리트 엔진을 사용 2


const connectionString = "postgresql://owner:!ghkwn_20@172.19.1.22:5432/owner";
const JWT_SECRET_KEY = "plismplus";


// const pool = new Pool({
//     connectionString:  "postgresql://owner:!ghkwn_20@172.19.1.22:5432/owner",
//     max: 20,
//     min: 4,
//     idleTimeoutMillis: 10000,
//     connectionTimeoutMillis: 10000
// });

const client = new Client({
    connectionString: connectionString
});

// client.connect();

// passport.serializeUser(function (user, done) { // 로그인 성공 시 콜백 함수 호출
//     console.log('[SerializeUser]', user); 
//     //req.session.passport.user 에 저장
//     done(null, user); // 접속한 사용자의 식별 값이, session store에 user.authId로 저장  
// });

// passport.deserializeUser(function (user, done) { // 로그인 성공한 사용자가 웹 페이지 이동할 때 마다 콜백 함수 호출
//     console.log('[DeserializeUser]', user.id); // authId 인자에는 serializeUser 메소드에서 보낸 user.authId 값이 담김

//     if (user.id === 'admin' && user.token === '1234'){
//         done(null, user);
//     } else {
//         done(null, false, { message: '다시 로그인 하시기 바랍니다.' });
//     }

// });


const sUser = {
    provider:'',
    userno:'',
    userid:'',
    usertype:'',
    email:'',
    accessToken:'',
    refreshToken:'',
    username:'',
    displayName:'',
    token:''
};

const getUser = (id) => {
    console.log('getUser ....');
    client.connect();
    client.query("select  * from own_comp_user where upper(local_id) = upper($1)", [id], function(err,result) {

        console.log('query.....');
        client.end();
        if (err) {
            console.log(err);
            // done(null, false, { message: '존재하지 않는 아이디 입니다.' });
            return null;
        } else {
            console.log("query result.rows:", result.rows);
            // console.log("query log:", err, result);
            // response.status(200).json(result.rows);    
            if (result.rows.length < 1) {
                // done(null, false, { message: '존재하지 않는 아이디 입니다.' });
                return null;
            } else {
                return result.rows[0];
            }
        }
        // console.log('end query.....');
        
    });
};


const getUserAsync = async (id) => {
    console.log('getUser ....');
    await client.connect();
    await client.query("select  * from own_comp_user where upper(local_id) = upper($1)", [id], function(err,result) {

        console.log('query.....');
        client.end();
        if (err) {
            console.log(err);
            // done(null, false, { message: '존재하지 않는 아이디 입니다.' });
            return null;
        } else {
            console.log("query result.rows:", result.rows);
            // console.log("query log:", err, result);
            // response.status(200).json(result.rows);    
            if (result.rows.length < 1) {
                // done(null, false, { message: '존재하지 않는 아이디 입니다.' });
                return null;
            } else {
                return result.rows[0];
            }
        }
        // console.log('end query.....');
        
    });
};


passport.use('local',new LocalStrategy({
    usernameField: 'id',
    passwordField: 'pw',
    passReqToCallback: true
}, async (req, id, password, done) => {
    console.log('3. LocalStrategy id:', id, 'pw:', password);
    const inputpassword = crypto.pbkdf2Sync(password, 'salt', 100000, 64, 'sha512').toString('hex');
    console.log(inputpassword)
    try {
        

        const token = jwt.sign({userno:"M000005"}, JWT_SECRET_KEY, { expiresIn : '1h', });
        sUser.provider = 'local';
        sUser.userid = id;
        sUser.userno = "M000005";
        sUser.username = "판토스";
        sUser.displayName = 'web';
        sUser.email = "null";
        sUser.usertype = 'O';
        sUser.token = token;
        done(null, sUser);


        // console.log(req.url, req.baseUrl, req.fullUrl);
        // const row = getUser(id);
        // console.log('row', row);
        // done(null, row); 

        // client.connect();
        client.query("select  * from own_comp_user where upper(local_id) = upper($1)", [id], function(err,result) {
            // client.end();
            if (err) {
                console.log(err);
                done(null, false, { message: '존재하지 않는 아이디 입니다.' });
            } else {
                // console.log("query result.rows:", result.rows);
                // console.log("query log:", err, result);
                // response.status(200).json(result.rows);    
                if (result.rows.length < 1) {
                    done(null, false, { message: '존재하지 않는 아이디 입니다.' });
                } else {

                    if(result.rows[0] != null) {
                        if(inputpassword == result.rows[0].local_pw.toString()) {
                            const token = jwt.sign({userno:result.rows[0].user_no}, JWT_SECRET_KEY, { expiresIn : '1h', });
                            sUser.provider = 'local';
                            sUser.userid = id;
                            sUser.userno = result.rows[0].user_no;
                            sUser.username = result.rows[0].user_name,
                            sUser.displayName = 'web',
                            sUser.email = result.rows[0].user_email;
                            sUser.usertype = result.rows[0].user_type;
                            sUser.token = token;
                            // console.log('sUser', sUser.provider);

                            // callback type
                            if (req.url === '/oauth/authorize' ) {
                                console.log('result.rows[0]', result.rows[0].api_service_key)
                                if(req.body.client_id === result.rows[0].api_service_key) {
                                    done(null, sUser); 
                                } else {

                                    console.log(req.body.client_id, ':', result.rows[0].api_service_key)

                                    done(null, false, { message: 'client id 가 일치하지 않습니다.' });
                                }
                            } else {
                                done(null, sUser); 
                            }

                        } else {
                            done(null, false, { message: '아이디 또는 비밀번호가 일치하지 않습니다.' });
                        }

                    } else {
                        done(null, false, { message: '존재하지 않는 아이디 입니다.' });
                    }

                }
            }
        });
        


    } catch(error) {
        console.log(">>>>>error",error);
        console.error(error);
        done(error);
    }
}));

app.post('/oauth/login2', 
    passport.authenticate('local', { successRedirect:'/', 
                                     failureRedirect:'/login',
                                     failureFlash: true })
);

app.get('/oauth/v2/authorize',  (req,res) => { console.log('oauth v2 authorize'); res.send('oauth v2 authorize');  } );

app.get('/oauth/authorize',  (req,res) => { console.log('6. oauth authorize'); res.send('oauth authorize');  } );


app.post('/oauth/authorize', (req, res, next) => {
    console.log("2. (auth.js) req.isAuthenticated():", req.isAuthenticated());

    passport.authenticate('local',{session: false},(authError, user, info) => {
        console.log("4. authError:",authError,",user:",user,",info:",info);
        // console.log("(auth.js) req.isAuthenticated():", req.isAuthenticated());

        // const token = jwt.sign({userno:user.userno}, `plismplus`, { expiresIn : '1h', });
        // console.log("5. token:", token)
        // return res.redirect('/success');




        if(!user){
            return res.status(401).json({ errorcode: 401, error: info.message });
        } else {

            // client.connect();
            client.query("UPDATE OWN_COMP_USER SET token_local=$1 , local_login_date= now() WHERE user_no=$2", [user.token, user.userno], function(err,result) {
                // client.end();
                if (err) {
                    console.log(err);
                } 
                // else {
                //     console.log("query result.rows:", result);
                // }
            });

            const ipaddr = requestIp.getClientIp(req);
            // console.log(req);
            client.query("insert into own_login_history(history_Seq,user_no,inout_type,device_type,os_name,browser_name,browser_version,ip_addr)values(to_char(now(),'YYYYMMDDHH24miss')||nextval('own_history_seq'),$1,$2,$3,$4,$5,$6,replace($7,'::ffff:',''))"
                , [user.userno, 'I', req.useragent.isMobile?'M':'P',req.useragent.os,req.useragent.browser,req.useragent.version,ipaddr], 
                function(err,result) {
                    // client.end();
                    if (err) {
                        console.log(err);
                    } 
                    // else {
                    //     console.log("query result.rows:", result);
                    // }
                }
            );

            // return res.json({user:user, token:user.token});

            console.log("5. req.body.redirect_uri:",req.body.redirect_uri);

            return res.redirect(req.body.redirect_uri);

        }
        
    })(req, res, next)  //미들웨어 내의 미들웨어에는 (req, res, next)를 붙인다.
});


app.post('/oauth/login', (req, res, next) => {
    console.log("2. (auth.js) req.isAuthenticated():", req.isAuthenticated());

    passport.authenticate('local',{session: false},(authError, user, info) => {
        console.log("4. authError:",authError,",user:",user,",info:",info);
        // console.log("(auth.js) req.isAuthenticated():", req.isAuthenticated());

        // const token = jwt.sign({userno:user.userno}, `plismplus`, { expiresIn : '1h', });
        // console.log("5. token:", token)
        // return res.redirect('/success');




        if(!user){
            return res.status(401).json({ errorcode: 401, error: info.message });
        } else {

            // client.connect();
            client.query("UPDATE OWN_COMP_USER SET token_local=$1 , local_login_date= now() WHERE user_no=$2", [user.token, user.userno], function(err,result) {
                // client.end();
                if (err) {
                    console.log(err);
                } 
                // else {
                //     console.log("query result.rows:", result);
                // }
            });

            const ipaddr = requestIp.getClientIp(req);
            // console.log(req);
            client.query("insert into own_login_history(history_Seq,user_no,inout_type,device_type,os_name,browser_name,browser_version,ip_addr)values(to_char(now(),'YYYYMMDDHH24miss')||nextval('own_history_seq'),$1,$2,$3,$4,$5,$6,replace($7,'::ffff:',''))"
                , [user.userno, 'I', req.useragent.isMobile?'M':'P',req.useragent.os,req.useragent.browser,req.useragent.version,ipaddr], 
                function(err,result) {
                    // client.end();
                    if (err) {
                        console.log(err);
                    } 
                    // else {
                    //     console.log("query result.rows:", result);
                    // }
                }
            );

            return res.json({user:user, token:user.token});
        }
        
    })(req, res, next)  //미들웨어 내의 미들웨어에는 (req, res, next)를 붙인다.
});


app.post('/oauth/logout',  (req, res) => {
    //console.log(">>>>>LOG OUT SERVER");
    
    let authorization;
    if (req.headers['authorization']) {
        authorization = req.headers['authorization'];
    }
    // console.log("authorization", authorization);
    const re = /(\S+)\s+(\S+)/;
    const matches = authorization.match(re);
    const clientToken = matches[2];
    const decoded = jwt.verify(clientToken, process.env.JWT_SECRET_KEY);
    
  //   jwt.destroy(clientToken);
  //   db.update token clear
    //console.log("session:",req.session.sUser);
    //var ipaddr = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  	console.log("ID",decoded.userno);
  	
    var ipaddr = requestIp.getClientIp(req);
    if(decoded && decoded.user != undefined) {
    	// client.connect();
        client.query("UPDATE OWN_COMP_USER SET token_local=$1 , local_login_date= now() WHERE user_no=$2", ['', decoded.userno], function(err,result) {
            // client.end();
            if (err) {
                console.log(err);
            } 
            // else {
            //     console.log("query result.rows:", result);
            // }
        });

        const ipaddr = requestIp.getClientIp(req);
        // console.log(req);
        client.query("insert into own_login_history(history_Seq,user_no,inout_type,device_type,os_name,browser_name,browser_version,ip_addr)values(to_char(now(),'YYYYMMDDHH24miss')||nextval('own_history_seq'),$1,$2,$3,$4,$5,$6,replace($7,'::ffff:',''))"
            , [decoded.userno, 'O', req.useragent.isMobile?'M':'P',req.useragent.os,req.useragent.browser,req.useragent.version,ipaddr], 
            function(err,result) {
                // client.end();
                if (err) {
                    console.log(err);
                } 
                // else {
                //     console.log("query result.rows:", result);
                // }
            }
        );
    }
    req.logout();
   // res.clearCookie('connect.sid',{ path: '/' });
    res.clearCookie('express:sess',{ path: '/' });
    res.clearCookie('express:sess.sig',{ path: '/' });
    //console.log(":>>>");
    res.send(false);
      
});



app.get('/oauth/', (req, res) => {
    res.render('index', {
        title: 'Klnet Oauth2.0',
        message: 'Hello!'
    });
});

app.get('/oauth/join', (req, res) => {

    //http://localhost:5002/oauth/join?client_id=bWFtbWEgTTAwMDAwMA==&redirect_uri=http://localhost:5000/auth/klnet/callback&response_type=code&state=12345
    //http://localhost:5002/oauth/join?client_id=bWFtbWEgTTAwMDAwMA==&redirect_uri=https://dev.plismplus.com/auth/klnet/callbak&response_type=code&state=12345

    console.log('client_id:', req.query['client_id']); //Profile page api key bWFtbWEgTTAwMDAwMA==
    console.log('redirect_uri:', req.query['redirect_uri']); //https://dev.plismplus.com/auth/klnet/callback
    //http://localhost:5000/auth/klnet/callback
    console.log('response_type:', req.query['response_type']); //code
    console.log('state:', req.query['state']); //12345
    let client_id = req.query['client_id'];
    let redirect_uri = req.query['redirect_uri'];
    let response_type = req.query['response_type'];
    let state = req.query['state'];
    res.render('join', {
        title: '회원가입',
        client_id: client_id,
        redirect_uri: redirect_uri,
        response_type: response_type,
        state: state,
        joinError: req.flash('joinError'),
    });
});

app.listen(5002, () => console.log(`Listening on port 5002`));