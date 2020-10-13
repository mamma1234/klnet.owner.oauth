'use strict';

const express = require('express');
const app = express();
const router = express.Router();

const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const crypto = require('crypto');

app.use(passport.initialize()); // passport 사용 하도록 세팅
app.use(passport.session()); // passport 사용 시 session을 활용

const isVerifyToken = (req,res,next) => {
    try {
        // console.log(req);

        // var AUTH_HEADER = "authorization",
        // LEGACY_AUTH_SCHEME = "JWT", 
        // BEARER_AUTH_SCHEME = 'bearer';
        
        // var extractors = {};
        let authorization;
        if (req.headers['authorization']) {
            authorization = req.headers['authorization'];
        }

        // console.log("req.headers", req.headers);
        //console.log("authorization", authorization);

        const re = /(\S+)\s+(\S+)/;
        const matches = authorization.match(re);

        // console.log("matches[1]", matches[1]);
        // console.log("matches[2]", matches[2]);
        const clientToken = matches[2];
        console.log("clientToken", clientToken);
        // const clientToken = req.cookies.user;
        // console.log("(middlewares.js) isVerifyToken clientToken", clientToken);
        const decoded = jwt.verify(clientToken, JWT_SECRET_KEY);
        console.log("(middlewares.js) decoded", decoded);
        if (decoded) {
            // console.log("(middlewares.js) decoded.user_id", decoded.user_id)
            // res.locals.userId = decoded.user_id;
            console.log("(middlewares.js) decoded.userno", decoded.userno)
            sUser.userno = decoded.userno;
            req.session.sUser = sUser;
            next();
        } else {
            console.log("(middlewares.js) isVerifyToken unauthorized");
            res.status(401).json({ errorcode: 401, error: 'unauthorized' });
        }
    } catch (err) {
        console.log("(middlewares.js) isVerifyToken token expired");
        res.status(401).json({ errorcode: 401, error: 'token expired' });
    }

};

const isLoggedPass = (req, res, next) => {
    console.log('1. isLoggedPass');
    next();
}


passport.serializeUser(function (user, done) { // 로그인 성공 시 콜백 함수 호출
    console.log('[SerializeUser]', user);
    done(null, user.authId); // 접속한 사용자의 식별 값이, session store에 user.authId로 저장
});

passport.deserializeUser(function (authId, done) { // 로그인 성공한 사용자가 웹 페이지 이동할 때 마다 콜백 함수 호출
    console.log('[DeserializeUser]', authId); // authId 인자에는 serializeUser 메소드에서 보낸 user.authId 값이 담김
    db.query(
        'SELECT * FROM users WHERE authId=?',
        [authId],
        function (err, results) {
        if (err) done(err);
        if (!results[0]) done(err);
        var user = results[0];
        done(null, user);
    });
});
  

passport.use('local',new LocalStrategy({
    usernameField: 'id',
    passwordField: 'pw',
    passReqToCallback: true
}, async (req, userid, password, done) => {
            console.log('3. LocalStrategy userid:', userid, 'password:', password);
            const inputpassword = crypto.pbkdf2Sync(password, 'salt', 100000, 64, 'sha512').toString('hex');
            
    try {

        // test용 pdk ship
        // sUser.provider = 'local';
        // sUser.userid = "test1@klnet.co.kr";
        // sUser.userno = "M000002";
        // sUser.username = "니꼬동",
        // sUser.displayName = 'web',
        // sUser.email = "test1@klnet.co.kr";
        // sUser.token_local = "";
        // req.session.sUser = sUser;
        // done(null, null);

        //console.log(userid, password);

        // console.log(".Input Password:"+crypto.pbkdf2Sync(password, 'salt', 100000, 64, 'sha512').toString('hex'));
        /*
            2020.01.21 pdk ship 
            userid, password 로 DB를 검색하여 존재하는지에 따라 프로세스 처리
        */
                    
        // const exUser = await User.find({ where: { email } });
        
        if(userid) {
            if(userid.toUpperCase() == "admin".toUpperCase()) {
                done(null, false, { message: 'ADMIN 아이디는 사용금지 아이디 입니다.' });
            } else {
                console.log("1.DB Connect");
                await pgsqlPool.connect(function(err,conn, release) { 
                    if(err){
                        console.log("err" + err);
                        if (conn)
                        {
                            release();
                        }
                    } else {
                    console.log("2.DB Select");
                    conn.query("select  * from own_comp_user where upper(local_id) = upper('"+userid+"')", function(err,result) {
                        if(err){
                            release();
                            console.log(err);
                        } else {
                            if(result.rows[0] != null) {
                                    console.log("3. select ok");  
                                const exUser = {userid, password}

                                //let resultSet = false; 
                                    // if (inputpassword == result.rows[0].local_pw.toString()) resultSet = true;
                                        // console.log("result:"+result);
                                        if(inputpassword == result.rows[0].local_pw.toString()) {
                                        console.log("4. pass check ok"); 

                                            sUser.provider = 'local';
                                        //sUser.userid = userid;
                                        sUser.userno = result.rows[0].user_no;
                                        sUser.username = result.rows[0].user_name,
                                        sUser.displayName = 'web',
                                        sUser.email = result.rows[0].user_email;
                                        sUser.usertype = result.rows[0].user_type;
                                        req.session.sUser = sUser;
                                        release();
                                        done(null, sUser);
                                        } else {
                                        console.log('아이디 또는 비밀번호가 일치하지 않습니다.');
                                        release();
                                        done(null, false, { message: '아이디 또는 비밀번호가 일치하지 않습니다.' });
                                        }   
                            } else {
                                console.log('가입되지 않은 회원입니다.');
                                release();
                                done(null, false, { message: '아이디 또는 비밀번호가 일치하지 않습니다.' });
                            }
                        }
                    });
                    // conn.release();
                    }
                });
            }
            console.log(">>>>>end");
        }else{
            done(null, false, { message: '필수 입력값이 누락되었습니다.' });
        }

    } catch(error) {
        console.log(">>>>>error",error);
        console.error(error);
        done(error);
    }
}));

app.post('/login', isLoggedPass, (req, res, next) => {
    console.log("2. (auth.js) req.isAuthenticated():", req.isAuthenticated());
    
    passport.authenticate('local',{session: false},(authError, user, info) => {
        console.log("authError:",authError,",user:",user,",info:",info);
        console.log("(auth.js) req.isAuthenticated():", req.isAuthenticated());
        if(authError) {
            console.error("authError", authError);
            return next(authError);
        }
        if(!user){
            console.log("!user", user);
            // req.flash('loginError', info.message);
            // return res.redirect('/');
            // return res.status(200).json(info);
            return res.status(401).json({ errorcode: 401, error: info.message });
            
        }

        return req.login(user,(loginError) => {
            console.log("user=====", user);

            if(loginError) {
                console.error("loginError", loginError);
                return next(loginError);
            }

            // return res.redirect('/');
            //res.status(200).json(user);
            //return;
            //return res.redirect('http://localhost:3000');
            //console.log("log:",user.userno);
            //토큰 발행
            const token = jwt.sign({userno:user.userno}, process.env.JWT_SECRET_KEY, { expiresIn : '1h', });
            //토큰 저장
            //var ipaddr = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
            var ipaddr = requestIp.getClientIp(req);
           // console.log("ip1:",req.headers['x-forwarded-for']);
           // console.log("ip2:",requestIp.getClientIp(req));
            
            pgSql.setUserToken(user, token);
            pgSql.setLoginHistory(user.userno,'I',req.useragent, ipaddr);
            
            
            //console.log("token value:"+token);
            /*res.cookie("connect.sid",token);
            res.cookie("connect.userno",user.userno);*/
            return res.json({user:user, token:token});

        });
    })(req, res, next)  //미들웨어 내의 미들웨어에는 (req, res, next)를 붙인다.
});


app.listen(4000, () => console.log(`Listening on port 4000`));