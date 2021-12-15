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
// const { Client } = require('pg');
const pgdb = require( './database/postgres.js');
const oracledb = require('./database/oracle.js');
// const oracledb = require('oracledb');
// const { response } = require('express');
// const http = require('http');

require('dotenv').config();
const PRODUCTION = process.env.PRODUCTION;

app.use(flash()); //connect-flash: 일회성 메시지들을 웹 브라우저에 나타낼 때 사용한다. cookie-parser와 express-session 뒤에 위치해야한다.

app.use(useragent.express());

app.use(session({secret:`비밀코드`, resave:true, saveUninitialized:false})); //세션 활성화

app.use(passport.initialize()); // passport 사용 하도록 세팅
app.use(passport.session()); // passport 사용 시 session을 활용

app.use(bodyParser.json()); //요청의 본문을 해석해주는 미들웨어 1
app.use(bodyParser.urlencoded({ extended: true })); //요청의 본문을 해석해주는 미들웨어 2

app.get('/testLogin',function(req,res){
    req.sendFile(__dirname+'/loginTest.html')
})

// app.set('view engine', 'pug'); //템플리트 엔진을 사용 2
app.set('view engine', 'ejs'); 
//0609ssong//////////////////////
app.set('views',__dirname+'/views');


///////////////////////
//const connectionString = "postgresql://owner:!ghkwn_20@172.19.1.22:5432/owner";
//const connectionString = "postgresql://owner:!ghkwn_20@172.21.1.199:5432/owner";
const JWT_SECRET_KEY = "plismplus";


// const pool = new Pool({
//     connectionString:  "postgresql://owner:!ghkwn_20@172.19.1.22:5432/owner",
//     max: 20,
//     min: 4,
//     idleTimeoutMillis: 10000,
//     connectionTimeoutMillis: 10000
// });

// const client = new Client({
//     connectionString: connectionString
// });

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



app.get('/oauth/oracletest', (req, res) => {

    const sql = "SELECT sysdate, sysdate FROM dual";
    oracledb.getConnection(function (err, conn) {
        conn.execute(sql, (error, results) => {
            if (error) {
                conn.close(function(er) { 
                    if (er) {
                        console.log('Error closing connection', er);
                    } else {
                        console.log('Connection closed');
                    }
                });
                res.status(400).json({ "error": error.message });
                return;
            }

            conn.close(function(er) { 
                if (er) {
                    console.log('Error closing connection', er);
                } else {
                    console.log('Connection closed');
                }
            });            
            // response.send(results);
            res.send(results.rows);
        });  
    });
});

app.get('/oauth/postgresqltest', (req, res) => {

    pgdb.query("select now()", function (err, result) {

        if (err) {
            res.status(400).json({ "error": error.message });
            return;
        } 
        console.log("query result.rows:", result.rows);
        // console.log("query log:", err, result);
        // response.status(200).json(result.rows);    

        res.send(result.rows);
    
        // console.log('end query.....');
    });
});

/*
function getUser(id) {
    console.log('getUser ....');
    // client.connect();
    pgdb.query("select  * from own_comp_user where upper(local_id) = upper($1)", [id], function (err, result) {

        console.log('query.....');
        // client.end();
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
}

const getUserAsync = async (id) => {
    console.log('getUser ....');
    // await client.connect();
    pgdb.query("select  * from own_comp_user where upper(local_id) = upper($1)", [id], function(err,result) {

        console.log('query.....');
        // client.end();
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
*/
/*
passport.use('local',new LocalStrategy({
    usernameField: 'id',
    passwordField: 'pw',
    passReqToCallback: true
}, async (req, id, password, done) => {
    console.log('3. LocalStrategy id:', id, 'pw:', password);
    const inputpassword = crypto.pbkdf2Sync(password, 'salt', 100000, 64, 'sha512').toString('hex');
    console.log('password:', inputpassword);
    try {
        
        // console.log(req.url, req.baseUrl, req.fullUrl);
        // const row = getUser(id);
        // console.log('row', row);
        // done(null, row); 

        // client.connect();
        //client.query("select  * from own_comp_user where upper(local_id) = upper($1)", [id], function(err,result) {
        pgdb.query("select  * from own_comp_user where local_id = $1", [id], function(err,result) {
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
        console.error(error);
        done(error);
    }
}));


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


app.post('/oauth/login2', 
    passport.authenticate('local', { successRedirect:'/', 
                                     failureRedirect:'/login',
                                     failureFlash: true })
);

app.get('/oauth/v2/authorize',  (req,res) => { console.log('oauth v2 authorize'); res.send('oauth v2 authorize');  } );

app.get('/oauth/authorize',  (req,res) => { console.log('6. oauth authorize'); res.send('oauth authorize');  } );
*/



app.post('/oauth/access_token', (req, res, next) => {
    console.log('1. /oauth/access_token');

    console.log('req.body=', req.body);

    if ( req.body.grant_type === 'refresh_token' 
        // && req.body.redirect_uri === 'http://localhost:5000/auth/klnet/callback'
        && req.body.client_id === '5vSPppBEGLWEwMT8p9kZ'
        && req.body.client_secret === 's94tuPZ0Go'){

        const refreshToken = req.body.refresh_token;
        const refresh_token_decoded = jwt.verify(refreshToken, JWT_SECRET_KEY);
        const user_no = refresh_token_decoded.userno;

        console.log('user_no:', user_no);

        oracledb.getConnection(function (err, conn) {
            conn.execute("select * from do_comp_user_tbl where user_id = :1 and klnet_refresh_token = :2 ", {1:user_no, 2:refreshToken}, {outFormat:oracledb.OBJECT},(err, result) => {
                if (err) {
                    console.log(err);
                    // return res.json({access_token:accessToken, refresh_token:refreshToken, expires_in : '3600', token_type:"bearer"});
                    conn.close(function(er) { 
                        if (er) {
                            console.log('Error closing connection', er);
                        } else {
                            console.log('Connection closed');
                        }
                    });                    
                    return res.json();
                } else {
// console.log(('result:', result));
                    if (result.rows.length < 1) {
                        conn.close(function(er) { 
                            if (er) {
                                console.log('Error closing connection', er);
                            } else {
                                console.log('Connection closed');
                            }
                        });                        
                        return res.json();
                    } else {
                        const accessToken = jwt.sign({userno:result.rows[0].USER_ID}, JWT_SECRET_KEY, { expiresIn : 7200, }); //60*60 = 1h (3600)
                        
                        conn.execute("update do_comp_user_tbl set klnet_access_token=:1, last_login_date=sysdate where user_id=:2 ", {1:accessToken, 2:result.rows[0].USER_ID}, {outFormat:oracledb.OBJECT},(err, result) => {
                            if (err) {                            
                                console.log(err);
                            } 
        
                            // console.log('result=', result);

                            (async () => {
                                await conn.commit();
                                console.log('2. /oauth/access_token accessToken:', accessToken, ',refreshToken:', refreshToken);
                                conn.close(function(er) { 
                                    if (er) {
                                        console.log('Error closing connection', er);
                                    } else {
                                        console.log('Connection closed');
                                    }
                                });   
                                return res.json({access_token:accessToken, refresh_token:refreshToken, expires_in : 3600, token_type:"bearer"});
    
                            })().then(ret=> {console.log("[RETURN]");} ).catch(err => {console.log("[ERROR]",err)} )                            
                        });
        
                    }
                }

            });
        });    


    };


});

app.post('/oauth/token', (req, res, next) => {
    console.log('1. /oauth/token');
    
    if ( req.body.grant_type === 'authorization_code' 
        // && req.body.redirect_uri === 'http://localhost:5000/auth/klnet/callback'
        && req.body.client_id === '5vSPppBEGLWEwMT8p9kZ'
        && req.body.client_secret === 's94tuPZ0Go'){

        // console.log('req.body=', req.body);
        console.log('req.body.code=', req.body.code);

        // if(req.cookies['socialKey']) {
        //     const socialKey = req.cookies['socialKey'];
        //     console.log('1. /oauth/token socialKey(auth token, user_id 추가 로직 필요할까?)=', socialKey);
        // }

        oracledb.getConnection(function (err, conn) {
            conn.execute("select * from do_comp_user_tbl where klnet_auth_code = :1 and klnet_auth_date <= sysdate and klnet_auth_date >= sysdate-1/24 ", {1:req.body.code}, {outFormat:oracledb.OBJECT},(err, result) => {
                if (err) {
                    console.log(err);
                    // return res.json({access_token:accessToken, refresh_token:refreshToken, expires_in : '3600', token_type:"bearer"});
                    conn.close(function(er) { 
                        if (er) {
                            console.log('Error closing connection', er);
                        } else {
                            console.log('Connection closed');
                        }
                    });                       
                    return res.json();
                } else {
// console.log(('result:', result));
                    if (result.rows.length < 1) {
                        conn.close(function(er) { 
                            if (er) {
                                console.log('Error closing connection', er);
                            } else {
                                console.log('Connection closed');
                            }
                        });                           
                        return res.json();
                    } else {
                        const accessToken = jwt.sign({userno:result.rows[0].USER_ID}, JWT_SECRET_KEY, { expiresIn : 7200, }); //60*60 = 2h (7200)
                        const refreshToken = jwt.sign({userno:result.rows[0].USER_ID}, JWT_SECRET_KEY, { expiresIn : 172800, }); //60*60*48 = 48h

                        const ipaddr = requestIp.getClientIp(req);
                        let sql = "update do_comp_user_tbl set klnet_access_token=:1, klnet_refresh_token=:2 where user_id=:4"
                        let binds = {1:accessToken, 2:refreshToken, 4:result.rows[0].USER_ID}

                        // console.log('ipaddr:',ipaddr);

                        // const re = /^localhost$|^127(?:\.[0-9]+){0,2}\.[0-9]+$|^(?:0*\:)*?:?0*1$|::/;
                        // let sql;
                        // let binds;
                        // console.log('>>>>>>re test:', re.test(ipaddr))
                        // if ( re.test(ipaddr)){
                        //     console.log(ipaddr, ' >>> not update last_login_ip')
                        //     sql = "update do_comp_user_tbl set klnet_access_token=:1, klnet_refresh_token=:2, last_login_date=sysdate where user_id=:4"
                        //     binds = {1:accessToken, 2:refreshToken, 4:result.rows[0].USER_ID}
                        // }else{ 
                        //     console.log(ipaddr, ' >>> update with last_login_ip')

                        //     sql = "update do_comp_user_tbl set klnet_access_token=:1, klnet_refresh_token=:2, last_login_date=sysdate, last_login_ip=:3 where user_id=:4"
                        //     binds = {1:accessToken, 2:refreshToken, 3:ipaddr, 4:result.rows[0].USER_ID}
                        // }
                             


                        conn.execute(sql, binds, {outFormat:oracledb.OBJECT},(err, result) => {
                            if (err) {
                                console.log(err);
                            } 
        
                            // console.log('result=', result);
 

                            (async () => {
                                await conn.commit();
                                console.log('1. /oauth/token accessToken:', accessToken, ',refreshToken:', refreshToken);
                                conn.close(function(er) { 
                                    if (er) {
                                        console.log('Error closing connection', er);
                                    } else {
                                        console.log('Connection closed');
                                    }
                                });   
                                return res.json({access_token:accessToken, refresh_token:refreshToken, expires_in : 3600, token_type:"bearer"});    
    
                            })().then(ret=> {console.log("[RETURN]");} ).catch(err => {console.log("[ERROR]",err)} )                                  
                        });
        
                    }
                }

            });
        });    

        

    }
 


});

app.get('/oauth/userinfo', (req, res) => {
    console.log('1. /oauth/userinfo call', req.headers.authorization);

    const bearerHeader = req.headers.authorization;
    if (bearerHeader) {
        const bearer = bearerHeader.split(' ');
        const bearerToken = bearer[1];
        const decoded = jwt.verify(bearerToken, process.env.JWT_SECRET_KEY);
        console.log("ID",decoded.userno);

        oracledb.getConnection(function (err, conn) {
            conn.execute("select * from do_comp_user_tbl where user_id = :1 and klnet_access_token = :2 ", {1:decoded.userno, 2:bearerToken}, {outFormat:oracledb.OBJECT},(err, result) => {
                if (err) {
                    console.log(err);
                    conn.close(function(er) { 
                        if (er) {
                            console.log('Error closing connection', er);
                        } else {
                            console.log('Connection closed');
                        }
                    });                       
                    return res.json({resultcode:'024', message:'Authentication failed' });
                } else {
// console.log(('result:', result));

                    if (result.rows.length < 1) {
                        conn.close(function(er) { 
                            if (er) {
                                console.log('Error closing connection', er);
                            } else {
                                console.log('Connection closed');
                            }
                        });   
                        return res.json({resultcode:'024', message:'Authentication failed' });
                    } else {
                        conn.close(function(er) { 
                            if (er) {
                                console.log('Error closing connection', er);
                            } else {
                                console.log('Connection closed');
                            }
                        });   
                        return res.json({resultcode:'00', message:'success', response : {id:result.rows[0].USER_ID, email:result.rows[0].EMAIL, name:result.rows[0].UNAME_KR, displayName:result.rows[0].UNAME_KR, local_id:result.rows[0].USER_ID}});    
                    }
                }

            });
        });   

    }

});


app.post('/oauth/authorize', (req, res, next) => {
    // console.log(req);
    console.log('1. 시작 authorize................');
    // console.log('/oauth/authorize:', req.body);
    
    let fullUrl = req.protocol + '://' + req.headers.host + req.originalUrl;
    let param = '&client_id='+req.body.client_id+'&redirect_uri='+req.body.redirect_uri+'&response_type='+req.body.response_type+'&state='+req.body.state ;


    // /oauth/join?client_id=bWFtbWEgTTAwMDAwMA==&redirect_uri=http://localhost:5000/auth/klnet/callback&response_type=code&state=12345

    // <input type="hidden" name="client_id" value=<%=client_id %>>
    // <input type="hidden" name="redirect_uri" value=<%=redirect_uri %>>
    // <input type="hidden" name="response_type" value=<%=response_type %>>
    // <input type="hidden" name="state" value=<%=state %>>
    
    
    console.log('req.originalUrl', req.originalUrl);
    console.log('param', param);

    // console.log(fullUrl)
    // console.log( fullUrl );
    // console.log("2. (auth.js) req.isAuthenticated():", req.isAuthenticated());
    try {
        // console.log(req.url, req.baseUrl, req.fullUrl);
        // const row = getUser(id);
        // console.log('row', row);
        // done(null, row); 

        // client.connect();
        // console.log('2. 쿼리 준비');

        // console.log('req.body.redirect_uri=', req.body.redirect_uri);
        let redirect_uri = req.body.redirect_uri + '?id='+req.body.id;

        oracledb.getConnection(function (error, conn) {
            conn.execute("select * from do_comp_user_tbl where user_id=:1", {1:req.body.id}, {outFormat:oracledb.OBJECT},(err, result) => {
        // pgdb.query("select  * from own_comp_user where local_id = $1 ", [req.body.id], (err, result)=>{
            // client.end();
                if (err) {
                    // console.log('3. 쿼리 오류');
                    // console.log(err);
                    // console.log('3.1 쿼리 오류');
                    // done(null, false, { message: '존재하지 않는 아이디 입니다.' });
                    //redirect_uri = redirect_uri +'&message=존재하지 않는 아이디 입니다.';
                    // redirect_uri = redirect_uri +'&errcode=E1000';
                    // return res.redirect(redirect_uri);
                    conn.close(function(er) { 
                        if (er) {
                            console.log('Error closing connection', er);
                        } else {
                            console.log('Connection closed');
                        }
                    });   
                    return res.redirect("/oauth/join?errcode=E1000&message=로그인중 에러가 발생했습니다." + param);
                } else { 
                    // console.log('4. 쿼리 완료');
                    // console.log("query result.rows:", result.rows);
                    // console.log("query log:", err, result);
                    // response.status(200).json(result.rows);    
                    if (result.rows.length < 1) {
                        // console.log('5. 결과 없는 쿼리');
                        // done(null, false, { message: '존재하지 않는 아이디 입니다.' });
                        //redirect_uri = redirect_uri +'&message=존재하지 않는 아이디 입니다.'
                        // redirect_uri = redirect_uri +'&errcode=E1002';
                        // return res.redirect(redirect_uri);            

                        conn.close(function(er) { 
                            if (er) {
                                console.log('Error closing connection', er);
                            } else {
                                console.log('Connection closed');
                            }
                        });                           
                        return res.redirect("/oauth/join?errcode=E1002&message=회원 정보가 존재하지 않습니다." + param); 
                        // return res.send("errcode=E1002&message=회원 정보가 존재하지 않습니다.");


                    } else {
                        // console.log('6. 결과 있는 쿼리');
                        // console.log(result.rows[0]);
                        if(result.rows[0] != null) {
                            conn.execute("select * from do_comp_user_tbl where user_id=:1 and user_pwd = DAMO.HASH_SHA256_J(UPPER(:2))", {1:req.body.id, 2:req.body.pw}, {outFormat:oracledb.OBJECT},(err, result) => {
                                if (err) {
                                    console.log(err);
                                    conn.close(function(er) { 
                                        if (er) {
                                            console.log('Error closing connection', er);
                                        } else {
                                            console.log('Connection closed');
                                        }
                                    });                                       
                                    return res.redirect("/oauth/join?errcode=E1001&message=회원 정보가 일치하지 않습니다." + param); 
                                } else {
                                    if (result.rows.length < 1) {
                                        conn.close(function(er) { 
                                            if (er) {
                                                console.log('Error closing connection', er);
                                            } else {
                                                console.log('Connection closed');
                                            }
                                        });                                           
                                        return res.redirect("/oauth/join?errcode=E1001&message=회원 정보가 일치하지 않습니다!" + param); 
                                    } else {
                                        if(result.rows[0] != null) {
                                            const token = jwt.sign({userno:result.rows[0].USER_ID}, JWT_SECRET_KEY, { expiresIn : 3600, });


                                            // const accessToken = jwt.sign({userno:result.rows[0].user_no}, JWT_SECRET_KEY, { expiresIn : 60, }); //60*60 = 1h (3600)
                                            // const refreshToken = jwt.sign({userno:result.rows[0].user_no}, JWT_SECRET_KEY, { expiresIn : 172800, }); //60*60*48 = 48h

                                            sUser.provider = 'local';
                                            sUser.userid = result.rows[0].USER_ID;
                                            sUser.userno = result.rows[0].USER_ID;
                                            sUser.username = result.rows[0].UNAME_KR,
                                            sUser.displayName = 'web',
                                            sUser.email = result.rows[0].EMAIL;
                                            sUser.usertype = result.rows[0].SYSTEM_ADMIN_FLAG;
                                            sUser.token = token;
                                            console.log('sUser', sUser);
            
                                            const code = crypto.pbkdf2Sync(token, 'salt', 100000, 64, 'sha512').toString('hex');                

                                            const ipaddr = requestIp.getClientIp(req);
                                            // let sql = "update do_comp_user_tbl set klnet_local_token=:1, klnet_auth_code=:2, klnet_auth_date=sysdate where user_id=:4"
                                            // let binds = {1:token, 2:code, 4:req.body.id}
                                                                                        


                                            const re = /^localhost$|^127(?:\.[0-9]+){0,2}\.[0-9]+$|^(?:0*\:)*?:?0*1$|::/;
                                            let sql;
                                            let binds;
                                            // console.log('>>>>>>re test:', re.test(ipaddr))
                                            if ( re.test(ipaddr)){
                                                console.log(ipaddr, ' >>> not update last_login_ip')
                                                sql = "update do_comp_user_tbl set klnet_local_token=:1, klnet_auth_code=:2, klnet_auth_date=sysdate, last_login_date=sysdate where user_id=:4"
                                                binds = {1:token, 2:code, 4:req.body.id}
                                            }else{ 
                                                console.log(ipaddr, ' >>> update with last_login_ip')
                                                sql = "update do_comp_user_tbl set klnet_local_token=:1, klnet_auth_code=:2, klnet_auth_date=sysdate, last_login_date=sysdate, last_login_ip=:3  where user_id=:4"
                                                binds = {1:token, 2:code, 3:ipaddr, 4:req.body.id}
                                            }



                                            
                                            conn.execute(sql,binds, {outFormat:oracledb.OBJECT},(err, result1) => {
                                                if (err) {
                                                    console.log(err);
                                                } 

                                                // console.log('result=', result);

 

                                                (async () => {
                                                    await conn.commit();
                                                    pgdb.query("insert into own_login_history(history_Seq,user_no,inout_type,device_type,os_name,browser_name,browser_version,ip_addr)values(to_char(now(),'YYYYMMDDHH24miss')||nextval('own_history_seq'),$1,$2,$3,$4,$5,$6,replace($7,'::ffff:',''))"
                                                        , [result.rows[0].USER_ID, 'A', req.useragent.isMobile?'M':'P',req.useragent.os,req.useragent.browser,req.useragent.version,ipaddr], 
                                                        function(err,result) {
                                                            if (err) {
                                                                console.log(err);
                                                            } 
                                                        }
                                                    );
                    
                                                    // console.log("5. req.body.redirect_uri:",req.body.redirect_uri);
                                                    redirect_uri = redirect_uri +'&code=' + code + '&state=12345';
                                                    console.log("5. redirect_uri:",redirect_uri);
                    
                                                    res.cookie('socialKey', token);

                                                    conn.close(function(er) { 
                                                        if (er) {
                                                            console.log('Error closing connection', er);
                                                        } else {
                                                            console.log('Connection closed');
                                                        }
                                                    });                                                   
                                                    return res.redirect(redirect_uri);    
                        
                                                })().then(ret=> {console.log("[RETURN]");} ).catch(err => {console.log("[ERROR]",err)} )     


                                                                                            
                                            });


                                        } else {
                                            conn.close(function(er) { 
                                                if (er) {
                                                    console.log('Error closing connection', er);
                                                } else {
                                                    console.log('Connection closed');
                                                }
                                            });                                               
                                            return res.redirect("/oauth/join?errcode=E1001&message=회원 정보가 일치하지 않습니다" + param); 
                                        }
                                    }
                                }
                            });


                        } else {
                            // done(null, false, { message: '존재하지 않는 아이디 입니다.' });
                            //redirect_uri = redirect_uri +'&message=존재하지 않는 아이디 입니다.'
                            // redirect_uri = redirect_uri +'&errcode=E1002&message=회원 정보를 다시 확인하십시요.';
                            // return res.redirect(redirect_uri);
                            return res.redirect("/oauth/join?errcode=E1002&message=회원 정보를 다시 확인하십시요." + param); 
                        }

                    }
                }
        // });
            });  
        });

    } catch(error) {
        console.log(">>>>>error",error);
        console.error(error);
        done(error);
    }

});



app.post('/oauth/authorize2', (req, res, next) => {
    // console.log(req);
    console.log('1. 시작 authorize2................');
    // console.log('/oauth/authorize:', req.body);
    
    // let fullUrl = req.protocol + '://' + req.headers.host + req.originalUrl;
    const param = '&client_id='+req.body.client_id+'&redirect_uri='+req.body.redirect_uri+'&response_type='+req.body.response_type+'&state='+req.body.state ;
    const redirect_uri = req.body.redirect_uri;

    // /oauth/join?client_id=bWFtbWEgTTAwMDAwMA==&redirect_uri=http://localhost:5000/auth/klnet/callback&response_type=code&state=12345

    // <input type="hidden" name="client_id" value=<%=client_id %>>
    // <input type="hidden" name="redirect_uri" value=<%=redirect_uri %>>
    // <input type="hidden" name="response_type" value=<%=response_type %>>
    // <input type="hidden" name="state" value=<%=state %>>
    
    
    // console.log('req.originalUrl', req.originalUrl);
    // console.log('param', param);

    // console.log(fullUrl)
    // console.log( fullUrl );
    // console.log("2. (auth.js) req.isAuthenticated():", req.isAuthenticated());
    try {
        // console.log(req.url, req.baseUrl, req.fullUrl);
        // const row = getUser(id);
        // console.log('row', row);
        // done(null, row); 

        // client.connect();
        // console.log('2. 쿼리 준비');

        // console.log('req.body.redirect_uri=', req.body.redirect_uri);
        // let redirect_uri = req.body.redirect_uri + '?id='+req.body.id;
        
        oracledb.getConnection(function (error, conn) {
            conn.execute("select * from do_comp_user_tbl where user_id=:1", {1:req.body.id}, {outFormat:oracledb.OBJECT},(err, result) => {
                if (err) {
                    conn.close(function(er) { 
                        if (er) {
                            console.log('Error closing connection', er);
                        } else {
                            console.log('Connection closed');
                        }
                    });                       
                    return res.redirect(redirect_uri + "?errcode=E1000&message=로그인중 에러가 발생했습니다." + param);
                } else {
                    if (result.rows.length < 1) {
                        conn.close(function(er) { 
                            if (er) {
                                console.log('Error closing connection', er);
                            } else {
                                console.log('Connection closed');
                            }
                        });                           
                        return res.redirect(redirect_uri + "?errcode=E1002&message=회원 정보가 존재하지 않습니다." + param); 
                    } else {
                        if(result.rows[0] != null) {
                            conn.execute("select * from do_comp_user_tbl where user_id=:1 and user_pwd = DAMO.HASH_SHA256_J(UPPER(:2))", {1:req.body.id, 2:req.body.pw}, {outFormat:oracledb.OBJECT},(err, result) => {
                                if (err) {
                                    console.log(err);
                                    conn.close(function(er) { 
                                        if (er) {
                                            console.log('Error closing connection', er);
                                        } else {
                                            console.log('Connection closed');
                                        }
                                    });                                       
                                    return res.redirect(redirect_uri + "?errcode=E1001&message=회원 정보가 일치하지 않습니다." + param); 
                                } else {
                                    if (result.rows.length < 1) {
                                        conn.close(function(er) { 
                                            if (er) {
                                                console.log('Error closing connection', er);
                                            } else {
                                                console.log('Connection closed');
                                            }
                                        });                                           
                                        return res.redirect(redirect_uri + "?errcode=E1001&message=회원 정보가 일치하지 않습니다!" + param); 
                                    } else {
                                        if(result.rows[0] != null) {
                                            const token = jwt.sign({userno:result.rows[0].USER_ID}, JWT_SECRET_KEY, { expiresIn : 3600, });

                                            sUser.provider = 'local';
                                            sUser.userid = result.rows[0].USER_ID;
                                            sUser.userno = result.rows[0].USER_ID;
                                            sUser.username = result.rows[0].UNAME_KR,
                                            sUser.displayName = 'web',
                                            sUser.email = result.rows[0].EMAIL;
                                            sUser.usertype = result.rows[0].SYSTEM_ADMIN_FLAG;
                                            sUser.token = token;
        
                                            console.log('sUser', sUser);
        

                                            const code = crypto.pbkdf2Sync(token, 'salt', 100000, 64, 'sha512').toString('hex');
                                            const ipaddr = requestIp.getClientIp(req);

                                            let sql = "update do_comp_user_tbl set klnet_local_token=:a1, klnet_auth_code=:a2, klnet_auth_date=sysdate where user_id=:a3"
                                            let binds = {a1:token, a2:code, a3:req.body.id}


                                            console.log('update do_comp_user_tbl : ',sql, binds);

                                            // const re = /^localhost$|^127(?:\.[0-9]+){0,2}\.[0-9]+$|^(?:0*\:)*?:?0*1$|::/;
                                            // // console.log('ipaddr>>>>>>>>>>>>>>',ipaddr)

                                            // let sql;
                                            // let binds;

                                            // // console.log('>>>>>>re test:', re.test(ipaddr))
                                            // if (re.test(ipaddr)){
                                            //     console.log(ipaddr, ' >>> not update last_login_ip')
                                            //     sql = "update do_comp_user_tbl set klnet_local_token=:1, klnet_auth_code=:2, klnet_auth_date=sysdate, last_login_date=sysdate where user_id=:4"
                                            //     binds = {1:token, 2:code, 4:req.body.id}
                                            // }else{ 
                                            //     console.log(ipaddr, ' >>> update last_login_ip')
                                            //     sql = "update do_comp_user_tbl set klnet_local_token=:1, klnet_auth_code=:2, klnet_auth_date=sysdate, last_login_date=sysdate, last_login_ip=:3  where user_id=:4"
                                            //     binds = {1:token, 2:code, 3:ipaddr, 4:req.body.id}
                                            // }

                                            conn.execute(sql,binds , {outFormat:oracledb.OBJECT},(err, result1) => {
                                                if (err) {
                                                    console.log(err);
                                                } 
        
                                                console.log('result1=', result1);
                                              
                                                (async () => {
                                                    await conn.commit();
                                                    pgdb.query("insert into own_login_history(history_Seq,user_no,inout_type,device_type,os_name,browser_name,browser_version,ip_addr)values(to_char(now(),'YYYYMMDDHH24miss')||nextval('own_history_seq'),$1,$2,$3,$4,$5,$6,replace($7,'::ffff:',''))"
                                                        , [result.rows[0].USER_ID, 'A', req.useragent.isMobile?'M':'P',req.useragent.os,req.useragent.browser,req.useragent.version,ipaddr], 
                                                        function(err,result2) {
                                                            if (err) {
                                                                console.log(err);
                                                            } 
                                                            console.log('result2=', result2);
                                                        }
                                                    );
                    
                                                    // console.log("5. req.body.redirect_uri:",req.body.redirect_uri);

                                                    res.cookie('socialKey', token);
                                                    conn.close(function(er) { 
                                                        if (er) {
                                                            console.log('Error closing connection', er);
                                                        } else {
                                                            console.log('Connection closed');
                                                        }
                                                    });                             
                                                    
                                                    console.log("2. req.body.redirect_uri:",redirect_uri + '?id='+req.body.id +'&code=' + code + '&state=12345');
                                                    return res.redirect(redirect_uri + '?id='+req.body.id +'&code=' + code + '&state=12345');     
                        
                                                })().then(ret=> {console.log("[RETURN]");} ).catch(err => {console.log("[ERROR]",err)} )     
                                                
                                            });
        
                                          
                                        } else {
                                            conn.close(function(er) { 
                                                if (er) {
                                                    console.log('Error closing connection', er);
                                                } else {
                                                    console.log('Connection closed');
                                                }
                                            });                                               
                                            return res.redirect(redirect_uri + "?errcode=E1001&message=회원 정보가 일치하지 않습니다" + param); 
                                        }
                                    }
                                }
                            });
                        } else {
                            return res.redirect(redirect_uri + "?errcode=E1002&message=회원 정보를 다시 확인하십시요." + param); 
                        }
                    }
                }
            });
        });  
            
/*
        pgdb.query("select  * from own_comp_user where local_id = $1 ", [req.body.id], (err, result)=>{
            // client.end();
            if (err) {
                return res.redirect(redirect_uri + "?errcode=E1000&message=로그인중 에러가 발생했습니다." + param);
            } else {
                if (result.rows.length < 1) {

                    return res.redirect(redirect_uri + "?errcode=E1002&message=회원 정보가 존재하지 않습니다." + param); 

                } else {
                    // console.log('6. 결과 있는 쿼리');
                    if(result.rows[0] != null) {
                        const inputpassword = crypto.pbkdf2Sync(req.body.pw, 'salt', 100000, 64, 'sha512').toString('hex');
                        console.log('password:', inputpassword, result.rows[0].local_pw.toString());
                        if(inputpassword == result.rows[0].local_pw.toString()) {
                            const token = jwt.sign({userno:result.rows[0].user_no}, JWT_SECRET_KEY, { expiresIn : 3600, });

                            // const accessToken = jwt.sign({userno:result.rows[0].user_no}, JWT_SECRET_KEY, { expiresIn : 60, }); //60*60 = 1h (3600)
                            // const refreshToken = jwt.sign({userno:result.rows[0].user_no}, JWT_SECRET_KEY, { expiresIn : 172800, }); //60*60*48 = 48h

                            console.log('/oauth/authorize2 token:', token);

                            sUser.provider = 'local';
                            sUser.userid = result.rows[0].local_id;
                            sUser.userno = result.rows[0].user_no;
                            sUser.username = result.rows[0].user_name,
                            sUser.displayName = 'web',
                            sUser.email = result.rows[0].user_email;
                            sUser.usertype = result.rows[0].user_type;
                            sUser.token = token;


                            const code = crypto.pbkdf2Sync(token, 'salt', 100000, 64, 'sha512').toString('hex');

                            console.log('token:', token, ',code:', code);

                            pgdb.query("UPDATE OWN_COMP_USER SET token_local=$1, klnet_auth_code=$2 , klnet_auth_date= now() WHERE user_no=$3", [token, code, result.rows[0].user_no], function(err,result) {
                                // client.end();
                                if (err) {
                                    console.log(err);
                                } 
                            });

                            const ipaddr = requestIp.getClientIp(req);
                            // console.log(req);
                            pgdb.query("insert into own_login_history(history_Seq,user_no,inout_type,device_type,os_name,browser_name,browser_version,ip_addr)values(to_char(now(),'YYYYMMDDHH24miss')||nextval('own_history_seq'),$1,$2,$3,$4,$5,$6,replace($7,'::ffff:',''))"
                                , [result.rows[0].user_no, 'A', req.useragent.isMobile?'M':'P',req.useragent.os,req.useragent.browser,req.useragent.version,ipaddr], 
                                function(err,result) {
                                    if (err) {
                                        console.log(err);
                                    } 
                                }
                            );

                            // console.log("5. req.body.redirect_uri:",req.body.redirect_uri);



                            res.cookie('socialKey', token);
                            return res.redirect(redirect_uri + '?id='+req.body.id +'&code=' + code + '&state=12345');

                        } else {
                            return res.redirect(redirect_uri + "?errcode=E1001&message=회원 정보가 일치하지 않습니다." + param); 
                        }

                    } else {
                            return res.redirect(redirect_uri + "?errcode=E1002&message=회원 정보를 다시 확인하십시요." + param); 
                    }

                }
            }
        });

*/

    } catch(error) {
        console.log(">>>>>error",error);
        console.error(error);
        done(error);
    }

});




app.post('/oauth/auth_code', (req, res, next) => {
    console.log('1. /oauth/auth_code');

    console.log('req.body=', req.body);

    if ( req.body.grant_type === 'refresh_token' 
        // && req.body.redirect_uri === 'http://localhost:5000/auth/klnet/callback'
        && req.body.client_id === '5vSPppBEGLWEwMT8p9kZ'
        && req.body.client_secret === 's94tuPZ0Go'){

        const refreshToken = req.body.refresh_token;
        const refresh_token_decoded = jwt.verify(refreshToken, JWT_SECRET_KEY);
        const user_no = refresh_token_decoded.userno;

        console.log('refresh_token(access_token):', refreshToken);
        console.log('user_no:', user_no);


        oracledb.getConnection(function (err, conn) {
            conn.execute("select * from do_comp_user_tbl where user_id = :1 and klnet_access_token = :2 ", {1:user_no, 2:refreshToken}, {outFormat:oracledb.OBJECT},(err, result) => {
                if (err) {
                    console.log(err);
                    // return res.json({access_token:accessToken, refresh_token:refreshToken, expires_in : '3600', token_type:"bearer"});
                    conn.close(function(er) { 
                        if (er) {
                            console.log('Error closing connection', er);
                        } else {
                            console.log('Connection closed');
                        }
                    });                    
                    return res.json();
                } else {
// console.log(('result:', result));
                    if (result.rows.length < 1) {
                        conn.close(function(er) { 
                            if (er) {
                                console.log('Error closing connection', er);
                            } else {
                                console.log('Connection closed');
                            }
                        });                        
                        return res.json();
                    } else {


                        const token = jwt.sign({userno:user_no}, JWT_SECRET_KEY, { expiresIn : 3600, });
                        const code = crypto.pbkdf2Sync(token, 'salt', 100000, 64, 'sha512').toString('hex');


                        let sql = "update do_comp_user_tbl set klnet_local_token=:a1, klnet_auth_code=:a2, klnet_auth_date=sysdate where user_id=:a3"
                        let binds = {a1:token, a2:code, a3:user_no}


                        console.log('update do_comp_user_tbl : ',sql, binds);

                        conn.execute(sql,binds , {outFormat:oracledb.OBJECT},(err, result1) => {
                            if (err) {
                                console.log(err);
                            } 

                            console.log('result1=', result1);
                          
                            (async () => {
                                await conn.commit();

                                res.cookie('socialKey', token);
                                conn.close(function(er) { 
                                    if (er) {
                                        console.log('Error closing connection', er);
                                    } else {
                                        console.log('Connection closed');
                                    }
                                });                             
                                
                                return res.json({access_token:code, refresh_token:refreshToken, expires_in : 3600, token_type:"bearer"});
    
                            })().then(ret=> {console.log("[RETURN]");} ).catch(err => {console.log("[ERROR]",err)} )     
                            
                        });

                    }
                }

            });
        });    


    };


});



/*
app.post('/oauth/authorize', (req, res, next) => {
    // console.log(req);
    console.log(req.body);
    var fullUrl = req.protocol + '://' + req.headers.host + req.originalUrl;
    console.log( fullUrl );

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
            const redirect_uri = req.body.redirect_uri + '?code=' + user.token + '&state=12345';
            // res.status(response.statusCode).send({"access_token":"1231231321231"});
            res.header('Authorization', user.token);
            return res.redirect(redirect_uri);

            // const options = {
            //     host:'localhost',
            //     port:5000,
            //     path:'/auth/klnet/callback'
            // };
            // http.get(options, function(resp) {
            //     const body = 'abcdefg';
            //     resp.on('data', function(chunk) {
            //         body += chunk;
            //     });
            //     resp.on('end', function() {
            //         console.log('body=', body);
            //     });
            // }).on('error', function(e) {
            //     console.log("error:" + e.message);
            // })
            // next();

            // reqeust.post({url:'http://localhost:5000/auth/klnet/callback', form:'data'});
        }
        
    })(req, res, next)  //미들웨어 내의 미들웨어에는 (req, res, next)를 붙인다.
});
*/





app.post('/oauth/keyauthorize', (req, res, next) => {
    console.log('1. 시작 keyauthorize................');
    console.log('/oauth/authorize:', req.body.apiKey);
    
    // console.log("2. (auth.js) req.isAuthenticated():", req.isAuthenticated());
    try {
        // console.log(req.url, req.baseUrl, req.fullUrl);
        // const row = getUser(id);
        // console.log('row', row);
        // done(null, row); 

        // client.connect();
        // console.log('2. 쿼리 준비');

        oracledb.getConnection(function (error, conn) {
            conn.execute("select * from do_comp_user_tbl where user_id=:1 and api_service_key=:2", {1:req.body.id, 2:req.body.apiKey}, {outFormat:oracledb.OBJECT},(err, result) => {
                if (err) {
                    redirect_uri = redirect_uri +'&errcode=E1002';
                    conn.close(function(er) { 
                        if (er) {
                            console.log('Error closing connection', er);
                        } else {
                            console.log('Connection closed');
                        }
                    });                       
                    res.send({data:[],errcode:'E1002'});
                } else {
                    if (result.rows.length < 1) {
                        conn.close(function(er) { 
                            if (er) {
                                console.log('Error closing connection', er);
                            } else {
                                console.log('Connection closed');
                            }
                        });                           
                        res.send({data:[],errcode:'E1002'});
                    } else {
                        if(result.rows[0] != null) {                            
                            const token = jwt.sign({userno:result.rows[0].USER_ID}, JWT_SECRET_KEY, { expiresIn : '1h', });
                            const code = crypto.pbkdf2Sync(token, 'salt', 100000, 64, 'sha512').toString('hex');
                            conn.execute("update do_comp_user_tbl set klnet_local_token=:1, klnet_auth_code=:2, klnet_auth_date=sysdate where user_id=:3", {1:token, 2:code, 3:req.body.id}, {outFormat:oracledb.OBJECT},(err, result) => {
                                if (err) {
                                    console.log(err);
                                } 
                                // console.log('result=', result);

                                (async () => {
                                    await conn.commit();
                                    const ipaddr = requestIp.getClientIp(req);
                                    // console.log(req);
                                    pgdb.query("insert into own_login_history(history_Seq,user_no,inout_type,device_type,os_name,browser_name,browser_version,ip_addr)values(to_char(now(),'YYYYMMDDHH24miss')||nextval('own_history_seq'),$1,$2,$3,$4,$5,$6,replace($7,'::ffff:',''))"
                                        , [result.rows[0].USER_ID, 'A', req.useragent.isMobile?'M':'P',req.useragent.os,req.useragent.browser,req.useragent.version,ipaddr], 
                                        function(err,result) {
                                            if (err) {
                                                console.log(err);
                                            } 
                                        }
                                    );
                                    conn.close(function(er) { 
                                        if (er) {
                                            console.log('Error closing connection', er);
                                        } else {
                                            console.log('Connection closed');
                                        }
                                    });   
                                    res.send({data:token,errcode:''});
        
                                })().then(ret=> {console.log("[RETURN]");} ).catch(err => {console.log("[ERROR]",err)} )                                     
                            });

                        } else {
                            conn.close(function(er) { 
                                if (er) {
                                    console.log('Error closing connection', er);
                                } else {
                                    console.log('Connection closed');
                                }
                            });                               
                            res.send({data:[],errcode:'E1002'});
                        }
                    }
                }
            });
        });  

    } catch(error) {
        console.log(">>>>>error",error);
        console.error(error);
        done(error);
    }

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
  //   pgdb.update token clear
    //console.log("session:",req.session.sUser);
    //var ipaddr = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  	console.log("ID",decoded.userno);
  	
    var ipaddr = requestIp.getClientIp(req);
    console.log("LOGOUT ", (decoded && decoded.user != undefined), decoded, decoded.user )
    if(decoded && decoded.user != undefined) {

/*
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
*/

        oracledb.getConnection(function (err, conn) {
            conn.execute("update do_comp_user_tbl set last_logout_date=sysdate, klnet_local_token=null, klnet_auth_code=null,  "
            +" klnet_auth_date=null, klnet_access_token=null, klent_refresh_token=null where user_id=:1 ",{1:decoded.userno},{outFormat:oracledb.OBJECT},(error, results) => {
                if (error) {
                    console.log(error);
                }

                (async () => {
                    await conn.commit();
                    conn.close(function(er) { 
                        if (er) {
                            console.log('Error closing connection', er);
                        } else {
                            console.log('Connection closed');
                        }
                    });   
                })().then(ret=> {console.log("[RETURN]");} ).catch(err => {console.log("[ERROR]",err)} )                

                const ipaddr = requestIp.getClientIp(req);
                // console.log(req);
                client.query("insert into own_login_history(history_Seq,user_no,inout_type,device_type,os_name,browser_name,browser_version,ip_addr)values(to_char(now(),'YYYYMMDDHH24miss')||nextval('own_history_seq'),$1,$2,$3,$4,$5,$6,replace($7,'::ffff:',''))"
                    , [decoded.userno, 'U', req.useragent.isMobile?'M':'P',req.useragent.os,req.useragent.browser,req.useragent.version,ipaddr], 
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
            });
        });


    }
    req.logout();
   // res.clearCookie('connect.sid',{ path: '/' });
    res.clearCookie('express:sess',{ path: '/' });
    res.clearCookie('express:sess.sig',{ path: '/' });
    //console.log(":>>>");
    res.send(false);
      
});



app.get('/oauth', (req, res) => {
    res.render('index', {
        title: 'Klnet Oauth2.0',
        message: 'Hello!'
    });
});


app.get('/oauth/index.html', (req, res) => {
    res.redirect('/oauth');
});

app.get('/oauth/index', (req, res) => {
    res.redirect('/oauth');
});

app.get('/oauth/join', (req, res) => {

    //http://localhost:5002/oauth/join?client_id=bWFtbWEgTTAwMDAwMA==&redirect_uri=http://localhost:5000/auth/klnet/callback&response_type=code&state=12345
    //http://localhost:5002/oauth/join?client_id=bWFtbWEgTTAwMDAwMA==&redirect_uri=https://dev.plismplus.com/auth/klnet/callback&response_type=code&state=12345

    console.log('client_id:', req.query['client_id']); //Profile page api key bWFtbWEgTTAwMDAwMA==
    console.log('redirect_uri:', req.query['redirect_uri']); //https://dev.plismplus.com/auth/klnet/callback
    //http://localhost:5000/auth/klnet/callback
    console.log('response_type:', req.query['response_type']); //code
    console.log('state:', req.query['state']); //12345
    let client_id = req.query['client_id'];
    let redirect_uri = req.query['redirect_uri'];
    let response_type = req.query['response_type'];
    let state = req.query['state'];
    let message = req.query['message'];
    let klnetUrl= (PRODUCTION === 'LOCAL' ? 'http://localhost:3000' : (PRODUCTION === 'DEV' ? 'https://devbooking.plism.com' : 'https://booking.plism.com' ));

    res.render('join', {
        title: '회원가입',
        client_id: client_id,
        redirect_uri: redirect_uri,
        response_type: response_type,
        state: state,
        message: message,
        klnetUrl: klnetUrl,
        joinError: req.flash('joinError'),
    });
});


app.post('/oauth/prelogin', (req, res, next) => {
    console.log(req.query);
    console.log('id' + req.query[`id`]);
    console.log(req.body);
    console.log('id' + req.body.id);
    console.log('id' + req.body.emp);
    console.log('id' + req.body.emps);
    console.log('id' + req.query['emp']);
    console.log('id' + req.query['emps']);
    res.redirect('/oauth/authorize');
});

app.listen(5002, () => console.log(`Listening on port 5002`));
app.use(express.static('public')); /////////로컬실행시