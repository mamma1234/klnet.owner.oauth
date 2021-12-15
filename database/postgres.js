const { Pool } = require('pg');

const pool = new Pool({
    user: 'owner',
    host: '172.19.1.22',
    database: 'owner',
    password: '!ghkwn_20',
    port: '5432',
    max: 1,
    min: 1,
});

module.exports = {
    query: (sql, params, callback) => {
        const start = Date.now();
        return pool.query(sql, params, (err, res ) => {
            const duration = Date.now() - start;
            console.log('execute query', { sql, duration, rows: res.rowCount });
            callback( err, res);
        }) 
    },
    getClient: ( callback ) => {
        pool.connect((err, client, done) => {
            const query = client.query;
///
            // monkey patch the query method to keep tack of the last query executed
            client.query = ( ...args ) => {
                client.lastQuery = args;
                return query.apply(client, args);
            }
            client.release =(err)=> {
                done(err);
                client.query = query;
            }

            callback(err, client, release);
        });
    }
}