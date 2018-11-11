const express = require('express')
const session = require('express-session')
const moment = require('moment-timezone')
const fetch = require('node-fetch')
const FormData = require('form-data')
const nJwt = require('njwt')
const njwk = require('node-jwk')
const uuid = require('uuid/v4')
const {Pool} = require('pg')
const path = require('path')
const exphbs = require("express-handlebars")
const bodyParser = require('body-parser')

// configuration from environment
const OAUTH_CLIENT_ID = process.env.OAUTH_CLIENT_ID
const OAUTH_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET
const OAUTH_REDIRECT_URI = process.env.OAUTH_REDIRECT_URI
const KID_OVERRIDE = process.env.KID_OVERRIDE
const SF_LOGIN_URL = process.env.SF_LOGIN_URL || 'https://login.salesforce.com'

// configure app
const app = express()
app.use(bodyParser.json())
app.use(express.static(path.join(__dirname, 'public')))
app.engine('handlebars', exphbs({defaultLayout: 'main'}))
app.set('view engine', 'handlebars')

// json formatting
app.set('json replacer', undefined)
app.set('json spaces', 2)

// configure our session
app.use(session({
    secret: uuid(),
    resave: false,
    saveUninitialized: true, 
    cookie: {
        maxAge: 60 * 60 * 1000 // 60 minutes
    }
}))

// load environment variables for localhost
try {
	require('dotenv').config()
} catch (e) {}

// get database connection pool
const db = (function() {
    if (process.env.DATABASE_URL) {
        return new Pool({
            'connectionString': process.env.DATABASE_URL,
            'ssl': true
        })
    } else {
        // return stub
        return {
            'query': () => {
                return Promise.resolve({
                    rows: [{
                        name: 'I-000001',
                        id: 'a001t000002Xx4LAAS',
                        'title__c': 'Make cubes round',
                        'description__c': 'I really like cubes but really like them to be rounder. Maybe like an oval?'
                    }]
                })
            },
            'end': () => {}
        }
    }
})()

/**
 * Specific route for OAuth callback.
 */
app.get('/oauth/callback', (req, res) => {
    // grab authorization code
    const authcode = req.query.code
    if (!authcode) {
        return res.status(417).send('Expected authorization code').end()
    }
    
    // exchange authcode
    const formdata = new FormData()
    formdata.append('client_id', OAUTH_CLIENT_ID)
    formdata.append('client_secret', OAUTH_CLIENT_SECRET)
    formdata.append('redirect_uri', OAUTH_REDIRECT_URI)
    formdata.append('code', authcode)
    formdata.append('grant_type', 'authorization_code')
    fetch(`${SF_LOGIN_URL}/services/oauth2/token`, {
        method: 'POST',
        body: formdata
    }).then(response => {
        return response.json()
    }).then(payload => {
        // get idtoken out of payload
        const idtoken = payload.id_token

        // we need to verify the token before trusting it
        return Promise.all([Promise.resolve(payload), verifyIDToken(idtoken), fetchIdentity(payload.access_token, payload.id)])

    }).then(data => {
        const payload = data[0]
        const verifyResult = data[1]
        const identity = data[2]

        // grab verify result and payload and store session
        req.session.user = verifyResult
        req.session.payload = payload
        req.session.identity = identity
        req.session.scopes = payload.scope.split(' ')
        req.session.save()

        // start process to load wellknown config
        global.setImmediate(() => {
            // get well known config
            fetchWellknownConfig(identity.urls.custom_domain || payload.instance_url).then(config => {
                req.session.wellknown_config = config
                req.session.save()
            })
        })

        // redirect
        return res.redirect('/')

    }).catch(err => {
        console.log(`Error: ${err.message}`, err)
        return res.status(500).send(err.message).end()

    })
})

app.use((req, res, next) => {
    if (process.env.BYPASS_AUTH) {
        req.session.user = {
            header: { typ: 'JWT', alg: 'RS256', kid: '216' },
            body: {
                at_hash: 'btzzYwv03uxO5XLFCYp4UA',
                sub: 'https://login.salesforce.com/id/00D1t000000rXxREAU/0051t000001qjZ7AAI',
                aud: '3MVG9fTLmJ60pJ5KS3EXllTxHn43nhbIpAwP9f46NM444ueQDU8pJFHFFfRqreMM0HTiCO.0yAEsfGKdkGfXn',
                iss: 'https://login.salesforce.com',
                exp: 1541968639,
                iat: 1541968519
            }
        }
        req.session.payload = {
            access_token: '00D1t000000rXxR!AREAQL.ZVktPeK1rHnEkVQoPHKRohYTB.j002zdPRFn.LSf847SvUAnidj9_QBmG0T3TQ96rjBNKXZ7tWJJ8pPDps8Sa0Oq3',
            signature: 'DvSMILcBmSmH4ZO6+XPxqD+rnNe6H0BheH8tB1+Nj9g=',
            scope: 'openid api',
            id_token: 'eyJraWQiOiIyMTYiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdF9oYXNoIjoiYnR6ell3djAzdXhPNVhMRkNZcDRVQSIsInN1YiI6Imh0dHBzOi8vbG9naW4uc2FsZXNmb3JjZS5jb20vaWQvMDBEMXQwMDAwMDByWHhSRUFVLzAwNTF0MDAwMDAxcWpaN0FBSSIsImF1ZCI6IjNNVkc5ZlRMbUo2MHBKNUtTM0VYbGxUeEhuNDNuaGJJcEF3UDlmNDZOTTQ0NHVlUURVOHBKRkhGRmZScXJlTU0wSFRpQ08uMHlBRXNmR0tka0dmWG4iLCJpc3MiOiJodHRwczovL2xvZ2luLnNhbGVzZm9yY2UuY29tIiwiZXhwIjoxNTQxOTY4NjM5LCJpYXQiOjE1NDE5Njg1MTl9.HOmwc1QwIhsyB_xLNvVgepk3kGwT2n3aYiFLChs_5FmYfquZ8SVYQ3-u24s8v5zr4bOXiHj5pMtkrdOGtZvlWk34RN6o3LflhQWun9TmS0NjGDZkMyEQdehaY68YSyvW2oDCuD17NpRepbxOU0-BDQPR588LakQ1J9dnlisL6pv7LKy8bwdTW7CWq0aj2NpYbdr5m2JgJxgfjL7slC-q7UCNHxS_rmS4279r3PKJGNPRDT3xQGwXt4fUdTcflx5bzz_iIz6dkdljP-l_UJyWzJKHBhri5IZgNQgPDRRXDnHJp_DohUSCXjgTVzy-oAHKOIUcj4EzUfDyRUxpoAr2FkU1-GfGCaByGJjtRxPDaSa97anLaNOUZXbGV9kHNmo1NrH7blPhWt2KOUxxonL0b8T38v5WZb2Qqyaa6A0x02W3KzbPXS2L0sqyhAQepZNJ2YZQvD8iZyyfh7iL408CgNToaX9NT-hKSAbBsuHvE2LU7rx7vlXJkp5dC1cNkWCiJ9WLr2T-_XCmi5IHSvIBxd705gATKrMuX2SVF9LlxHedb7gcEcnaE7u1VynoiIPnj1oBRGPxi0xw1AkUY19HkMR_zx03sdcsVoQjoAPl9A_APTz1ENgbsPoH-h37QLghOACljJGMURI9HWtiFQ1gcvxJo4VVDXED8zHxnqmhl9U',
            instance_url: 'https://eu16.salesforce.com',
            id: 'https://login.salesforce.com/id/00D1t000000rXxREAU/0051t000001qjZ7AAI',
            token_type: 'Bearer',
            issued_at: '1541968519421'
        }
        req.session.identity = { 
            id: 'https://login.salesforce.com/id/00D1t000000rXxREAU/0051t000001qjZ7AAI',
            asserted_user: true,
            user_id: '0051t000001qjZ7AAI',
            organization_id: '00D1t000000rXxREAU',
            username: 'idpp@trailhead.com',
            nick_name: 'idpp',
            display_name: 'Mikkel Flindt Heisterberg',
            email: 'mheisterberg@salesforce.com',
            email_verified: false,
            first_name: 'Mikkel Flindt',
            last_name: 'Heisterberg',
            timezone: 'Europe/Paris',
            photos: {
                picture: 'https://c.eu16.content.force.com/profilephoto/005/F',
                thumbnail: 'https://c.eu16.content.force.com/profilephoto/005/T'
            },
            addr_street: null,
            addr_city: null,
            addr_state: null,
            addr_country: 'DK',
            addr_zip: null,
            mobile_phone: null,
            mobile_phone_verified: false,
            is_lightning_login_user: false,
            status: { created_date: null, body: null },
            urls: {
                enterprise: 'https://eu16.salesforce.com/services/Soap/c/{version}/00D1t000000rXxR',
                metadata: 'https://eu16.salesforce.com/services/Soap/m/{version}/00D1t000000rXxR',
                partner: 'https://eu16.salesforce.com/services/Soap/u/{version}/00D1t000000rXxR',
                rest: 'https://eu16.salesforce.com/services/data/v{version}/',
                sobjects: 'https://eu16.salesforce.com/services/data/v{version}/sobjects/',
                search: 'https://eu16.salesforce.com/services/data/v{version}/search/',
                query: 'https://eu16.salesforce.com/services/data/v{version}/query/',
                recent: 'https://eu16.salesforce.com/services/data/v{version}/recent/',
                tooling_soap: 'https://eu16.salesforce.com/services/Soap/T/{version}/00D1t000000rXxR',
                tooling_rest: 'https://eu16.salesforce.com/services/data/v{version}/tooling/',
                profile: 'https://eu16.salesforce.com/0051t000001qjZ7AAI',
                feeds: 'https://eu16.salesforce.com/services/data/v{version}/chatter/feeds',
                groups: 'https://eu16.salesforce.com/services/data/v{version}/chatter/groups',
                users: 'https://eu16.salesforce.com/services/data/v{version}/chatter/users',
                feed_items: 'https://eu16.salesforce.com/services/data/v{version}/chatter/feed-items',
                feed_elements: 'https://eu16.salesforce.com/services/data/v{version}/chatter/feed-elements' 
            },
            active: true,
            user_type: 'STANDARD',
            language: 'en_US',
            locale: 'da_DK',
            utcOffset: 3600000,
            last_modified_date: '2018-11-11T18:56:07Z',
            is_app_installed: true,
            custom_attributes: {
                external_user: '0', 
                cube_branding: '1' 
            }
        }
        req.session.save()
    }
    next()
})

/**
 * Middleware to always make sure we have authenticated the user.
 */
app.use((req, res, next) => {
    // see if there is a user object in the session
    if (!req.session.user) {
        // there is not - initiate authentication
        return res.redirect(`${SF_LOGIN_URL}/services/oauth2/authorize?client_id=${OAUTH_CLIENT_ID}&redirect_uri=${OAUTH_REDIRECT_URI}&response_type=code&prompt=consent`)
    } else {
        // yay
        return next()
    }
})

app.use((req, res, next) => {
    if (!req.session || !req.session.identity || !req.session.identity.custom_attributes) return next(new Error('Missing payload in session'))

    // build context
    let ctx = {}
    if (req.session.identity.custom_attributes.cube_branding === '0') {
        ctx.branding1 = true
        ctx.logo_filename = 'cube_logo1.png'
    } else {
        ctx.logo_filename = 'cube_logo2.png'
    }
    ctx.identity = req.session.identity
    ctx.updated_timedate = formatDate()
    req.cube_context = ctx
    next()
})

/**
 * Route for welcome page.
 */
app.get('/', (req, res) => {
    res.render('welcome', req.cube_context)
})

/**
 * Route to display ideas.
 */
app.get('/ideas', (req, res) => {
    const ctx = Object.assign({}, req.cube_context)
    db.query('SELECT Id, Name, Title__c, Description__c FROM salesforce.Idea__c').then(rs => {
        ctx.ideas = rs.rows
        res.render('ideas', ctx)
    })
})

/**
 * Route to post comment.
 */
app.post('/comment', (req, res) => {
    // get data from body
    const recordId = req.body.id
    const comment = req.body.comment

    const url = `${req.session.identity.urls.rest.replace('{version}', '44.0')}sobjects/Comment_Event_Storage__c`
    fetch(url, {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${req.session.payload.access_token}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            'Comment__c': comment,
            'RecordId__c': recordId
        })
    }).then(res => {
        return res.json()
    }).then(obj => {
        res.status(201).send({
            'status': 'OK',
            'id': obj.id
        })
    })
})

/**
 * Route for Salesforce Canvas App
 */
app.post('/canvas', (req, res) => {
    // get data from body
    console.log(req.body)
    res.status(200).send('ok')
})

/**
 * Route for about.
 */
app.get('/about', (req, res) => {
    res.render('about', req.cube_context)
})

/**
 * Route for logout.
 */
app.get('/logout', (req, res) => {
    req.session.destroy()
    if (req.session.wellknown_config && req.session.wellknown_config.end_session_endpoint) {
        res.redirect(req.session.wellknown_config.end_session_endpoint)
    } else {
        res.redirect('/')
    }
})

/**
 * Route for logout.
 */
app.get('/slo', (req, res) => {
    console.log('slo received')
    req.session.destroy()
    res.redirect('/')
})

/**
 * Route for JSON response - user.
 */
app.get('/json/user', (req, res) => {
    res.json(req.session.user).end()
})

/**
 * Route for JSON response - payload.
 */
app.get('/json/payload', (req, res) => {
    res.json(req.session.payload).end()
})

/**
 * Route for JSON response - identity.
 */
app.get('/json/identity', (req, res) => {
    res.json(req.session.identity).end()
})

/**
 * Route for JSON response - wellknown config.
 */
app.get('/json/wellknown_config', (req, res) => {
    res.json(req.session.wellknown_config).end()
})

app.use((err, req, res, next) => {
    // put on console
    console.log(`Caught error: ${err.message}`, err)

    // render error page
    const ctx = Object.assign({}, req.cube_context)
    ctx.error_msg = err.message
    ctx.error = err
    //res.status(500)
    res.render('error', ctx)
})

// listen
app.listen(process.env.PORT || 3000)

/**
 * Method to verify the ID Token we received from Salesforce using the standard 
 * public keys provided by Salesforce.
 * 
 * @param {String} idtoken 
 */
const verifyIDToken = idtoken => {
    return new Promise((resolve, reject) => {
        // get keys from Salesforce
        fetch(`${SF_LOGIN_URL}/id/keys`).then(res => {
            return res.json()
        }).then(keys => {
            // parse jwk keys
            const myKeySet = njwk.JWKSet.fromObject(keys)

            // get header
            const idtoken_parts = idtoken.split('.')

            // parse header
            const header = JSON.parse(Buffer.from(idtoken_parts[0], 'base64').toString('utf8'))
            if (!header.kid || header.typ !== 'JWT' || header.alg !== 'RS256') return rejrect(Error('Missing kid in header or invalid type or algorithm'))

            // get key to use
            const jwkKey = myKeySet.findKeyById(KID_OVERRIDE || header.kid)
            if (!jwkKey) throw Error(`Unable to find key for kid ${header.kid}`)
            return jwkKey.key.toPublicKeyPEM()

        }).then(pem => {
            // verify signature
            const verifyResult = nJwt.verify(idtoken, pem, 'RS256');

            // coming here means we verified the signature - now let's check that we 
            // are the audience meaning it was generated for us
            if (verifyResult.body.aud !== OAUTH_CLIENT_ID) {
                // it wasn't
                return reject(Error('Received JWT wasn\'t generated for us do we wont accept it!'))
            }

            // we verified the token
            resolve(verifyResult)

        }).catch(err => {
            return reject(err)
        })
    })
}

/**
 * Method to get the identity of a user based on an access_token and id URL.
 * 
 * @param {String} access_token 
 * @param {String} id 
 */
const fetchIdentity = (access_token, id) => {
    return fetch(id, {
        headers: {
            'Authorization': `Bearer ${access_token}`
        }
    }).then(res => res.json())
}

/**
 * Load well-known config from base_url
 * @param {*} base_url 
 */
const fetchWellknownConfig = base_url => {
    return fetch(`${base_url}/.well-known/openid-configuration`).then(res => {
        return res.json()
    })
}


/**
 * Utiltity method to format a date to a string format
 * @param {*} date 
 */
const formatDate = (date) => {
    let m = date && date['diff'] ? date : date ? moment(date) : moment()
    return m.tz(process.env.TIMEZONE || 'Europe/Copenhagen').format(process.env.DATETIME_FORMAT || 'YYYY-M-D @ k:mm')
}

// add termination listener
require('./terminate-listener.js')(() => {
	console.log("Terminating services");
	db.end()
	console.log("Terminated services");
})