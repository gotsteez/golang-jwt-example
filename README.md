# golang-jwt-example
Simple barebones example of proper JWTs in golang. I couldn't find any good examples that were compatible with go-chi, so I decided to write my own and share my knowledge. The example isn't meant to be production grade, but by tweaking a few things such as the secret, adding some proper middleware, and optionally changing the signing method (see [here](https://auth0.com/blog/brute-forcing-hs256-is-possible-the-importance-of-using-strong-keys-to-sign-jwts/) on how H256 can be brute forced), you can use this in a production grade application.

## What is JWT?
JWT (JSON Web Token) is a very popular industry standard when it comes to creating user sessions. You can read up more on the math and reasoning [here](https://jwt.io/). 

## Why refresh tokens?
Normally, a JWT is just one token that is used for user authentication when calling APIs. This presents the problem of token jacking, as if the token is stored improperly, it can be hijacked and used to unintended and often malicious sources. Refresh tokens provide a way to have long time sessions, and all the features of regular JWT. This is done by using the access token to access APIs, while the refresh token is just used to prolong sessions. Even if the access token is stolen, it's only for 15 minutes, so the attacker doesn't have persistent access.

## How would I log out?
There really isn't a way to destroy JWTs, as they are suppose to be stateless. One way of logging out would be to add the current refresh and access tokens into a blacklist, and then remove them from the blacklist when they expire. I might write this in an update in the future. However, the implication with this is that it essentially becomes stateless, taking away one of the main reasons people use JWT.

## My thoughts
Although the idea of a stateless session mechanism is nice, it isn't really possible form a security standpoint. One alternative to JWTs is [scs](https://github.com/alexedwards/scs), which is very similar to `express-session` if you are familiar with NodeJS and Express. People use refresh tokens because it "can't be hijacked", but in reality, you can hijack it through a MITM attack. Then again, anything can be hijacked. JWTs are very useful when making APIs, and you really don't need refresh tokens if your API is not meant to be accessed by the web. For example, refresh tokens wouldn't be too useful in a SASS application because only servers are contacting the API, not users. This means hijacking is near impossible.