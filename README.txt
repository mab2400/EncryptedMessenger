To run GETCERT:

- In one window, cd server
    - ./setup.sh
	    - Enter PEM pass phrase: topsecretserverpassword
- In another window, cd client
    - ./setup.sh

============
Passwords for the server side:
    - Enter pass phrase for ./intermediate/private/intermediate.key.pem: lesstopsecretpassword 
Passwords for the client side:
    - Enter pass phrase for client-priv.key.pem: <password> (by default, it is "pass")
