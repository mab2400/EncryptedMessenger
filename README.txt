To run the programs:
1) ./setup.sh
    - When prompted for the PEM pass phrase on the server side, enter topsecretserverpassword
    - When prompted "Enter pass phrase for ./intermediate/private/intermediate.key.pem:", enter
      lesstopsecretpassword 

2) In another window, valgrind ./getcert <username> <password>
    - When prompted "Enter pass phrase for client/client-priv.key.pem:", enter the user's password
