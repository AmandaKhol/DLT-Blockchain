# Distributed Ledger Platform tutorial

The repository contains an implementation of a distributed ledger platform and its client using Python. 

This ledger has the following features:

+ Possibility of adding multiple nodes to the ledger
+ Proof of Work (PoW)
+ Conflict resolution between nodes
+ Transactions with RSA encryption
+ Identification by JWT
+ Independent database per node


The blockchain client has the following features:

+ Wallets generation using Public/Private key encryption (based on RSA algorithm)
+ Generation of transactions with RSA encryption
+ User identification by the Public/Private key


The respository also includes a [Postman](https://www.postman.com/) test collection and environment created in order to test the endpoint.

This code takes as its starting point the source code proposed by [Adil Moujahid](http://adilmoujahid.com/posts/2018/03/intro-blockchain-bitcoin-python/)

## Dependencies
+ Python 3.7
+ Pipfile contains all the dependencies for the code to run

## How to run the code

We recommend using an IDE like PyCharm to run the code. 

1. To start a blockchain node, go to blockchain folder and execute the command below: 
    ```python
    python server_api.py -p 5000
    ```
    You can add a new node to blockchain by executing the same command and specifying a port that is not already used. For example, 

    ```python
    python server_api.py -p 5001
    ```
   
      **NOTE:** We recommend running 3 blockchain nodes and a client simultaneously.

2.  To start the blockchain client, go to blockchain_client folder and execute the command below: 

    ```python
    python client_app.py -p 8080
    ```

3. To start with a created ledger execute the command below:

    ```python
    python initialize.py
    ```
