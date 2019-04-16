# Crypto cold storage

## Content
* [Description](#description)
* [Built With](#built-with)
* [Project Structure](#project-structure)
* [Authors](#authors)

### Description

This project is a simple cold storage wallet


### Installation

You can install this project with the following commands:
```shell
# clone the repository
git clone https://github.com/dgaydukov/crypto-cold-storage

# go to repo
cd crypto-cold-storage

# install
npm i

# copy env variables
cp .env.tpl .env

# run the project
npm start
```



### Built With

* [Node.js v10.15.0](https://nodejs.org/fr/blog/release/v10.15.0/)


### Project Structure
```
public # directory with public access, works as static server
src # directory with all source code
    app # all app source code
    btc # code related to bitcoin (address generation, tx sign)
    eth # code related to ethereum (address generation, tx sign)
test # tests that run on commit, push, deploy
```


### Authors

* **Gaydukov Dmitiry** - *Take a look* - [How to become a Senior Javascript Developer](https://github.com/dgaydukov/how-to-become-a-senior-js-developer)