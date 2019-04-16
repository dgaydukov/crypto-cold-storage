# Crypto cold storage

## Content
* [Description](#description)
* [Built With](#built-with)
* [Project Structure](#project-structure)
* [Authors](#authors)

### Description

This project is a simple cold storage wallet, that allows you to work with crypto currency in a cold storage device.
We all know website [MEW](https://myetherwallet.com), and that you can download it and use as a cold storage to manage your funds. You can also generate transactions there, all you need is to get current `nonce` from the blockchain, and your tx is ready.
So the idea striked me, why not to create something similar for bitcoin. Something like `mybtcwallet`. You can object me, that there are dozens of sites that allow to generate keypairs, like [bitaddress](https://www.bitaddress.org). But there is none, that allow you to create tx.
Again you can object me and say, that for bitcoin to create a transaction, you have to first get all `utxo`, and then based of them create your tx. And here is my idea. Why not to have a website, where you can download all desired `utxo`, and then use them from your cold storage.
Let me give you an example. Suppose Bob has a bootable usb with linux. He knows all his addresses, where he has money. So here is his actions:
```
1. Go to website, input all his addresses, and download a JSON with all his UTXO
2. Turn off his pc, and load Operation System from his usb (never connecting to internet)
3. Open offline version of our website and upload there his UTXO list
4. Our website generate tx for him, gives him QR-code
5. He scans QR-code and broadcast tx
```


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
src # directory with all source code
    app # all app source code
    btc # code related to bitcoin (address generation, tx sign)
    eth # code related to ethereum (address generation, tx sign)
test # tests that run on commit, push, deploy
```


### Authors

* **Gaydukov Dmitiry** - *Take a look* - [How to become a Senior Javascript Developer](https://github.com/dgaydukov/how-to-become-a-senior-js-developer)