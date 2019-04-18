require('dotenv').config()

import * as Koa from 'koa';
import * as Router from 'koa-router';
import EthStorage from '../eth';
import BtcStorage from '../btc';
const port = process.env.APP_PORT;

const app = new Koa();
const router = new Router({
    prefix: '/v1'
});

const eth = new EthStorage();
//eth.run();
const btc = new BtcStorage();
btc.run();

app.use(router.routes());


(async ()=>{
    await app.listen(port);
    console.log(`cold storage app run on port: ${port}`);
})();