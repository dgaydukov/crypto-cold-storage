require('dotenv').config()

import * as Koa from 'koa';
import * as Router from 'koa-router';
import EthStorage from './eth';
const port = 27333;

const app = new Koa();
const router = new Router({
    prefix: '/v1'
});

const eth = new EthStorage();
eth.run();

app.use(router.routes());


(async ()=>{
    await app.listen(port);
    console.log(`cold storage app run on port: ${port}`);
})();